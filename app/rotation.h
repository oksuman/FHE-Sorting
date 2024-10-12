#include "ciphertext-fwd.h"
#include "encryption.h"
#include "lattice/hal/lat-backend.h"
#include "openfhe.h"
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

using namespace lbcrypto;

struct Step {
    int8_t value; // -1, 0, or 1 for NAF; 0 or 1 for binary
    int stepSize; // The actual rotation amount (e.g., 32, 16, 8, etc.)

    Step(int8_t v, int s) : value(v), stepSize(s) {}
    Step(int s) : value(1), stepSize(s) {}
};

inline void dump(std::vector<Step> steps) {
    std::cout << "Decomposed steps: [";
    for (const auto &step : steps) {
        std::cout << "(" << (int32_t)step.value << ", " << step.stepSize
                  << "), ";
    }
    std::cout << " ]" << std::endl;
}
enum class DecomposeAlgo { NAF, BNAF, BINARY };

template <int N> class Decomposer {

    std::vector<int> rotIndices;
    int maxDecomposed;

    int calculateMax() const {
        int maxDecomposed = 0;
        int step = 1;
        for (int index : rotIndices) {
            if (step == index / 2)
                maxDecomposed += index;
            step = index;
        }
        return maxDecomposed;
    }

  public:
    Decomposer(std::vector<int> rot) : rotIndices(rot) {
        std::sort(rotIndices.begin(), rotIndices.end());
        maxDecomposed = calculateMax();
    }

    std::vector<int> getRotIndices() { return rotIndices; }

    std::vector<Step> decompose(int rotation, int wrapN, DecomposeAlgo algo) {
        std::vector<Step> steps;
        int largestStep = rotIndices.back();

        // Handle rotations larger than the biggest step, this can be an
        // arbitrarily large step size depending on the range.
        while (rotation >= largestStep) {
            steps.emplace_back(largestStep);
            rotation -= largestStep;
        }
        if (!rotation)
            return steps;

        while (rotation > maxDecomposed) {
            // Get the largest available rotation step smaller than the required
            // rotation
            int legalStep = *(std::lower_bound(rotIndices.begin(),
                                               rotIndices.end(), rotation) -
                              1);
            steps.emplace_back(legalStep);
            rotation -= legalStep;
        }
        if (!rotation)
            return steps;

        // Now in the safe range decompose the remaining rotation
        std::vector<Step> remainingSteps;
        switch (algo) {
        case DecomposeAlgo::NAF:
            remainingSteps = decomposeNAF(rotation);
            break;
        case DecomposeAlgo::BNAF:
            remainingSteps = decomposeBNAF(rotation);
            break;
        case DecomposeAlgo::BINARY:
            remainingSteps = decomposeBinary(rotation);
            break;
        }
        steps.insert(steps.end(), remainingSteps.begin(), remainingSteps.end());

        // Sanitize by removing unnecessary rotates
        steps.erase(std::remove_if(steps.begin(), steps.end(),
                                   [wrapN](const Step &step) {
                                       return step.stepSize % wrapN == 0;
                                   }),
                    steps.end());

        return steps;
    }

  private:
    std::vector<Step> decomposeBinary(int rotation) const {
        std::vector<Step> steps;
        for (int i = 31; i >= 0; --i) {
            auto stepSize = (1 << i);
            if (stepSize < N && rotation & stepSize) {
                steps.emplace_back(1, stepSize);
            }
        }
        return steps;
    }

    std::vector<Step> decomposeNAF(int rotation) const {
        std::vector<Step> steps;
        int i = 0;
        while (rotation != 0) {
            if (rotation & 1) {
                int z = ((rotation & 2) ? -1 : 1);
                auto stepSize = z * (1 << i);
                // -N/2 rotation is equal to N/2 rotation
                if (stepSize == -N / 2) {
                    steps.emplace_back(-z, -stepSize);
                } else
                    steps.emplace_back(z, stepSize);

                rotation -= z;
            }
            rotation >>= 1;
            i++;
        }
        std::reverse(steps.begin(), steps.end());
        return steps;
    }

    std::vector<Step> decomposeBNAF(int k) const {
        std::vector<int> digits;
        int K = k;
        int B = 2; // Since we're working in binary

        while (K != 0) {
            int ki = K % B;
            K = (K - ki) / B;

            if (ki > B / 2 || (ki == B / 2 && (K % B) >= B / 2)) {
                ki = ki - B;
                K = K + 1;
            }

            digits.push_back(ki);
        }

        std::vector<Step> steps;
        for (size_t i = 0; i < digits.size(); ++i) {
            if (digits[i] != 0) {
                steps.emplace_back(digits[i],
                                   digits[i] * static_cast<int64_t>(1) << i);
            }
        }

        std::reverse(steps.begin(), steps.end());
        return steps;
    }
};

struct RotationStats {
    size_t fastRotationCount = 0;
    size_t normalRotationCount = 0;
    size_t totalRotationCount = 0;
    size_t cacheHits = 0;
    size_t cacheMisses = 0;

    void reset() {
        fastRotationCount = 0;
        normalRotationCount = 0;
        totalRotationCount = 0;
        cacheHits = 0;
        cacheMisses = 0;
    }

    void print() const {
        std::cout << "Rotation Statistics:\n"
                  << "  Fast Rotations: " << fastRotationCount << "\n"
                  << "  Normal Rotations: " << normalRotationCount << "\n"
                  << "  Total Rotations: " << totalRotationCount << "\n"
                  << "  Cache Hits: " << cacheHits << "\n"
                  << "  Cache Misses: " << cacheMisses << "\n";
    }
};

template <int N> class RotationComposer {
  private:
    CryptoContext<DCRTPoly> m_cc;
    std::shared_ptr<Encryption> m_enc;
    Decomposer<N> m_decomposer;
    DecomposeAlgo m_algo;
    // uint32_t M;

  public:
    RotationComposer(CryptoContext<DCRTPoly> cc,
                     std::shared_ptr<Encryption> enc,
                     std::vector<int> rotIndices,
                     DecomposeAlgo algo = DecomposeAlgo::NAF)
        : m_cc(cc), m_enc(enc), m_decomposer(rotIndices), m_algo(algo) {
        // M = cc->GetCyclotomicOrder();
    }

    std::vector<int> getRotIndices() { return m_decomposer.getRotIndices(); }

    Ciphertext<DCRTPoly> rotate(const Ciphertext<DCRTPoly> &input,
                                int rotation) {
        auto steps =
            m_decomposer.decompose(rotation, input->GetSlots(), m_algo);
        // std::cout << "Rotation: " << rotation << "\n";
        // dump(steps);
        Ciphertext<DCRTPoly> result = input->Clone();
        for (auto step : steps)
            result = m_cc->EvalRotate(result, step.stepSize);
        return result;
    }
};

template <int N> class RotationTree {
  public:
    struct RotationNode {
        int stepSize;
        RotationNode *parent;
        std::map<int, std::unique_ptr<RotationNode>> children;
        std::vector<int> finalValues;
        Ciphertext<DCRTPoly> rotatedCiphertext;
        std::shared_ptr<std::vector<DCRTPoly>> cPrecomp;

        RotationNode(int step, RotationNode *p = nullptr)
            : stepSize(step), parent(p) {}
    };

  private:
    std::unique_ptr<RotationNode> root;
    Decomposer<N> m_decomposer;
    DecomposeAlgo m_algo;
    CryptoContext<DCRTPoly> m_cc;
    uint32_t M;
    RotationStats stats;

  public:
    RotationTree(CryptoContext<DCRTPoly> cc, const std::vector<int> &rotIndices,
                 DecomposeAlgo algo = DecomposeAlgo::NAF)
        : m_decomposer(rotIndices), m_algo(algo), m_cc(cc) {
        root = std::make_unique<RotationNode>(0); // Root node
        M = cc->GetCyclotomicOrder();
    }

    void buildTree(int start, int end) {
#pragma omp parallel for
        for (int i = start; i <= end; ++i) {
            auto steps = m_decomposer.decompose(i, end, m_algo);
#pragma omp critical
            { addToTree(root.get(), steps, 0, i); }
        }
    }

    Ciphertext<DCRTPoly> treeRotate(const Ciphertext<DCRTPoly> &input,
                                    int rotation) {
        auto steps =
            m_decomposer.decompose(rotation, input->GetSlots(), m_algo);
        // std::cout << "Tree rotate " << rotation << "\n";
        // dump(steps);
        if (!root->cPrecomp)
            root->cPrecomp = m_cc->EvalFastRotationPrecompute(input);

        return traverseAndRotate(input, root.get(), steps, 0);
    }

    const RotationStats &getStats() const { return stats; }

  private:
    void addToTree(RotationNode *node, const std::vector<Step> &steps,
                   size_t stepIndex, int originalValue) {
        if (stepIndex >= steps.size()) {
            node->finalValues.push_back(originalValue);
            return;
        }

        const auto &step = steps[stepIndex];
        if (step.value != 0) {
            if (node->children.find(step.stepSize) == node->children.end()) {
                node->children[step.stepSize] =
                    std::make_unique<RotationNode>(step.stepSize, node);
            }
            addToTree(node->children[step.stepSize].get(), steps, stepIndex + 1,
                      originalValue);
        } else {
            addToTree(node, steps, stepIndex + 1, originalValue);
        }
    }

    Ciphertext<DCRTPoly> traverseAndRotate(const Ciphertext<DCRTPoly> &input,
                                           RotationNode *node,
                                           const std::vector<Step> &steps,
                                           size_t stepIndex) {
        if (stepIndex >= steps.size()) {
            return input;
        }

        const auto &step = steps[stepIndex];
        if (step.value == 0) {
            return traverseAndRotate(input, node, steps, stepIndex + 1);
        }

        auto childIt = node->children.find(step.stepSize);
        if (childIt == node->children.end()) {
            std::cerr << "Error: Child node not found for step size "
                      << step.stepSize << std::endl;
            return input;
        }
        auto *child = childIt->second.get();
        Ciphertext<DCRTPoly> rotated;

        if (child->rotatedCiphertext) {
            rotated = child->rotatedCiphertext;
            // stats.cacheHits++;
        } else {
            // stats.cacheMisses++;
            // stats.totalRotationCount++;
            if (std::abs(node->stepSize) > 2 || !node->stepSize /*root node*/) {
                if (!node->cPrecomp) {
                    node->cPrecomp = m_cc->EvalFastRotationPrecompute(input);
                }
                rotated = m_cc->EvalFastRotation(input, child->stepSize, M,
                                                 node->cPrecomp);
                // stats.fastRotationCount++;
            } else {
                rotated = m_cc->EvalRotate(input, child->stepSize);
                // stats.normalRotationCount++;
            }
            child->rotatedCiphertext = rotated;
        }

        return traverseAndRotate(rotated, child, steps, stepIndex + 1);
    }
};
