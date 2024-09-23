#include "encryption.h"
#include "openfhe.h"
#include <array>
#include <cstdint>
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
enum class DecomposeAlgo { NAF, BINARY };

template <int N> class Decomposer {

    std::vector<int> rotIndices;
    int maxDecomposed;

    int calculateMax() const {
        int maxDecomposed = 0;
        int step;
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

    std::vector<Step> decompose(int rotation, DecomposeAlgo algo) {
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
        case DecomposeAlgo::BINARY:
            remainingSteps = decomposeBinary(rotation);
            break;
        }
        steps.insert(steps.end(), remainingSteps.begin(), remainingSteps.end());

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
                } else if (std::abs(stepSize) < N)
                    steps.emplace_back(z, stepSize);

                rotation -= z;
            }
            rotation >>= 1;
            i++;
        }
        std::reverse(steps.begin(), steps.end());
        return steps;
    }
};

template <int N> class RotationComposer {
  private:
    CryptoContext<DCRTPoly> m_cc;
    std::shared_ptr<Encryption> m_enc;
    Decomposer<N> m_decomposer;
    DecomposeAlgo m_algo;

  public:
    RotationComposer(CryptoContext<DCRTPoly> cc,
                     std::shared_ptr<Encryption> enc,
                     std::vector<int> rotIndices,
                     DecomposeAlgo algo = DecomposeAlgo::NAF)
        : m_cc(cc), m_enc(enc), m_decomposer(rotIndices), m_algo(algo) {}

    Ciphertext<DCRTPoly> rotate(const Ciphertext<DCRTPoly> &input,
                                int rotation) {
        auto steps = m_decomposer.decompose(rotation, m_algo);
        Ciphertext<DCRTPoly> result = input->Clone();
        for (auto step : steps)
            result = m_cc->EvalRotate(result, step.stepSize);
        return result;
    }
};
