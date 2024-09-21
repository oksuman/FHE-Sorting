#include "encryption.h"
#include "sign.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <vector>

class SignFunctionCharacterizer {
  private:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;
    std::shared_ptr<DebugEncryption> enc;

    double precisionThreshold;
    int maxTestValues;

  public:
    SignFunctionCharacterizer(double threshold = 0.01, int maxValues = 100)
        : precisionThreshold(threshold), maxTestValues(maxValues) {
        // Initialize crypto context
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(40);
        parameters.SetScalingModSize(50);
        parameters.SetBatchSize(8);
        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        enc = std::make_shared<DebugEncryption>(cc, keyPair);

        // Print configuration
        std::cout << "Characterizer Configuration:" << std::endl;
        std::cout << "Precision Threshold: " << precisionThreshold << std::endl;
        std::cout << "Max Test Values: " << maxTestValues << std::endl;
        std::cout << "Multiplicative Depth: "
                  << parameters.GetMultiplicativeDepth() << std::endl;
        std::cout << "Scaling Mod Size: " << parameters.GetScalingModSize()
                  << std::endl;
        std::cout << "Batch Size: " << parameters.GetBatchSize() << std::endl;
        std::cout << std::endl;
    }

    struct PrecisionMetrics {
        int depth;
        double workingPrecision;
        double executionTime;
    };

    using SignFunction = std::function<Ciphertext<DCRTPoly>(
        Ciphertext<DCRTPoly>, CryptoContext<DCRTPoly>, int, int)>;

    PrecisionMetrics characterizeFunction(SignFunc func,
                                          const SignConfig &cfg) {
        PrecisionMetrics metrics = {0, 0.0, 0.0};
        std::vector<double> testValues = {-1.0, 0.0, 1.0};
        double step = 0.1;

        while (testValues.size() < maxTestValues) {
            bool shouldStop = false;
            for (double value : {-step, step}) {
                if (testValues.size() >= maxTestValues)
                    break;

                std::vector<double> input = {value};
                auto ciphertext = enc->encryptInput(input);

                auto startTime = std::chrono::high_resolution_clock::now();
                auto result = sign(ciphertext, cc, func, cfg);
                auto endTime = std::chrono::high_resolution_clock::now();
                metrics.executionTime =
                    std::chrono::duration<double, std::milli>(endTime -
                                                              startTime)
                        .count();

                auto decrypted = enc->getPlaintext(result);

                double expected =
                    (value > 0) ? 1.0 : ((value < 0) ? -1.0 : 0.0);
                double error = std::abs(decrypted[0] - expected);

                metrics.depth = result->GetLevel();

                if (error > precisionThreshold) {
                    shouldStop = true;
                    metrics.workingPrecision = step * 10;
                    break;
                }

                testValues.push_back(value);
            }
            if (shouldStop)
                break;
            step /= 10;
        }

        return metrics;
    }

    struct SignFunctionConfig {
        SignFunc func;
        std::string name;
        std::vector<SignConfig> configs;
    };

    std::vector<SignFunctionConfig> signFunctions = {
        {SignFunc::NaiveDiscrete, "NaiveDiscrete", {SignConfig()}},
        {SignFunc::Tanh, "Tanh", {SignConfig()}},
        {SignFunc::CompositeSign,
         "CompositeSign",
         {SignConfig(CompositeSignConfig(2, 2)),
          SignConfig(CompositeSignConfig(3, 3))}},
    };

    std::string getConfigString(const SignConfig &cfg) {
        if (cfg.compos.dg != 0 || cfg.compos.df != 0) {
            return "_" + std::to_string(cfg.compos.dg) + "_" +
                   std::to_string(cfg.compos.df);
        }
        return "";
    }

    void writeCryptoConfig(std::ofstream &file) {
        file << "// Crypto Configuration:\n";
        file << "// Precision Threshold: " << precisionThreshold << "\n";
        file << "// Max Test Values: " << maxTestValues << "\n";

        // TODO write crypto params and other relevant context in the header
        // comments
    }
    void generateHeader(const std::string &filename) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return;
        }
        writeCryptoConfig(file);

        file << "#ifdef GET_SIGN_FUNCTION_METRIC\n";

        for (const auto &signFunc : signFunctions) {
            for (const auto &cfg : signFunc.configs) {
                std::cout << "Characterizing " << signFunc.name
                          << getConfigString(cfg) << std::endl;

                auto metrics = characterizeFunction(signFunc.func, cfg);

                file << "GET_SIGN_FUNCTION_METRIC(" << signFunc.name
                     << getConfigString(cfg) << ", " << metrics.depth << ", "
                     << std::setprecision(10) << metrics.workingPrecision
                     << ", " << metrics.executionTime << ")\n";
            }
        }

        file << "#endif // GET_SIGN_FUNCTION_METRIC\n\n";

        file.close();
        std::cout << "Generated header file: " << filename << std::endl;
    }
};

void printUsage(const char *programName) {
    std::cout << "Usage:" << std::endl;
    std::cout << programName << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --generate-header         Generate the full header file"
              << std::endl;
    std::cout << "  --characterize <function> Characterize a single function"
              << std::endl;
    std::cout << "    Available functions:" << std::endl;
    std::cout << "      CompositeSign_<dg>_<df>" << std::endl;
    std::cout << "      NaiveDiscrete" << std::endl;
    std::cout << "Example:" << std::endl;
    std::cout << programName << " --characterize CompositeSign_2_3"
              << std::endl;
}

int main(int argc, char *argv[]) {
    SignFunctionCharacterizer characterizer;

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--generate-header") == 0) {
        characterizer.generateHeader("sign_function_metrics.h");
    } else if (strcmp(argv[1], "--characterize") == 0) {
        if (argc < 3) {
            std::cerr
                << "Error: Function name not provided for characterization"
                << std::endl;
            printUsage(argv[0]);
            return 1;
        }

        std::string funcName = argv[2];
        SignFunc func;
        SignConfig cfg;

        if (funcName.compare(0, 13, "CompositeSign_") == 0) {
            func = SignFunc::CompositeSign;
            size_t pos1 = funcName.find_last_of('_');
            size_t pos2 = funcName.find_last_of('_', pos1 - 1);
            if (pos1 == std::string::npos || pos2 == std::string::npos) {
                std::cerr << "Error: Invalid CompositeSign format. Use "
                             "CompositeSign_<dg>_<df>"
                          << std::endl;
                return 1;
            }
            cfg.compos.dg =
                std::stoi(funcName.substr(pos2 + 1, pos1 - pos2 - 1));
            cfg.compos.df = std::stoi(funcName.substr(pos1 + 1));
        } else if (funcName == "NaiveDiscrete") {
            func = SignFunc::NaiveDiscrete;
        } else if (funcName == "Tanh") {
            func = SignFunc::Tanh;
        } else {
            std::cerr << "Error: Unknown function " << funcName << std::endl;
            printUsage(argv[0]);
            return 1;
        }

        auto metrics = characterizer.characterizeFunction(func, cfg);
        std::cout << "Function: " << funcName << std::endl;
        std::cout << "Depth: " << metrics.depth << std::endl;
        std::cout << "Working Precision: " << std::setprecision(10)
                  << metrics.workingPrecision << std::endl;
        std::cout << "Execution Time: " << metrics.executionTime << " ms"
                  << std::endl;
    } else {
        std::cerr << "Error: Unknown option " << argv[1] << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    return 0;
}
