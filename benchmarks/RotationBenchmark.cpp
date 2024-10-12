#include "lattice/stdlatticeparms.h"
#include "openfhe.h"
#include "sort_algo.h"
#include <benchmark/benchmark.h>

using namespace lbcrypto;

/*

When the benchmark is run on a local laptop with no security setting we
get the following results. This means that any rotation above 2 should be
done in FastRotation.

Run on (8 X 2488.33 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x4)
  L1 Instruction 32 KiB (x4)
  L2 Unified 1280 KiB (x4)
  L3 Unified 12288 KiB (x1)
Load Average: 0.61, 0.73, 0.53
--------------------------------------------------------------
Benchmark                    Time             CPU   Iterations
--------------------------------------------------------------
BM_Rotations/1            4.94 ms         4.94 ms          149
BM_Rotations/2            10.1 ms         10.0 ms           69
BM_Rotations/3            17.2 ms         17.2 ms           44
BM_Rotations/4            22.6 ms         22.6 ms           32
BM_Rotations/5            28.2 ms         28.2 ms           25
BM_Rotations/6            34.3 ms         34.2 ms           20
BM_Rotations/7            43.1 ms         42.8 ms           14
BM_Rotations/8            46.9 ms         46.8 ms           15
BM_Rotations/9            53.7 ms         53.7 ms           12
BM_Rotations/10           59.2 ms         59.1 ms           10
BM_Rotations/11           74.7 ms         74.5 ms           10
BM_Rotations/12            103 ms         94.9 ms            7
BM_Rotations/13           95.8 ms         88.4 ms            9
BM_Rotations/14           74.5 ms         74.3 ms            8
BM_FastRotations/1        4.91 ms         4.89 ms          141
BM_FastRotations/2        9.45 ms         9.17 ms           86
BM_FastRotations/3        11.9 ms         11.9 ms           55
BM_FastRotations/4        16.9 ms         16.2 ms           47
BM_FastRotations/5        23.5 ms         23.1 ms           35
BM_FastRotations/6        26.4 ms         26.3 ms           32
BM_FastRotations/7        32.6 ms         30.5 ms           26
BM_FastRotations/8        28.7 ms         28.6 ms           24
BM_FastRotations/9        32.8 ms         32.7 ms           21
BM_FastRotations/10       35.7 ms         35.6 ms           15
BM_FastRotations/11       51.9 ms         51.0 ms           10
BM_FastRotations/12       43.0 ms         42.8 ms           16
BM_FastRotations/13       45.3 ms         45.2 ms           14
BM_FastRotations/14       49.6 ms         49.5 ms           12
*/

// Helper function to setup the crypto context and generate keys
std::tuple<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>>
SetupContext(uint32_t batchSize, enum SecurityLevel sec = HEStd_NotSet) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(sec);
    if (sec == HEStd_NotSet)
        parameters.SetRingDim(1 << 12);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    std::vector<int32_t> rotations = {-64, -32, -16, -8, -4, -2, -1,
                                      1,   2,   4,   8,  16, 32, 64};
    cc->EvalRotateKeyGen(keys.secretKey, rotations);

    return std::make_tuple(cc, keys);
}

static void BM_Rotations(benchmark::State &state) {
    uint32_t batchSize = 8;
    auto [cc, keys] = SetupContext(batchSize);

    std::vector<double> x(batchSize, 0.0);
    x[batchSize - 1] = 1.0;
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x);
    auto c = cc->Encrypt(keys.publicKey, ptxt);

    int numRotations = state.range(0);
    std::vector<int32_t> rotations = {-64, -32, -16, -8, -4, -2, -1,
                                      1,   2,   4,   8,  16, 32, 64};

    for (auto _ : state) {
        std::vector<Ciphertext<DCRTPoly>> rotated(numRotations);
        for (int i = 0; i < numRotations; ++i) {
            rotated[i] = cc->EvalRotate(c, rotations[i]);
        }
        benchmark::DoNotOptimize(rotated);
        benchmark::ClobberMemory();
    }
}

static void BM_FastRotations(benchmark::State &state) {
    uint32_t batchSize = 8;
    auto [cc, keys] = SetupContext(batchSize);
    uint32_t N = cc->GetRingDimension();
    uint32_t M = 2 * N;

    std::vector<double> x(batchSize, 0.0);
    x[batchSize - 1] = 1.0;
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x);
    auto c = cc->Encrypt(keys.publicKey, ptxt);

    int numRotations = state.range(0);
    std::vector<int32_t> rotations = {-64, -32, -16, -8, -4, -2, -1,
                                      1,   2,   4,   8,  16, 32, 64};

    for (auto _ : state) {
        auto cPrecomp = cc->EvalFastRotationPrecompute(c);
        std::vector<Ciphertext<DCRTPoly>> rotated(numRotations);
        for (int i = 0; i < numRotations; ++i) {
            rotated[i] = cc->EvalFastRotation(c, rotations[i], M, cPrecomp);
        }
        benchmark::DoNotOptimize(rotated);
        benchmark::ClobberMemory();
    }
}

static void BM_BatchRotations(benchmark::State &state) {
    const uint32_t batchSize = 128;
    auto [cc, keys] = SetupContext(batchSize, HEStd_128_classic);

    std::vector<double> x(batchSize, 0.0);
    x[batchSize - 1] = 1.0;
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x);
    auto c = cc->Encrypt(keys.publicKey, ptxt);

    int numRotations = batchSize;
    std::vector<int32_t> rotations = {-32, -16, -8, -4, -2, -1, 1,
                                      2,   4,   8,  16, 32, 64};
    RotationComposer<batchSize> rot(cc, nullptr, rotations);

    for (auto _ : state) {
        std::vector<Ciphertext<DCRTPoly>> rotated(numRotations);
        for (int i = 0; i < numRotations; ++i) {
            rotated[i] = rot.rotate(c, i);
        }
        benchmark::DoNotOptimize(rotated);
        benchmark::ClobberMemory();
    }
}

static void BM_BatchTreeRotations(benchmark::State &state) {
    const uint32_t batchSize = 128;
    const uint32_t N = batchSize;
    auto [cc, keys] = SetupContext(batchSize, HEStd_128_classic);

    std::vector<double> x(batchSize, 0.0);
    x[batchSize - 1] = 1.0;
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x);
    auto c = cc->Encrypt(keys.publicKey, ptxt);

    int numRotations = batchSize;
    std::vector<int32_t> rotations = {-32, -16, -8, -4, -2, -1, 1,
                                      2,   4,   8,  16, 32, 64};
    RotationTree<batchSize> rot(cc, rotations);

    for (auto _ : state) {
        std::vector<Ciphertext<DCRTPoly>> rotated(numRotations);
        rot.buildTree(1, N);
        for (int i = 0; i < numRotations; ++i) {
            rotated[i] = rot.treeRotate(c, i);
        }
        benchmark::DoNotOptimize(rotated);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_Rotations)->DenseRange(1, 14)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_FastRotations)->DenseRange(1, 14)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_BatchRotations)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_BatchTreeRotations)->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
