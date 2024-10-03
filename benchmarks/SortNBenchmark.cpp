#include <algorithm>
#include <memory>
#include <random>
#include <vector>

#include "encryption.h"
#include "lattice/stdlatticeparms.h"
#include "openfhe.h"
#include "sort_algo.h"
#include <benchmark/benchmark.h>

using namespace lbcrypto;

// Utility function to generate a vector with minimum difference
std::vector<double> getVectorWithMinDiff(int N) {
    std::vector<double> result(N);
    std::vector<int> integers(25500);
    std::iota(integers.begin(), integers.end(), 0);
    std::shuffle(integers.begin(), integers.end(),
                 std::mt19937{std::random_device{}()});
    for (int i = 0; i < N; ++i) {
        result[i] = integers[i] * 0.01;
    }
    return result;
}

// // Setup function for DirectSort
// template <int N> auto setupDirectSort() {
//     CCParams<CryptoContextCKKSRNS> parameters;
//     parameters.SetMultiplicativeDepth(DirectSort<N>::getDepth());
//     parameters.SetScalingModSize(59);
//     parameters.SetBatchSize(N);
//     parameters.SetSecurityLevel(HEStd_NotSet);
//     usint ringDim = 1 << 12;
//     parameters.SetRingDim(ringDim);
//     // assert(ringDim / 2 > N * N && "Ring dimension should be higher than
//     the
//     // square of array length due to SIMD batching.");
//
//     auto cc = GenCryptoContext(parameters);
//     cc->Enable(PKE);
//     cc->Enable(KEYSWITCH);
//     cc->Enable(LEVELEDSHE);
//     cc->Enable(ADVANCEDSHE);
//
//     auto keyPair = cc->KeyGen();
//     std::vector<int> rotations;
//     // std::vector<int> rotations = {-1, -2, -4, -8, -16, -32, -64, 1,
//     //                               2,  4,  8,  16, 32,  64, 128};
//     for (int i = 1; i < N; i *= 2) {
//         rotations.push_back(i);
//         rotations.push_back(-i);
//     }
//     cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
//     cc->EvalMultKeyGen(keyPair.secretKey);
//
//     auto enc = std::make_shared<Encryption>(cc, keyPair.publicKey);
//     auto directSort =
//         std::make_unique<DirectSort<N>>(cc, keyPair.publicKey, enc);
//     std::vector<double> inputArray = getVectorWithMinDiff(N);
//     auto ctxt = enc->encryptInput(inputArray);
//
//     return std::make_tuple(std::move(cc), std::move(directSort),
//                            std::move(ctxt));
// }

// Setup function for BitonicSort
template <int N> auto setupBitonicSort() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(58);
    parameters.SetScalingModSize(59);
    parameters.SetBatchSize(N);
    parameters.SetSecurityLevel(lbcrypto::HEStd_NotSet);
    parameters.SetRingDim(1 << 17);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    std::vector<int> rotations;
    for (int i = 1; i < N; i *= 2) {
        rotations.push_back(i);
        rotations.push_back(-i);
    }
    cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
    cc->EvalMultKeyGen(keyPair.secretKey);

    // Bootstrapping setup
    cc->Enable(FHE);
    std::vector<uint32_t> levelBudget = {4, 4};
    cc->EvalBootstrapSetup(levelBudget, {0, 0}, N);
    cc->EvalBootstrapKeyGen(keyPair.secretKey, N);

    auto enc = std::make_shared<Encryption>(cc, keyPair.publicKey);
    auto bitonicSort =
        std::make_unique<BitonicSort<N>>(cc, keyPair.publicKey, rotations, enc);
    std::vector<double> inputArray = getVectorWithMinDiff(N);
    auto ctxt = enc->encryptInput(inputArray);

    return std::make_tuple(std::move(cc), std::move(bitonicSort),
                           std::move(ctxt));
}

// Benchmark function for DirectSort
// template <int N> static void BM_DirectSort(benchmark::State &state) {
//     auto [cc, directSort, ctxt] = setupDirectSort<N>();
//     for (auto _ : state) {
//         auto ctxt_out = directSort->sort(ctxt);
//         benchmark::DoNotOptimize(ctxt_out);
//         benchmark::ClobberMemory();
//     }
//     state.counters["ArraySize"] = N;
//     state.counters["RingDimension"] = cc->GetRingDimension();
// }

// Benchmark function for BitonicSort
template <int N> static void BM_BitonicSort(benchmark::State &state) {
    auto [cc, bitonicSort, ctxt] = setupBitonicSort<N>();
    for (auto _ : state) {
        auto ctxt_out = bitonicSort->sort(ctxt);
        benchmark::DoNotOptimize(ctxt_out);
        benchmark::ClobberMemory();
    }
    bitonicSort->printPerformanceResults();
    state.counters["ArraySize"] = N;
    state.counters["RingDimension"] = cc->GetRingDimension();
}

// Register the benchmarks for different input sizes
#define REGISTER_BENCHMARKS(N)                                                 \
    BENCHMARK(BM_BitonicSort<N>)->Unit(benchmark::kMillisecond)->UseRealTime();

REGISTER_BENCHMARKS(4)
REGISTER_BENCHMARKS(8)
REGISTER_BENCHMARKS(16)
REGISTER_BENCHMARKS(32)
REGISTER_BENCHMARKS(64)
REGISTER_BENCHMARKS(128)
REGISTER_BENCHMARKS(256)
REGISTER_BENCHMARKS(512)
REGISTER_BENCHMARKS(1024)

BENCHMARK_MAIN();
