#include <algorithm>
#include <benchmark/benchmark.h>
#include <memory>
#include <openfhe.h>
#include <random>
#include <vector>

#include "encryption.h"
#include "sort_algo.h"

using namespace lbcrypto;

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

// Setup function to create the necessary objects
template <int N> auto setupBenchmark() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(48);
    parameters.SetScalingModSize(59);
    parameters.SetBatchSize(N);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(1 << 17);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();

    std::vector<int> rotations = {-1, -2, -4, -8, -16, -32, 1,   2,
                                  4,  8,  16, 32, 64,  512, 4096};

    cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto enc = std::make_shared<Encryption>(cc, keyPair.publicKey);
    auto directSort =
        std::make_unique<DirectSort<N>>(cc, keyPair.publicKey, rotations, enc);

    std::vector<double> inputArray = getVectorWithMinDiff(N);
    auto ctxt = enc->encryptInput(inputArray);

    return std::make_tuple(std::move(cc), std::move(directSort),
                           std::move(ctxt));
}

// Benchmark function for sort
template <int N> static void BM_DirectSort(benchmark::State &state) {
    auto [cc, directSort, ctxt] = setupBenchmark<N>();

    for (auto _ : state) {
        auto ctxt_out = directSort->sort(ctxt);
        benchmark::DoNotOptimize(ctxt_out);
        benchmark::ClobberMemory();
    }

    state.counters["ArraySize"] = N;
    state.counters["RingDimension"] = cc->GetRingDimension();
}

// Benchmark function for constructRank
template <int N> static void BM_ConstructRank(benchmark::State &state) {
    auto [cc, directSort, ctxt] = setupBenchmark<N>();

    for (auto _ : state) {
        auto rank = directSort->constructRank(ctxt);
        benchmark::DoNotOptimize(rank);
        benchmark::ClobberMemory();
    }

    state.counters["ArraySize"] = N;
    state.counters["RingDimension"] = cc->GetRingDimension();
}

// Register the benchmarks
BENCHMARK(BM_DirectSort<128>)->Unit(benchmark::kMillisecond)->UseRealTime();

BENCHMARK(BM_ConstructRank<128>)->Unit(benchmark::kMillisecond)->UseRealTime();

// Run the benchmark
BENCHMARK_MAIN();
