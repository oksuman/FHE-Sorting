#include <algorithm>
#include <benchmark/benchmark.h>
#include <memory>
#include <openfhe.h>
#include <random>
#include <vector>

#include "encryption.h"
#include "sort_algo.h"

using namespace lbcrypto;
#include "encryption.h"
#include "sort_algo.h"
#include <benchmark/benchmark.h>

using namespace lbcrypto;

// Utility function to generate a vector with minimum difference (as in your
// original code)
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
    parameters.SetMultiplicativeDepth(50);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(N);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();

    std::vector<int> rotations = {0};
    for (int i = 1; i < N; i = i * 2) {
        rotations.push_back(i);
        rotations.push_back(-i);
    }

    cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto enc = std::make_shared<Encryption>(cc, keyPair.publicKey);
    auto directSort =
        std::make_unique<DirectSort<N>>(cc, keyPair.publicKey, enc);

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
BENCHMARK(BM_DirectSort<128>)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(5)
    ->Repetitions(3)
    ->ReportAggregatesOnly(true)
    ->UseRealTime();
BENCHMARK(BM_ConstructRank<128>)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(5)
    ->Repetitions(5)
    ->ReportAggregatesOnly(true)
    ->UseRealTime();

// Run the benchmark
BENCHMARK_MAIN();
