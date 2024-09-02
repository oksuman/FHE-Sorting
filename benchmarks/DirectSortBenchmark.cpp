#include <benchmark/benchmark.h>
#include <openfhe.h>
#include <vector>
#include <algorithm>
#include <random>
#include <memory>

#include "sort_algo.h"
#include "encryption.h"

using namespace lbcrypto;

// Utility function to generate a vector with minimum difference (as in your original code)
std::vector<double> getVectorWithMinDiff(int N) {
    std::vector<double> result(N);
    std::vector<int> integers(25500);
    std::iota(integers.begin(), integers.end(), 0);
    std::shuffle(integers.begin(), integers.end(), std::mt19937{std::random_device{}()});
    for (int i = 0; i < N; ++i) {
        result[i] = integers[i] * 0.01;
    }
    return result;
}

// Benchmark function
static void BM_DirectSort(benchmark::State& state) {
    // Setup (this will be done once for all iterations)
    constexpr int array_length = 128;
    
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(50);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(array_length);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();

    std::vector<int> rotations;
    for (int i = 1; i <= array_length; i++) {
        rotations.push_back(i);
        rotations.push_back(-i);
    }
    for (int i = 1; i <= array_length; i++) {
        rotations.push_back(-i * 64);
    }

    cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto enc = std::make_shared<Encryption>(cc, keyPair);
    auto directSort = std::make_unique<DirectSort<array_length>>(cc, keyPair.publicKey, enc);

    std::vector<double> inputArray = getVectorWithMinDiff(array_length);
    auto ctxt = enc->encryptInput(inputArray);

    // Benchmark loop
    for (auto _ : state) {
        // This code will be measured repeatedly
        auto ctxt_out = directSort->sort(ctxt);
        benchmark::DoNotOptimize(ctxt_out); // Ensure the result is not optimized away
        benchmark::ClobberMemory(); // Ensure the entire computation is done
    }

    // You can report custom metrics
    state.counters["ArraySize"] = array_length;
    state.counters["RingDimension"] = cc->GetRingDimension();
}

// Register the benchmark
BENCHMARK(BM_DirectSort)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(5)
    ->Repetitions(3)
    ->ReportAggregatesOnly(true)
    ->UseRealTime();

// Run the benchmark
BENCHMARK_MAIN();
