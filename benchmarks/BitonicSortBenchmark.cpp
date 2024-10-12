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

// Setup function for BitonicSort
template <int N> auto setupBitonicSort() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(58);
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

    std::vector<int> rotations = {-1, -2, -4, -8, -16, -32, 1,
                                  2,  4,  8,  16, 32,  64,  512};

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

// Benchmark function for BitonicSort
template <int N> static void BM_BitonicSort(benchmark::State &state) {
    auto [cc, bitonicSort, ctxt] = setupBitonicSort<N>();
    auto Cfg = SignConfig(CompositeSignConfig(4, 3, 3));
    for (auto _ : state) {
        auto ctxt_out = bitonicSort->sort(ctxt, SignFunc::CompositeSign, Cfg);
        benchmark::DoNotOptimize(ctxt_out);
        benchmark::ClobberMemory();
    }
    state.counters["ArraySize"] = N;
    state.counters["RingDimension"] = cc->GetRingDimension();
}

// Register the benchmarks
BENCHMARK(BM_BitonicSort<128>)->Unit(benchmark::kMillisecond)->UseRealTime();

// Run the benchmark
BENCHMARK_MAIN();
