#include "comparison.h"
#include <benchmark/benchmark.h>
#include <cmath>
#include <random>

// Helper function to generate random doubles
double random_double(double min, double max) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(min, max);
    return dis(gen);
}

// Benchmark for scaled_sinc with random inputs
static void BM_ScaledSinc(benchmark::State &state) {
    double x = random_double(-10.0, 10.0);
    for (auto _ : state) {
        double result = Sinc<128>::scaled_sinc(x);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ScaledSinc);

// Benchmark for scaled_sinc_j with random inputs
static void BM_ScaledSincJ(benchmark::State &state) {
    double x = random_double(-10.0, 10.0);
    int j = static_cast<int>(random_double(-100, 100));
    for (auto _ : state) {
        double result = Sinc<128>::scaled_sinc_j(x, j);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ScaledSincJ);

BENCHMARK_MAIN();
