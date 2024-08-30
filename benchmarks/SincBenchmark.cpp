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
        double result = scaled_sinc(x);
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
        double result = scaled_sinc_j(x, j);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ScaledSincJ);

// Benchmark for scaled_sinc evenness
static void BM_ScaledSincEvenness(benchmark::State &state) {
    double x = random_double(0.0, 10.0);
    for (auto _ : state) {
        double result1 = scaled_sinc(x);
        double result2 = scaled_sinc(-x);
        benchmark::DoNotOptimize(result1);
        benchmark::DoNotOptimize(result2);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ScaledSincEvenness);

// Benchmark for scaled_sinc_j periodicity
static void BM_ScaledSincJPeriodicity(benchmark::State &state) {
    double x = random_double(-10.0, 10.0);
    int j = static_cast<int>(random_double(-100, 100));
    for (auto _ : state) {
        double result1 = scaled_sinc_j(x, j);
        double result2 = scaled_sinc_j(x + 2048, j);
        benchmark::DoNotOptimize(result1);
        benchmark::DoNotOptimize(result2);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ScaledSincJPeriodicity);

BENCHMARK_MAIN();
