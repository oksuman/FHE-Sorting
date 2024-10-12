#pragma once

#include <vector>
#include <cassert>
#include <random>
#include <algorithm>

inline std::vector<double> getVectorWithMinDiff(int N) {
    assert(N < 255 * 100 &&
           "N should be less than or equal to 25500 to ensure all values are "
           "unique and have a minimum difference of 0.01.");

    std::vector<double> result(N);
    std::vector<int> integers(255 * 100); // 25500 = 255 * 100
    std::iota(integers.begin(), integers.end(),
              0); // Fill with values from 0 to 25499
    std::shuffle(integers.begin(), integers.end(),
                 std::mt19937{std::random_device{}()}); // Shuffle the integers

    for (int i = 0; i < N; ++i) {
        result[i] =
            integers[i] * 0.01; // Scale to have minimum difference of 0.01
    }

    return result;
}

inline std::vector<double> getVectorWithMinDiff(int N, double minValue, double maxValue, double minDiff) {
    assert(minValue < maxValue && "minValue must be less than maxValue");
    assert(minDiff > 0 && "minDiff must be greater than 0");
    
    double range = maxValue - minValue;
    int numSteps = static_cast<int>(std::floor(range / minDiff));
    
    assert(N <= numSteps && "N is too large for the given range and minimum difference");
    
    std::vector<int> integers(numSteps);
    std::iota(integers.begin(), integers.end(), 0);
    std::shuffle(integers.begin(), integers.end(), std::mt19937{std::random_device{}()});
    
    std::vector<double> result(N);
    
    for (int i = 0; i < N; ++i) {
        result[i] = minValue + integers[i] * minDiff;
    }
    
    return result;
}
