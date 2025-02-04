#ifndef MASKING_H_
#define MASKING_H_

#include "openfhe.h"
#include <algorithm>
#include <cmath>
#include <tuple>
#include <vector>

using namespace lbcrypto;

namespace kwaySort {

// Debug utilities for mask visualization
void printMask(const std::vector<double> &mask, long start = 0, long end = -1);
void printVector(const std::vector<int> &mask, long start = 0, long end = -1);

// Core masking functions
std::tuple<int, int, int> sortType(int k, int M, int stage);
std::vector<std::vector<int>> genIndices(long numSlots, long k, long M, long m,
                                         long dist, long slope);

// Generate mask for specific indices
void genMask(const std::vector<std::vector<int>> &indices, long index0,
             long index1, std::vector<double> &mask);

// Compute rotation distance
long getRotateDistance(long k, long logDist, long slope);

} // namespace kwaySort

#endif
