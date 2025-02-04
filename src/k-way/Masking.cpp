#include "Masking.h"
#include <iostream>

namespace kwaySort {

void printMask(const std::vector<double> &mask, long start, long end) {
    if (end == -1) {
        end = mask.size();
    }
    for (int i = start; i < end; i++) {
        std::cout << mask[i] << " ";
    }
    std::cout << std::endl;
}

void printVector(const std::vector<int> &mask, long start, long end) {
    if (end == -1) {
        end = mask.size();
    }
    for (int i = start; i < end; i++) {
        std::cout << mask[i] << " ";
    }
    std::cout << std::endl;
}

std::tuple<int, int, int> sortType(int k, int M, int stage) {
    int upperk = (k + 1) / 2;
    int r = 0;

    // f(r) = r + r(r-1)/2 * upperk
    // r = maximum r s.t. f(r) < stage
    // n = stage - f(r)
    while (stage >= (r + 1 + r * (r + 1) / 2 * upperk))
        r++;
    int n = stage - (r + r * (r - 1) / 2 * upperk);

    int m = (n + upperk - 1) / upperk;
    int logDist = r - m;
    int slope;

    if (n == 0)
        slope = 0;
    else
        slope = ((n - 1) % upperk) + 1;

    return std::make_tuple(m, logDist, slope);
}

std::vector<std::vector<int>> genIndices(long numSlots, long k, long M, long m,
                                         long logDist, long slope) {
    std::vector<std::vector<int>> res(2);
    for (int i = 0; i < res.size(); i++) {
        res[i].resize(numSlots, 0);
    }

    long km = pow(k, m);
    long dist = pow(k, logDist);
    long next = pow(k, m + 1);

    for (long start = 0; start < pow(k, M); start += dist * next) {
        if (slope == 0) {
            for (int s = 0; s < km; s++) {
                long loc = 1;
                long row = s;
                long col = 0;
                while (row >= 0 && col < k) {
                    for (int d = 0; d < dist; d++) {
                        long here = start + dist * (row + km * col) + d;
                        res[0][here] = k;
                        res[1][here] = loc;
                    }
                    loc += 1;
                    col += 1;
                }
            }
        } else if (slope > k / 2) {
            for (int t = 0; t < km - 1; t++) {
                int col = k - k / 2;
                for (int loc = 1; loc < k; loc++) {
                    for (int d = 0; d < dist; d++) {
                        long here = start + dist * (col + k * t + loc - 1) + d;
                        res[0][here] = k - 1;
                        res[1][here] = loc;
                    }
                }
            }
        } else {
            // Handle diagonal patterns
            for (int t = slope; t < k; t++) {
                int row = 0;
                int col = t;
                int loc = 1;
                while (row < km && col >= 0) {
                    for (int d = 0; d < dist; d++) {
                        long here = start + dist * (col + k * row) + d;
                        res[0][here] = loc;
                        if (row == km - 1 || col - slope < 0) {
                            for (int i = 0; i < loc; i++) {
                                long row_new = row - i;
                                long col_new = col + i * slope;
                                long here_new =
                                    start + dist * (col_new + k * row_new) + d;
                                res[1][here_new] = loc - i;
                                res[0][here_new] += i;
                            }
                        }
                    }
                    loc += 1;
                    row += 1;
                    col -= slope;
                }
            }

            for (int s = 1; s < km - 1; s++) {
                for (int t = k - slope; t < k; t++) {
                    int row = s;
                    int col = t;
                    int loc = 1;
                    while (row < km && col >= 0) {
                        for (int d = 0; d < dist; d++) {
                            long here = start + dist * (col + k * row) + d;
                            res[0][here] = loc;
                            if (row == km - 1 || col - slope < 0) {
                                for (int i = 0; i < loc; i++) {
                                    long row_new = row - i;
                                    long col_new = col + i * slope;
                                    long here_new =
                                        start + dist * (col_new + k * row_new) +
                                        d;
                                    res[1][here_new] = loc - i;
                                    res[0][here_new] += i;
                                }
                            }
                        }
                        loc += 1;
                        row += 1;
                        col -= slope;
                    }
                }
            }
        }
    }
    return res;
}

void genMask(const std::vector<std::vector<int>> &indices, long index0,
             long index1, std::vector<double> &mask) {
    long numSlots = indices[0].size();
    mask.resize(numSlots, 0.0);

    for (int i = 0; i < numSlots; i++) {
        if (indices[0][i] == index0 && indices[1][i] == index1) {
            mask[i] = 1.0;
        }
    }
}

long getRotateDistance(long k, long logDist, long slope) {
    long dist = pow(k, logDist);
    if (slope == 0) {
        return dist;
    } else if (slope == k / 2 + 1) {
        return dist;
    } else {
        return dist * (k - slope);
    }
}

} // namespace kwaySort
