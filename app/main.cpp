#include "sort.h"
#include "sort_algo.h"
#include <fstream>
#include <iostream>
#include <string>

using namespace lbcrypto;

int main(int argc, char *argv[]) {
    std::string pubKeyLocation;
    std::string multKeyLocation;
    std::string ccLocation;
    std::string arrayLocation;
    std::string outputLocation;
    std::string rotKeyLocation;

    std::this_thread::sleep_for(std::chrono::seconds(2));

    for (int i = 1; i < argc; i += 2) {
        std::string arg = argv[i];
        if (arg == "--key_pub") {
            pubKeyLocation = argv[i + 1];
        } else if (arg == "--key_mult") {
            multKeyLocation = argv[i + 1];
        } else if (arg == "--key_rot") {
            rotKeyLocation = argv[i + 1];
        } else if (arg == "--cc") {
            ccLocation = argv[i + 1];
        } else if (arg == "--input" || arg == "--array") {
            arrayLocation = argv[i + 1];
        } else if (arg == "--output") {
            outputLocation = argv[i + 1];
        }
    }

    // https://github.com/openfheorg/openfhe-development/blob/main/docs/static_docs/Best_Performance.md#multithreading-configuration-using-openmp
    // nproc/2 is suggested for better performance with OpenMP

    auto procs = omp_get_num_procs();
    omp_set_num_threads(procs / 2);

    SortContext<128> sort(ccLocation, pubKeyLocation, multKeyLocation,
                          rotKeyLocation, arrayLocation, outputLocation);
    sort.eval(SortAlgo::DirectSort,
              {-32, -16, -8, -4, -2, -1, 1, 2, 4, 8, 16, 32, 64, 512});
    sort.deserializeOutput();
    return 0;
}
