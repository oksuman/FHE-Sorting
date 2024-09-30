#include "sort.h"
#include "sort_algo.h"
#include <fstream>
#include <iostream>
#include <string>

using namespace lbcrypto;

int main(int argc, char *argv[]) {
    std::string pubKeyLocation, multKeyLocation, ccLocation, arrayLocation,
        outputLocation, rotKeyLocation;
    std::vector<std::string_view> args(argv + 1, argv + argc);

    for (size_t i = 0; i < args.size(); i += 2) {
        if (i + 1 >= args.size())
            break;

        if (args[i] == "--key_pub")
            pubKeyLocation = args[i + 1];
        else if (args[i] == "--key_mult")
            multKeyLocation = args[i + 1];
        else if (args[i] == "--key_rot")
            rotKeyLocation = args[i + 1];
        else if (args[i] == "--cc")
            ccLocation = args[i + 1];
        else if (args[i] == "--input" || args[i] == "--array")
            arrayLocation = args[i + 1];
        else if (args[i] == "--output")
            outputLocation = args[i + 1];
    }

    // Set the number of threads for OpenMP
    int procs = omp_get_num_procs();
    omp_set_num_threads(procs / 2);

    SortContext<128> sort(ccLocation, pubKeyLocation, multKeyLocation,
                          rotKeyLocation, arrayLocation, outputLocation);
    sort.eval(SortAlgo::DirectSort,
              {-1, -2, -4,  -8,  -16, -32,  1,    2,    4,    8,    16,
               32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384});
    sort.deserializeOutput();

    return 0;
}
