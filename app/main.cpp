#include "sort.h"
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
        } else if (arg == "--input") {
            arrayLocation = argv[i + 1];
        } else if (arg == "--output") {
            outputLocation = argv[i + 1];
        }
    }

    SortContext<128> sort(ccLocation, pubKeyLocation, multKeyLocation,
                          rotKeyLocation, arrayLocation, outputLocation);
    sort.eval();
    sort.deserializeOutput();
    return 0;
}
