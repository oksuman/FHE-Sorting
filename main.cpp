#include <iostream>
#include <fstream>
#include <string>
#include "sort.h"

using namespace lbcrypto;

int main(int argc, char *argv[])
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    arraySort sort;
    sort.eval();
    return 0;
}
