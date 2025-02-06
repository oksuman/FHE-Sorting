# FHE-Sorting

TODO

## Tests

To run the unittests build the project in the project root.

```
mkdir build && cd build
cmake -B . -DCMAKE_CXX_COMPILER=clang++ ..
make -j
```
The runnable unittests will be created under the directory `build/tests/`. For example:

```
cd build
make SincTest && ./tests/SincTest
...
[100%] Built target SincTest
[==========] Running 3 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 1 test from SincTest
[ RUN      ] SincTest.ZeroInput
[       OK ] SincTest.ZeroInput (0 ms)
[----------] 1 test from SincTest (0 ms total)
...
[  PASSED  ] 3 tests.
```

