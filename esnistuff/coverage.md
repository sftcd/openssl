
# How to see coverage of tests

@slontis once told me how:

```bash
./config --debug --coverage no-asm no-afalgeng no-shared -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
make -s -j4
make test TESTS='test_ech test_app_ech'
# next line failed, was replaced the the one following
# lcov -d . -c -o ./lcov.info
/usr/bin/geninfo . --output-filename ./lcov.info --memory 0 --ignore-errors mismatch
genhtml ./lcov.info --output-directory $HOME/tmp/myco
```

