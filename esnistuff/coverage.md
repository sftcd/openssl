
# How to see coverage of tests

@slontis once told me how:

```bash
./config --debug --coverage no-asm no-afalgeng no-shared -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
make -s -j4
make test TESTS=''ech_test"
lcov -d . -c -o ./lcov.info
genthml source ./lcov.info --output-directory /tmp/myco
```

Last line might need tweaks...
