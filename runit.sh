#!/bin/bash

export LD_LIBRARY_PATH=.
export OPENSSL_CONF_INCLUDE=./providers
export OPENSSL_ENGINES=./engines
export OPENSSL_MODULES=./providers
export OPENSSL_CONF=./test/fips-and-base.cnf

# ./test/ech_test -test 12 -iter 1 -v
gdb ./test/ech_test
