#!/usr/bin/env bash
#
# Grab a version of golang 1.26 and then run our HPKE/golang interop test programs.
#
# This is an external test, so to run this you need to build as follows:
#       ./config enable-external-tests
#       make -j12
# and to run it:
#       make test TESTS=test_external_hpke_golang V=1

set -e

PWD="$(pwd)"
SRCTOP="$(cd $SRCTOP; pwd)"
BLDTOP="$(cd $BLDTOP; pwd)"

if [ "$SRCTOP" != "$BLDTOP" ] ; then
    echo "Out of tree builds not supported with HPKE external golang test!"
    exit 1
fi

C_BIN="$PWD/hpke_ftest_c"
GO_BIN="$PWD/hpke_ftest_go"
TSRC="$SRCTOP/test/recipes/95-test_external_hpke_golang_data"
# SUITES omits mlkem512 which is supported in OpenSSL but not golang
SUITES="x25519 p256 mlkem768 mlkem1024 xwing mlkem768p256 mlkem1024p384"
O_EXE="$BLDTOP/apps"
O_BINC="$BLDTOP/include"
O_SINC="$SRCTOP/include"
O_LIB="$BLDTOP"

unset OPENSSL_CONF

# Check/Set openssl version
OPENSSL_VERSION=`openssl version | cut -f 2 -d ' '`

echo "------------------------------------------------------------------"
echo "Testing OpenSSL HPKE interop with gloang HPKE :"
echo "   CWD:                 $PWD"
echo "   Test sources:        $TSRC"
echo "   SRCTOP:              $SRCTOP"
echo "   BLDTOP:              $BLDTOP"
echo "   OpenSSL version:     $OPENSSL_VERSION"
echo "   HPKE test binary:    $C_BIN"
echo "   gloang test binary:  $GO_BIN"
echo "------------------------------------------------------------------"

gcc -o $C_BIN $TSRC/hpke_ftest.c -I$SRCTOP/include -L$BLDTOP -lssl -lcrypto -Wl,-rpath,$BLDTOP
go build -o $GO_BIN $TSRC/hpke_ftest.go

PASSED=0
FAILED=0
WORKDIR="workdir"
test -d "$WORKDIR" || mkdir "$WORKDIR"

run_step() {
    local label="$1"
    local dir="$2"
    local logfile="$dir/${label##*/}.log"
    shift 2
    if (cd "$dir" && "$@") > "$logfile" 2>&1; then
        echo "PASS  $label"
        sed 's/^/      /' "$logfile"
        PASSED=$(( PASSED + 1 ))
    else
        echo "FAIL  $label"
        sed 's/^/      /' "$logfile"
        FAILED=$(( FAILED + 1 ))
    fi
}

for suite in $SUITES; do
    dir="$WORKDIR/$suite"
    mkdir -p "$dir"

    run_step "$suite/go_keygen"  "$dir" "$GO_BIN" -suite "$suite" keygen
    run_step "$suite/c_keygen"   "$dir" "$C_BIN"  -suite "$suite" keygen
    run_step "$suite/go_encrypt" "$dir" "$GO_BIN" -suite "$suite" encrypt
    run_step "$suite/c_encrypt"  "$dir" "$C_BIN"  -suite "$suite" encrypt
    run_step "$suite/c_decrypt"  "$dir" "$C_BIN"  -suite "$suite" decrypt
    run_step "$suite/go_decrypt" "$dir" "$GO_BIN" -suite "$suite" decrypt
done

TOTAL=$(( PASSED + FAILED ))
echo "$PASSED / $TOTAL passed, WORKDIR is $WORKDIR"
# return zero for good
exit $FAILED
