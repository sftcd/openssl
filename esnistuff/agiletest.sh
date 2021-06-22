#!/bin/bash

# set -x

# to pick up correct .so's - maybe note 
: ${CODETOP:=$HOME/code/openssl}
export LD_LIBRARY_PATH=$CODETOP
# to pick up the relevant configuration
: ${CFGTOP:=$HOME/code/openssl}


KEM_STRINGS=(p256 p284 p521 x5519 x448 bogus-kem)
KEM_IDS=(0x10 0x11 0x12 0x20 0x21 0xa0)
NKEMS=${#KEM_IDS[*]}

KDF_STRINGS=(hkdf-sha256 hkdf-sha384 hkdf-sha512 bogus-kdf)
KDF_IDS=(0x01 0x02 0x03 0xa1)
NKDFS=${#KDF_IDS[*]}

AEAD_STRINGS=(aes-123-gcm aes-256-gcm chacha20poly1305 bogus-aead)
AEAD_IDS=(0x01 0x02 0x03 0xa2)
NAEADS=${#AEAD_IDS[*]}

: ${VERBOSE:=""}

verbose="no"
if [[ "$VERBOSE" != "" ]]
then
    verbose="yes"
fi

startdir=`/bin/pwd`
scratchdir=`/bin/mktemp -d`

if [[ "$verbose" == "yes" ]]
then
    echo "Using $scratchdir"
fi
cd $scratchdir

pname="-public_name example.com"

# 
# Stage 1 generate keys as needed
#
badcnt=0
goodnt=0
unexpectedcnt=0
baddies=""
for ((kdfind=0 ; kdfind<$NKDFS ; kdfind++))
do
    for ((aeadind=0 ; aeadind<$NAEADS ; aeadind++))
    do
        for ((kemind=0 ; kemind<$NKEMS ; kemind++))
        do
            suite="${KEM_IDS[$kemind]},${KDF_IDS[$kdfind]},${AEAD_IDS[$aeadind]}"
            if [[ "$verbose" == "yes" ]]
            then
                echo "Doing $suite ${KEM_STRINGS[$kemind]},${KDF_STRINGS[$kdfind]},${AEAD_STRINGS[$aeadind]}"
                echo "Running: $CODETOP/apps/openssl ech $pname -pemout $suite.pem -suite $suite"
                $CODETOP/apps/openssl ech $pname -pemout $suite.pem -suite $suite >/dev/null
            else
                $CODETOP/apps/openssl ech $pname -pemout $suite.pem -suite $suite >/dev/null 2>&1
            fi
            res=$?
            if [[ "$res" != "1" ]]
            then
                baddies="$baddies $suite/$res"
                badcnt=$((badcnt+1))
                if [[ "$kemind" != "$((NKEMS-1))" && \
                        "$kdfind" != "$((NKDFS-1))" && \
                        "$aeadind" != "$((NAEADS-1))" ]]
                then
                    echo "Unexpected: $suite ${KEM_STRINGS[$kemind]},${KDF_STRINGS[$kdfind]},${AEAD_STRINGS[$aeadind]}"
                    unexpectedcnt=$((unexpectedcnt+1))
                fi
            else
                goodcnt=$((goodcnt+1))
            fi
            # count good/bad and compare to expectations
        done
    done
done

if [[ "$verbose" == "yes" ]]
then
    echo "Baddies: $baddies"
fi
echo "Key gen: good: $goodcnt, bad: $badcnt, unexpected: $unexpectedcnt"

cd $startdir
rm -rf $scratchdir
