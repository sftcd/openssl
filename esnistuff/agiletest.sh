#!/bin/bash

# set -x

# to pick up correct executables and .so's  
: ${CODETOP:=$HOME/code/openssl}
export LD_LIBRARY_PATH=$CODETOP
# to pick up the relevant configuration
: ${CFGTOP:=$HOME/code/openssl}
# in case you want to re-use a tmp directory 
: ${SCRATCHDIR:=""}
# in case you want to keep output from this run, set this to something
: ${KEEP:=""}
# in case you'd like more detailed gibberish-like output:-)
: ${VERBOSE:=""}

KEM_STRINGS=(p256 p284 p521 x5519 x448 bogus-kem)
KEM_IDS=(0x10 0x11 0x12 0x20 0x21 0xa0)
NKEMS=${#KEM_IDS[*]}

KDF_STRINGS=(hkdf-sha256 hkdf-sha384 hkdf-sha512 bogus-kdf)
KDF_IDS=(0x01 0x02 0x03 0xa1)
NKDFS=${#KDF_IDS[*]}

AEAD_STRINGS=(aes-123-gcm aes-256-gcm chacha20poly1305 bogus-aead)
AEAD_IDS=(0x01 0x02 0x03 0xa2)
NAEADS=${#AEAD_IDS[*]}


verbose="no"
if [[ "$VERBOSE" != "" ]]
then
    verbose="yes"
fi

startdir=`/bin/pwd`

if [[ "$SCRATCHDIR" != "" && -d $SCRATCHDIR ]]
then
    scratchdir="$SCRATCHDIR"
else
    scratchdir=`/bin/mktemp -d`
fi

if [[ "$verbose" == "yes" ]]
then
    echo "Using $scratchdir"
fi
cd $scratchdir

# the same public_name for all test cases
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
            if [ -f $suite.pem ]
            then 
                # if re-using a scratchdir, we'll count that a win...
                goodcnt=$((goodcnt+1))
                continue
            fi
            if [[ "$verbose" == "yes" ]]
            then
                echo "Doing $suite ${KEM_STRINGS[$kemind]},${KDF_STRINGS[$kdfind]},${AEAD_STRINGS[$aeadind]}"
                echo "Running: $CODETOP/apps/openssl ech $pname -pemout $suite.pem -suite $suite"
                $CODETOP/apps/openssl ech $pname -pemout $suite.pem -suite $suite >/dev/null
            else
                $CODETOP/apps/openssl ech $pname -pemout $suite.pem -suite $suite >/dev/null 2>&1
            fi
            res=$?
            # count good/bad and compare to expectations
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
        done
    done
done

if [[ "$verbose" == "yes" ]]
then
    echo "Key gen: good: $goodcnt, bad: $badcnt, unexpected: $unexpectedcnt"
fi

#
# Stage 2 - simple client/server with each suite combo
#

# First, if needed, we want a fake CA, and TLS server certs etc
# (The "if needed" bit only applies if we re-use a tmpdir.)
if [ ! -d ./cadir ]
then
    # there's an odd issue with debug builds meaning we want
    # to use the system's openssl (for now) for these keys
    # FIXME: figure that out
    mkdir -p cadir
    cp /etc/ssl/openssl.cnf cadir
    obin=`which openssl`
    if [[ "$verbose" == "yes" ]]
    then
        echo "Making keys/fake CA etc."
        OBIN=$obin $CODETOP/esnistuff/make-example-ca.sh
    else
        OBIN=$obin $CODETOP/esnistuff/make-example-ca.sh >/dev/null 2>&1
    fi
fi

# check stuff worked above
if [ ! -f cadir/oe.priv ]
then
    echo "No sign of cadir/oe.priv - exiting"
    exit 11
fi

# make an oddball link to confuse echsvr.sh enough to work...
if [ ! -e esnistuff ]
then
    ln -s . esnistuff
fi

# We'll re-use the PEM files and dervice suites from file names

if [[ "$verbose" == "yes" ]]
then
    vparm=" -d "
fi

for file in *.pem 
do
    kem=${file:0:4}
    kdf=${file:5:4}
    aead=${file:10:4}
    echo "s_client/s_server test for kem: $kem, kdf: $kdf, aead; $aead"
    # start server
    if [[ "$verbose" == "yes" ]]
    then
        CFGTOP=$scratchdir $CODETOP/esnistuff/echsvr.sh -w -k $scratchdir/$file $vparm &
    else
        CFGTOP=$scratchdir $CODETOP/esnistuff/echsvr.sh -w -k $scratchdir/$file $vparm >/dev/null 2>&1 &
    fi
    # wait a bit
    sleep 4
    pids=`ps -ef | grep s_server | grep -v grep | awk '{print $2}'`
    if [[ "$pids" == "" ]]
    then
        echo "No sign of s_server - exiting (before client)"
        # exiting without cleanup
        exit 19
    fi
    # Try an 'aul client...
    # wait a bit
    sleep 4
    if [[ "$verbose" == "yes" ]]
    then
        $CODETOP/esnistuff/echcli.sh -P `$CODETOP/esnistuff/pem2rr.sh -p $file` -s localhost -p 8443 -H foo.example.com $vparm -f index.html
    else
        $CODETOP/esnistuff/echcli.sh -P `$CODETOP/esnistuff/pem2rr.sh -p $file` -s localhost -p 8443 -H foo.example.com $vparm -f index.html >/dev/null 2>&1
    fi
    cret=$?
    # kill server
    pids=`ps -ef | grep s_server | grep -v grep | awk '{print $2}'`
    if [[ "$pids" == "" ]]
    then
        echo "No sign of s_server - exiting (after client)"
        # exiting without cleanup
        exit 19
    fi
    kill $pids
    portpid=`netstat -anp 2>/dev/null | grep 8443 | grep openssl | awk '{print $7}' | sed -e 's#/.*##' 2>/dev/null`
    if [[ "$portpid" != "" ]]
    then
        kill $portpid
    fi
    pids=`ps -ef | grep s_server | grep -v grep | awk '{print $2}'`
    if [[ "$pids" != "" ]]
    then
        echo "hmm... $pids still running - exiting"
        # exiting without cleanup
        exit 20
    fi
    if [[ "$cret" != "0" ]]
    then
        echo "Client failed for $file - exiting"
        exit 21
    fi
    # sleep a bit
    sleep 2
done

cd $startdir
# clear up unless asked, to re-use
if [[ "$KEEP" == "" && "$SCRATCHDIR" == "" ]]
then
    rm -rf $scratchdir
fi

# success exit
echo "Looks like it worked out fine"
exit 0
