#!/bin/bash

LDIR=/home/stephen/code/dist/Debug/
RDIR=/home/stephen/code/openssl/esnistuff

ESNI=`dig +short txt _esni.www.cloudflare.com | sed -e 's/"//g'`

export LD_LIBRARY_PATH=$LDIR/lib
export SSLKEYLOGFILE=$RDIR/nss.premaster.txt
export SSLDEBUGFILE=$RDIR/nss.ssl.debug
export SSLTRACE=99
export SSLDEBUG=99



valgrind $LDIR/bin/tstclnt -h www.cloudflare.com -p 443  \
	-d ~/.mozilla/eclipse/ \
	-N $ESNI
