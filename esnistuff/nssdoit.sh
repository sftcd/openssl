#!/bin/bash

set -x

LDIR=/home/stephen/code/dist/Debug/
RDIR=/home/stephen/code/openssl/esnistuff


export LD_LIBRARY_PATH=$LDIR/lib
export SSLKEYLOGFILE=$RDIR/nss.premaster.txt
export SSLDEBUGFILE=$RDIR/nss.ssl.debug
export SSLTRACE=99
export SSLDEBUG=99

if [ ! -f $LDIR/bin/tstclnt ]
then
	echo "You need an NSS build first - can't find  $LDIR/bin/tstclnt"
	exit 1
fi


if [[ "$1" != "localhost" ]]
then
	ESNI=`dig +short txt _esni.www.cloudflare.com | sed -e 's/"//g'`
	valgrind $LDIR/bin/tstclnt -h www.cloudflare.com -p 443  \
		-d ~/.mozilla/eclipse/ \
		-N $ESNI
else
	ESNI=`cat $RDIR/esnikeydir/e2.pub | base64 -w0`
	valgrind $LDIR/bin/tstclnt -Q -h localhost -p 4000  \
		-a foo.example.com \
		-d cadir/nssca/ \
		-N $ESNI
fi
