#!/bin/bash

#set -x

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


NSSPARAMS=" -Q -b"

if [[ "$1" == "localhost" ]]
then
	ESNI=`cat $RDIR/esnikeydir/ff01.pub | base64 -w0`
	valgrind $LDIR/bin/tstclnt $NSSPARAMS -h localhost -p 4000  \
		-a foo.example.com \
		-d cadir/nssca/ \
		-N $ESNI
elif [[ "$1" == "defo" ]]
then
    # draft -02 version
	ESNI=`dig +short txt _esni.only.esni.defo.ie | sed -e 's/"//g'`
    if [[ "$ESNI" == "" ]]
    then
        echo "No ESNI for defo - exiting"
        exit 1
    fi
	valgrind $LDIR/bin/tstclnt $NSSPARAMS -h only.esni.defo.ie -p 443  \
		-d ~/.mozilla/eclipse/ \
		-N $ESNI
else
	ESNI=`dig +short txt _esni.www.cloudflare.com | sed -e 's/"//g'`
	valgrind $LDIR/bin/tstclnt $NSSPARAMS -h www.cloudflare.com -p 443  \
		-d ~/.mozilla/eclipse/ \
		-N $ESNI
fi
