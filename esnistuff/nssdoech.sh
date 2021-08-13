#!/bin/bash

# set -x

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


NSSPARAMS=" -Q"
XNSSPARAMS=" -Q"

if [[ "$1" == "localhost" ]]
then
	ECHCFG=`cat echconfig-256.pem | tail -2 | head -1`
	echo "Running: valgrind $LDIR/bin/tstclnt $NSSPARAMS -h localhost -p 8443 -a foo.example.com -d cadir/nssca/ -N $ECHCFG" 
	valgrind $LDIR/bin/tstclnt $NSSPARAMS -h localhost -p 8443 -a foo.example.com -d cadir/nssca/ -N $ECHCFG
elif [[ "$1" == "defo" ]]
then
    echo "Not there yet - exiting"
    exit 1
    # draft -09 version
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
    CFFE="crypto.cloudflare.com"
    #TARGET="blog.cloudflare.com"
    TARGET="rte.ie"
    ECHRR=`dig +short -t TYPE65 $CFFE | tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`
    # extract ECHConfigs from RR
    ECHwithtail=`echo $ECHRR |  sed -e 's/\(....FE09\)/-\1/' | cut -d'-' -f 2`
    ahlen0=${ECHwithtail:0:1}
    ahlen1=${ECHwithtail:1:1}
    ahlen2=${ECHwithtail:2:1}
    ahlen3=${ECHwithtail:3:1}
    echlen=$((ahlen0*16*16*16+ahlen1*16*16+ahlen2*16+ahlen3+2))
    echlen=$((2*echlen)) # octets -> AH chars
    ECH_AH=${ECHwithtail:0:echlen}
    ECH=`echo $ECH_AH | xxd -r -p | base64 -w0`
	 $LDIR/bin/tstclnt $XNSSPARAMS -h $CFFE -a $TARGET -p 443  \
        -d /home/stephen/.mozilla/firefox/33d5rynn.default-1566560611149/ \
		-N $ECH $*
fi
