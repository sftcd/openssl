#!/bin/bash

#  set -x

LDIR=/home/stephen/code/dist/Debug/
RDIR=/home/stephen/code/openssl/esnistuff

export LD_LIBRARY_PATH=$LDIR/lib
#export SSLKEYLOGFILE=$RDIR/nss.premaster.txt
#export SSLDEBUGFILE=$RDIR/nss.ssl.debug
#export SSLTRACE=100
#export SSLDEBUG=100

if [ ! -f $LDIR/bin/tstclnt ]
then
	echo "You need an NSS build first - can't find  $LDIR/bin/tstclnt"
	exit 1
fi

NSSPARAMS=" -D -b "

# 2022-02-17 - got basic interop for my NSS build with CF and defo:8413
# need to tidy this up a lot and add other defo.ie ports and re-do the
# localhost tests (didn't try that at all and the cadir I have from a
# year ago has a now-outdated format).

if [[ "$1" == "localhost" ]]
then
	ECHCFG=`cat echconfig-256.pem | tail -2 | head -1`
	echo "Running: valgrind $LDIR/bin/tstclnt $NSSPARAMS -h localhost -p 8443 -a foo.example.com -d cadir/nssca/ -N $ECHCFG" 
	valgrind $LDIR/bin/tstclnt $NSSPARAMS -h localhost -p 8443 -a foo.example.com -d cadir/nssca/ -N $ECHCFG
elif [[ "$1" == "defo" ]]
then
    defohost="draft-13.esni.defo.ie"
    defoport="8413"
    defohttpreq="GET /stats HTTP/1.1\\r\\nConnection: close\\r\\nHost: $defohost\\r\\n\\r\\n"
    ECHRR=`dig +short -t TYPE65 "_$defoport._https.$defohost" | \
        tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`
    if [[ "$ECHRR" == "" ]]
    then
        echo "Can't read ECHConfigList for $defohost:$defoport"
        exit 2
    fi
    # extract ECHConfigs from RR - TODO: make this a function!
    marker="FE0D"
    prefix=${ECHRR%%$marker*}
    index=${#prefix}
    ec_ah_ind=$((index-4))
    e_ah_len=${ECHRR:ec_ah_ind:4}
    ech_len=$(((2*(16#$e_ah_len+4))-3))
    ech_str=${ECHRR:ec_ah_ind:ech_len}
    ECH=`echo $ech_str | xxd -r -p | base64 -w0`

    # this does get content and exit but leaves a TIME_WAIT socket - that's ok for now
    echo -e $defohttpreq | timeout 1s $LDIR/bin/tstclnt $NSSPARAMS -h $defohost -p $defoport -D -N $ECH 
else
    # CF URL that works for FF: https://crypto.cloudflare.com/cdn-cgi/trace
    CFFE="crypto.cloudflare.com"
    #TARGET="encryptedsni.com"
    TARGET="rte.ie"
    httpreq="GET /cdn-cgi/trace HTTP/1.1\\r\\nConnection: close\\r\\nHost: $TARGET\\r\\n\\r\\n"

    ECHRR=`dig +short -t TYPE65 $CFFE | tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`
    if [[ "$ECHRR" == "" ]]
    then
        echo "Can't read ECHConfigList for $CFFE"
        exit 2
    fi
    # extract ECHConfigs from RR - TODO: make this a function!
    marker="FE0D"
    prefix=${ECHRR%%$marker*}
    index=${#prefix}
    ec_ah_ind=$((index-4))
    e_ah_len=${ECHRR:ec_ah_ind:4}
    ech_len=$(((2*(16#$e_ah_len+4))-3))
    ech_str=${ECHRR:ec_ah_ind:ech_len}
    ECH=`echo $ech_str | xxd -r -p | base64 -w0`

    echo -e $httpreq | timeout 1s $LDIR/bin/tstclnt $NSSPARAMS -h $CFFE -a $TARGET -p 443 -N $ECH $*
fi
