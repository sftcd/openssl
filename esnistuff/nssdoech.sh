#!/bin/bash

# set -x

# 2022-02-17 - got basic interop for my NSS build with CF and defo
# services
# - something up with port 8414 (forced HRR), not sure what's what yet
# - need to re-do the localhost stuff still (didn't try that at all and 
#   the cadir I have from a year ago has a now-outdated format). Some of
# - the HTTP respsonse content that this gets back is confusing and 
#   should be updated

LDIR=/home/stephen/code/dist/Debug/
RDIR=/home/stephen/code/openssl/esnistuff

export LD_LIBRARY_PATH=$LDIR/lib
#export SSLKEYLOGFILE=$RDIR/nss.premaster.txt
#export SSLDEBUGFILE=$RDIR/nss.ssl.debug
#export SSLTRACE=100
#export SSLDEBUG=100

function b64_ech_from_DNS()
{
    host=$1
    port=$2
    if [[ "$port" == "" ]]
    then
        port=443
        qname="$host"
    elif [[ "$port" == "443" ]]
    then
        qname="$host"
    else
        qname="_$port._https.$host"
    fi
    ECHRR=`dig +short -t TYPE65 $qname | \
        tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`
    if [[ "$ECHRR" == "" ]]
    then
        echo "Can't read ECHConfigList for $host:$port"
        exit 2
    fi
    # extract ECHConfigs from RR
    marker="FE0D"
    prefix=${ECHRR%%$marker*}
    index=${#prefix}
    ec_ah_ind=$((index-4))
    e_ah_len=${ECHRR:ec_ah_ind:4}
    ech_len=$(((2*(16#$e_ah_len+4))-3))
    ech_str=${ECHRR:ec_ah_ind:ech_len}
    ECH=`echo $ech_str | xxd -r -p | base64 -w0`
    echo $ECH
}


if [ ! -f $LDIR/bin/tstclnt ]
then
	echo "You need an NSS build first - can't find  $LDIR/bin/tstclnt"
	exit 1
fi

# the -4 seems to be down to some f/w oddity causing IPv6
# connections to fail from one vantage point - we don't need
# to care though, so we can just do IPv4 for now
NSSPARAMS=" -4 -D -b "

if [[ "$1" == "localhost" ]]
then
	ECH=`cat d13.pem | tail -2 | head -1`
	echo "Running: $LDIR/bin/tstclnt -b -h localhost -p 8443 -a foo.example.com -d cadir/nssca/ -N $ECH $*"
	$LDIR/bin/tstclnt -b -h localhost -p 8443 -a foo.example.com -d cadir/nssca/ -N $ECH $*
    exit $?
fi

# service specific details as CSVs...
cfdets="crypto.cloudflare.com,encryptedsni.com,443,cdn-cgi/trace"
cfrte="crypto.cloudflare.com,rte.ie,443,cdn-cgi/trace"
defo8413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,8413,stats"
defo8414="draft-13.esni.defo.ie,draft-13.esni.defo.ie,8414,stats"
defo9413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,9413," 
defo10413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,10413," 
defo11413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,11413," 
defo12413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,12413," 
defo12414="draft-13.esni.defo.ie,draft-13.esni.defo.ie,12414," 

services="$cfdets $cfrte \
    $defo8413 $defo8414 \
    $defo9413 \
    $defo10413 $defo11413 \
    $defo12413 $defo12414"
items=${#services[@]}

for item in $services
do
    echo "Doing $item"
    host=`echo $item | awk -F, '{print $1}'`
    innerhost=`echo $item | awk -F, '{print $2}'`
    port=`echo $item | awk -F, '{print $3}'`
    path=`echo $item | awk -F, '{print $4}'`
    httpreq="GET /$path HTTP/1.1\\r\\nConnection: close\\r\\nHost: $innerhost\\r\\n\\r\\n"
    ECH=`b64_ech_from_DNS $host $port`
    echo "Running: echo -e $httpreq | $LDIR/bin/tstclnt $NSSPARAMS -h $host -p $port -a $innerhost -N $ECH "
    echo -e $httpreq | timeout 1s $LDIR/bin/tstclnt $NSSPARAMS -h $host -p $port -a $innerhost -N $ECH 
    res=$?
    echo "res is: $res"
    echo "-----------------------" 
    echo "-----------------------" 
done

