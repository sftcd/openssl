#!/bin/bash

# set -x

# 2022-02-18 
# - basic interop for my NSS build with CF and defo services ok
# - something up with port 8414 (server-forced HRR), server thinks
#   all's good, but NSS' tstclnt doesn't like 2nd SH (could be bug 
#   on NSS's side according to moz person)
# - tstclnt (used here) works with a test page for which FF fails

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
    ECHRR=`dig +unknownformat +short -t TYPE65 $qname | \
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


# parse command line

# whether to run a localhost test
LOCAL="no"
# whether a port was provided on command line
CLIPORT=""
VERBOSE="no"

function usage()
{
    echo "$0 [-plhv] - run interop tests using local NSS build vs. localhost, CF or defo.ie"
    echo "  -l to run a localhost test"
    echo "  -p port - specifies a specific listening port to test, all others skipped"
    echo "  -h means print this"
    echo "  -v means be more verbose"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o hlp:v -l help,local,port:,verbose -- "$@")
then
    # something went wrong, getopt will put out an error message for us
    exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
    case "$1" in
        -h|--help) usage;;
        -l|--local) LOCAL="yes";;
        -p|--port) CLIPORT=$2; shift;;
        -v|--verbosel) VERBOSE="yes";;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done

if [ ! -f $LDIR/bin/tstclnt ]
then
	echo "You need an NSS build first - can't find  $LDIR/bin/tstclnt"
	exit 1
fi

# the -4 seems to be down to some f/w oddity causing IPv6
# connections to fail from one vantage point - we don't need
# to care though, so we can just do IPv4 for now
NSSPARAMS=" -4 -D -b "

if [[ "$LOCAL" == "yes" ]]
then
    # a server needs to be listening on localhost:8413 - just
    # running ``./echsrv.sh -d`` should do the trick
    port="8443"
    if [[ "$CLIPORT" != "" ]]
    then
        port=$CLIPORT
    fi
	ECH=`cat echconfig.pem | tail -2 | head -1`
	echo "Running: $LDIR/bin/tstclnt -Q -b -h localhost -p $port \
        -a foo.example.com -d cadir/nssca/ -N $ECH $*"
    $LDIR/bin/tstclnt -Q -b -h localhost -p $port -a foo.example.com -d cadir/nssca/ -N $ECH $* 
    exit $?
fi

# service specific details as CSVs...
# hostname for DNS,sni for inner CH/HTTP Host: header field,port,URI path
defo443="defo.ie,defo.ie,443,ech-check.php"
cfdets="crypto.cloudflare.com,encryptedsni.com,443,cdn-cgi/trace"
cfrte="crypto.cloudflare.com,rte.ie,443,cdn-cgi/trace"
defo8413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,8413,stats"
defo8414="draft-13.esni.defo.ie,draft-13.esni.defo.ie,8414,stats"
defo9413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,9413," 
defo10413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,10413," 
defo11413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,11413," 
defo12413="draft-13.esni.defo.ie,draft-13.esni.defo.ie,12413," 
defo12414="draft-13.esni.defo.ie,draft-13.esni.defo.ie,12414," 

#services="$defo443 \
    #$cfdets $cfrte \
    #$defo8413 $defo8414 \
    #$defo9413 \
    #$defo10413 $defo11413 \
    #$defo12413 $defo12414"

services="$defo8413"

# no longer needed but I'll forget HOWTO so leave it here:-)
# items=${#services[@]}

for item in $services
do
    if [[ "$VERBOSE" == "yes" ]]
    then
        echo "-----------------------" 
        echo "Doing $item"
    fi
    host=`echo $item | awk -F, '{print $1}'`
    innerhost=`echo $item | awk -F, '{print $2}'`
    port=`echo $item | awk -F, '{print $3}'`
    path=`echo $item | awk -F, '{print $4}'`
    if [[ "$CLIPORT" != "" ]]
    then
        if [[ "$port" != "$CLIPORT" ]]
        then
            if [[ "$VERBOSE" == "yes" ]]
            then
                echo "Skipping... port $port != $CLIPORT"
                echo "-----------------------" 
            fi
            continue
        fi
    fi
    httpreq="GET /$path HTTP/1.1\\r\\nConnection: close\\r\\nHost: $innerhost\\r\\n\\r\\n"
    ECH=`b64_ech_from_DNS $host $port`
    echo "Running: echo -e $httpreq | $LDIR/bin/tstclnt $NSSPARAMS -h $host -p $port -a $innerhost -N $ECH "
    echo -e $httpreq | timeout 1s $LDIR/bin/tstclnt $NSSPARAMS -h $host -p $port -a $innerhost -N $ECH 
    res=$?
    if [[ "$port" != "$CLIPORT" ]]
    then
        echo "res is: $res"
        echo "-----------------------" 
    fi
done

