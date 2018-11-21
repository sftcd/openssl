#!/bin/bash

#set -x

# to pick up correct .so's - maybe note 
TOP=$HOME/code/openssl
export LD_LIBRARY_PATH=$TOP

# this is one I downloaded manually via dig +short TXT _esni.encryptedsni.com around 20181110 (ish)
#ESNI="/wHHBBOoACQAHQAg4YSfjSyJPNr1z3F8KqzBNBnMejim0mJZaPmria3XsicAAhMBAQQAAAAAW9pQEAAAAABb4jkQAAA="
#HIDDEN="encryptedsni.com"
#COVER="www.cloudflare.com"

# this is one I downloaded manually via dig +short TXT _esni.www.cloudflare.com on 20181121
ESNI="/wEU528gACQAHQAguwSAYz57kzOUzDXCAZ7aBJLWPrQwvSuNsRZbi7JzqkYAAhMBAQQAAAAAW/E4IAAAAABb+SEgAAA="
HIDDEN="www.cloudflare.com"
COVER="www.cloudflare.com"

# variables/settings
VG="no"
FRESH="no"
NOESNI="no"
DEBUG="no"
PORT="443"
SUPPLIEDSERVER=""
SUPPLIEDPORT=""
HTTPPATH="/cdn-cgi/trace"


function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

echo "Running $0 at $NOW"

function usage()
{
    echo "$0 [-dnfvh] - try out encrypted SNI via openssl s_client"
    echo "  -h means print this"
    echo "  -d means run s_client in verbose mode"
    echo "  -v means run with valgrind"
    echo "  -f means first get fresh ESNIKeys from DNS (via dig)"
    echo "  -n means don't trigger esni at all"
    echo "  -s [name] specifices a servername ('NONE' is special)"
    echo "  -p [port] specifices a port (default: 442)"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o p:s:dfvnh -l port:,servername:,debug,fresh,valgrind,noesni,help -- "$@")
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
        -d|--debug) DEBUG="yes" ;;
        -f|--fresh) FRESH="yes" ;;
        -v|--valgrind) VG="yes" ;;
        -n|--noesni) NOESNI="yes" ;;
        -s|--servername) SUPPLIEDSERVER=$2; shift;;
        -p|--port) SUPPLIEDPORT=$2; shift;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done

if [[ "$FRESH" == "yes" ]]
then
    echo "Checking for fresh ESNI value from $HIDDEN"
    ESNI=`dig +short TXT _esni.$HIDDEN | sed -e 's/"//g'`    
    echo "Fresh ESNI value: $ESNI"
fi    

esnistr="-esni $HIDDEN -esnirr $ESNI "
if [[ "$NOESNI" == "yes" ]]
then
    echo "Not connecting"
    esnistr=""
fi

dbgstr=""
if [[ "$DEBUG" == "yes" ]]
then
    #dbgstr="-msg -debug -security_debug_verbose -state -tlsextdebug"
    dbgstr="-msg "
fi

vgcmd=""
if [[ "$VG" == "yes" ]]
then
    vgcmd="valgrind --leak-check=full "
fi

if [[ "$SUPPLIEDPORT" != "" ]]
then
    PORT=$SUPPLIEDPORT
fi

servername=$COVER
snicmd="-servername $servername "
target=" -connect $COVER:$PORT "
if [[ "$SUPPLIEDSERVER" != "" ]]
then
    if [[ "$SUPPLIEDSERVER" == "NONE" ]]
    then
        snicmd="-noservername "
    else
        snicmd="-servername $SUPPLIEDSERVER "
        target=" -connect $SUPPLIEDSERVER:$PORT"
    fi
fi

httpreq="GET $HTTPPATH\\r\\n\\r\\n"

# force tls13
#force13="-cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
force13="-tls1_3 -cipher TLS13-AES-128-GCM-SHA256 "

echo "$httpreq" | $vgcmd $TOP/apps/openssl s_client $dbgstr $target $esnistr $snicmd $force13
