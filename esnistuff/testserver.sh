#!/bin/bash

#set -x

# to pick up correct .so's - maybe note 
TOP=$HOME/code/openssl
export LD_LIBRARY_PATH=$TOP

ESNIPUB=$TOP/esnistuff/esnikeys.pub
ESNIPRIV=$TOP/esnistuff/esnikeys.priv
HIDDEN="foo.example.com"
HIDDEN2="bar.example.com"
COVER="example.com"
ESNIDIR="$TOP/esnistuff/esnikeydir"

SSLCFG="/etc/ssl/openssl.cnf"

# variables/settings
VG="no"
NOESNI="no"
DEBUG="no"
KEYGEN="no"
PORT="8443"
SUPPLIEDPORT=""

SUPPLIEDKEYFILE=""
SUPPLIEDHIDDEN=""
SUPPLIEDCOVER=""
SUPPLIEDDIR=""
#CAPATH="/etc/ssl/certs/"
CAPATH="$TOP/esnistuff/cadir/"

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

echo "Running $0 at $NOW"

function usage()
{
    echo "$0 [-cHpDsdnlvhK] - try out encrypted SNI via openssl s_server"
    echo "  -H means serve that hidden server"
    echo "  -D means find esni private/public values in that directory"
    echo "  -d means run s_server in verbose mode"
    echo "  -v means run with valgrind"
    echo "  -n means don't trigger esni at all"
	echo "  -c [name] specifices a covername that I'll accept as a clear SNI (NONE is special)"
    echo "  -p [port] specifices a port (default: 8443)"
	echo "  -K to generate server keys "
    echo "  -h means print this"

	echo ""
	echo "The following should work:"
	echo "    $0 -c example.com -H foo.example.com"
	echo "To generate keys, set -H/-c as required:"
	echo "    $0 -K"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o c:D:H:p:Kdlvnh -l dir:,cover:,hidden:,port:,keygen,debug,stale,valgrind,noesni,help -- "$@")
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
        -K|--keygen) KEYGEN="yes" ;;
        -d|--debug) DEBUG="yes" ;;
        -v|--valgrind) VG="yes" ;;
        -n|--noesni) NOESNI="yes" ;;
        -c|--cover) SUPPLIEDCOVER=$2; shift;;
        -H|--hidden) SUPPLIEDHIDDEN=$2; shift;;
        -D|--dir) SUPPLIEDDIR=$2; shift;;
        -p|--port) SUPPLIEDPORT=$2; shift;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done

hidden=$HIDDEN
if [[ "$SUPPLIEDHIDDEN" != "" ]]
then
	hidden=$SUPPLIEDHIDDEN
fi

# Set SNI
cover=$COVER
snicmd="-servername $cover"
if [[ "$SUPPLIEDCOVER" != "" ]]
then
    if [[ "$SUPPLIEDCOVER" == "NONE" ]]
    then
        snicmd="-noservername "
    else
		cover=$SUPPLIEDCOVER
        snicmd=" -servername $cover "
    fi
fi

KEYFILE1=$TOP/esnistuff/cadir/$cover.priv
CERTFILE1=$TOP/esnistuff/cadir/$cover.crt
KEYFILE2=$TOP/esnistuff/cadir/$hidden.priv
CERTFILE2=$TOP/esnistuff/cadir/$hidden.crt
KEYFILE3=$TOP/esnistuff/cadir/$HIDDEN2.priv
CERTFILE3=$TOP/esnistuff/cadir/$HIDDEN2.crt

if [[ "$KEYGEN" == "yes" ]]
then
	echo "Generating kays and exiting..."
	./make-example-ca.sh
	exit
fi

keyfile1="-key $KEYFILE1 -cert $CERTFILE1"
keyfile2="-key2 $KEYFILE2 -cert2 $CERTFILE2"
keyfile3="-key2 $KEYFILE3 -cert2 $CERTFILE3"

#dbgstr=" -verify_quiet"
dbgstr=" -quiet"
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
portstr=" -port $PORT "

esnidir=$ESNIDIR
if [[ "$SUPPLIEDDIR" != "" ]]
then
	esnidir=$SUPPLIEDDIR
fi

esnistr=" -esnipub $ESNIPUB -esnikey $ESNIPRIV -esnidir $esnidir"
if [[ ! -f $ESNIPUB || ! -f $ESNIPRIV ]]
then
	esnistr=" -esnidir $esnidir"
fi

if [[ "$NOESNI" == "yes" ]]
then
    echo "Not trying ESNI"
    esnistr=""
fi

# tell it where CA stuff is...
certsdb=" -CApath $CAPATH"

# force tls13
force13="-no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-tls1_3 -cipher TLS13-AES-128-GCM-SHA256 "

# turn off esni general padding - if we set this only the Certificate
# and CertificateVerify will be padded. Witout this, all plaintexts
# are (currently) padded
#padding=" -esnispecificpad"

$vgcmd $TOP/apps/openssl s_server $dbgstr $keyfile1 $keyfile2 $certsdb $portstr $force13 $esnistr $snicmd $padding


