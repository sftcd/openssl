#!/bin/bash

# set -x

# to pick up correct .so's - maybe note 
: ${TOP=$HOME/code/openssl}
export LD_LIBRARY_PATH=$TOP

ESNIPUB=$TOP/esnistuff/esnikeys.pub
ESNIPRIV=$TOP/esnistuff/esnikeys.priv
ESNIKEYFILE=$TOP/esnistuff/esnipair.key

HIDDEN="foo.example.com"
HIDDEN2="bar.example.com"
CLEAR_SNI="example.com"
ESNIDIR="$TOP/esnistuff/esnikeydir"

SSLCFG="/etc/ssl/openssl.cnf"

# variables/settings
VG="no"
NOESNI="no"
DEBUG="no"
KEYGEN="no"
PORT="8443"
HARDFAIL="no"
TRIALDECRYPT="no"
SUPPLIEDPORT=""
DEFALPNVAL="-alpn h2,h2"
DOALPN="no"

SUPPLIEDKEYFILE=""
SUPPLIEDHIDDEN=""
SUPPLIEDCLEAR_SNI=""
SUPPLIEDDIR=""
#CAPATH="/etc/ssl/certs/"
CAPATH="$TOP/esnistuff/cadir/"

# whether we feed a bad key pair to server for testing
BADKEY="no"

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

echo "Running $0 at $NOW"

function usage()
{
    echo "$0 [-acHpDsdnlvhK] - try out encrypted SNI via openssl s_server"
    echo "  -a provide an ALPN value of $DEFALPNVAL"
    echo "  -H means serve that hidden server"
    echo "  -D means find esni private/public values in that directory"
    echo "  -d means run s_server in verbose mode"
    echo "  -v means run with valgrind"
    echo "  -n means don't trigger esni at all"
	echo "  -c [name] specifices a name that I'll accept as a cleartext SNI (NONE is special)"
    echo "  -p [port] specifices a port (default: 8443)"
	echo "  -F says to hard fail if ESNI attempted but fails"
	echo "  -T says to attempt trial decryption if necessary"
	echo "  -K to generate server keys "
	echo "  -k provide ESNI Key pair PEM file"
    echo "  -B to input a bad key pair to server setup, for testing"
    echo "  -h means print this"

	echo ""
	echo "The following should work:"
	echo "    $0 -c example.com -H foo.example.com"
	echo "To generate keys, set -H/-c as required:"
	echo "    $0 -K"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o ak:BTFc:D:H:p:Kdlvnh -l alpn,keyfile,badkey,trialdecrypt,hardfail,dir:,clear_sni:,hidden:,port:,keygen,debug,stale,valgrind,noesni,help -- "$@")
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
        -k|--keyfile) SUPPLIEDKEYFILE=$2; shift;;
        -K|--keygen) KEYGEN="yes" ;;
        -d|--debug) DEBUG="yes" ;;
        -v|--valgrind) VG="yes" ;;
        -n|--noesni) NOESNI="yes" ;;
        -c|--clear_sni) SUPPLIEDCLEAR_SNI=$2; shift;;
        -B|--badkey) BADKEY="yes";;
        -H|--hidden) SUPPLIEDHIDDEN=$2; shift;;
        -D|--dir) SUPPLIEDDIR=$2; shift;;
        -F|--hardfail) HARDFAIL="yes"; shift;;
        -T|--trialdecrypt) TRIALDECRYPT="yes"; shift;;
        -p|--port) SUPPLIEDPORT=$2; shift;;
        -a|--alpn) DOALPN="yes";;
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
clear_sni=$CLEAR_SNI
snicmd="-servername $clear_sni"
if [[ "$SUPPLIEDCLEAR_SNI" != "" ]]
then
    if [[ "$SUPPLIEDCLEAR_SNI" == "NONE" ]]
    then
        snicmd="-noservername "
    else
		clear_sni=$SUPPLIEDCLEAR_SNI
        snicmd=" -servername $clear_sni "
    fi
fi

KEYFILE1=$TOP/esnistuff/cadir/$clear_sni.priv
CERTFILE1=$TOP/esnistuff/cadir/$clear_sni.crt
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

# figure out if we have tracing enabled within OpenSSL
# there's probably an easier way but s_server -help
# ought work
TRACING=""
tmpf=`mktemp`
$TOP/apps/openssl s_server -help >$tmpf 2>&1
tcount=`grep -c 'trace protocol messages' $tmpf`
if [[ "$tcount" == "1" ]]
then
    TRACING="-trace "
fi
rm -f $tmpf

#dbgstr=" -verify_quiet"
dbgstr=" -quiet"
if [[ "$DEBUG" == "yes" ]]
then
    #dbgstr="-msg -debug -security_debug_verbose -state -tlsextdebug"
    dbgstr="-msg $TRACING -tlsextdebug "
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

if [[ "$BADKEY" == "yes" ]]
then
    if [[ "$esnidir" == "" ]]
    then
        echo "Can't feed bad key pair without setting esnikeydir"
        exit 88
    else
        echo "Feeding bogus key pair to server for test"
        echo "boguspub" >$esnidir/badkey.pub
        echo "boguspriv" >$esnidir/badkey.priv
    fi
fi

esnistr=""
if [[ "$SUPPLIEDKEYFILE" != "" ]]
then
    ESNIKEYFILE="$SUPPLIEDKEYFILE"
fi
if [ -f $ESNIKEYFILE ]
then
    echo "Using key pair from $ESNIKEYFILE"
    esnistr="$esnistr -esnikey $ESNIKEYFILE "
fi
if [[ -f $ESNIPUB && ! -f $ESNIPRIV ]]
then
    echo "Using key pair from $ESNIPUB and $ESNIPRIV"
    esnistr="$esnistr -esnipub $ESNIPUB -esnipriv $ESNIPRIV "
fi
if [ -d $esnidir ]
then
    echo "Using all key pairs found in $esnidir "
	esnistr="$esnistr -esnidir $esnidir"
fi

if [[ "$NOESNI" == "yes" ]]
then
    echo "Not trying ESNI"
    esnistr=""
fi

hardfail=""
if [[ "$HARDFAIL" == "yes" ]]
then
    hardfail=" -esnihardfail"
fi
trialdecrypt=""
if [[ "$TRIALDECRYPT" == "yes" ]]
then
    trialdecrypt=" -esnitrialdecrypt"
fi

# tell it where CA stuff is...
certsdb=" -CApath $CAPATH"

alpn=""
if [[ "$DOALPN"=="yes" ]]
then
    alpn=$DEFALPNVAL
fi

# force tls13
force13="-no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-tls1_3 -cipher TLS13-AES-128-GCM-SHA256 "

# turn off esni general padding - if we set this only the Certificate
# and CertificateVerify will be padded. Witout this, all plaintexts
# are (currently) padded
#padding=" -esnispecificpad"

# catch the ctrl-C used to stop the server and do any clean up needed
cleanup() {
    echo "Cleaning up after ctrl-c"
    if [[ "$BADKEY" == "yes" ]]
    then
        rm -f $esnidir/badkey.pub $esnidir/badkey.priv
    fi
}
trap cleanup SIGINT

if [[ "$DEBUG" == "yes" ]]
then
    echo "Running: $vgcmd $TOP/apps/openssl s_server $dbgstr $keyfile1 $keyfile2 $certsdb $portstr $force13 $esnistr $snicmd $padding $hardfail $trialdecrypt $alpn"
fi
$vgcmd $TOP/apps/openssl s_server $dbgstr $keyfile1 $keyfile2 $certsdb $portstr $force13 $esnistr $snicmd $padding $hardfail $trialdecrypt $alpn


