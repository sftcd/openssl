#!/bin/bash

# set -x

# to pick up correct .so's - maybe note 
: ${CODETOP:=$HOME/code/openssl}
export LD_LIBRARY_PATH=$CODETOP
# to pick up the relevant configuration
: ${CFGTOP:=$HOME/code/openssl}

ECHKEYFILE="$CFGTOP/esnistuff/echconfig.pem"
ECH10KEYFILE="$CFGTOP/esnistuff/echconfig-10.pem"
# prefer the draft-10 file if it's there
if [ -f $ECH10KEYFILE ]
then
    ECHKEYFILE="$CFGTOP/esnistuff/echconfig-10.pem"
fi 

HIDDEN="foo.example.com"
HIDDEN2="bar.example.com"
CLEAR_SNI="example.com"
ECHDIR="$CFGTOP/esnistuff/echkeydir"

SSLCFG="/etc/ssl/openssl.cnf"

# variables/settings
VG="no"
NOECH="no"
DEBUG="no"
KEYGEN="no"
PORT="8443"
HARDFAIL="no"
TRIALDECRYPT="no"
SUPPLIEDPORT=""
WEBSERVER=""

SUPPLIEDKEYFILE=""
SUPPLIEDHIDDEN=""
SUPPLIEDCLEAR_SNI=""
SUPPLIEDDIR=""
CAPATH="$CFGTOP/esnistuff/cadir/"

# whether we feed a bad key pair to server for testing
BADKEY="no"

# whethe or not to do ECH-specific paddng
ECHPAD="no"

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

echo "Running $0 at $NOW"

function usage()
{
    echo "$0 [-cHpDsdnlvhKw] - try out encrypted SNI via openssl s_server"
    echo "  -B to input a bad key pair to server setup, for testing"
	echo "  -c [name] specifices a name that I'll accept as a cleartext SNI (NONE is special)"
    echo "  -D means find ech config files in that directory"
    echo "  -d means run s_server in verbose mode"
	echo "  -F says to hard fail if ECH attempted but fails"
    echo "  -H means serve that hidden server"
    echo "  -h means print this"
	echo "  -K to generate server keys "
	echo "  -k provide ECH Key pair PEM file"
    echo "  -n means don't trigger ech at all"
    echo "  -p [port] specifices a port (default: 8443)"
    echo "  -P turn on ECH specific padding"
    echo "  -v means run with valgrind"
	echo "  -T says to attempt trial decryption if necessary"
    echo "  -w means to run as a pretty dumb web server"

	echo ""
	echo "The following should work:"
	echo "    $0 -c example.com -H foo.example.com"
	echo "To generate keys, set -H/-c as required:"
	echo "    $0 -K"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o k:BTFc:D:H:p:PKdlvnhw -l keyfile,badkey,trialdecrypt,hardfail,dir:,clear_sni:,hidden:,port:,pad,keygen,debug,stale,valgrind,noech,help,web -- "$@")
then
    # something went wrong, getopt will put out an error message for us
    exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
    case "$1" in
        -B|--badkey) BADKEY="yes";;
        -c|--clear_sni) SUPPLIEDCLEAR_SNI=$2; shift;;
        -d|--debug) DEBUG="yes" ;;
        -D|--dir) SUPPLIEDDIR=$2; shift;;
        -F|--hardfail) HARDFAIL="yes"; shift;;
        -h|--help) usage;;
        -H|--hidden) SUPPLIEDHIDDEN=$2; shift;;
        -k|--keyfile) SUPPLIEDKEYFILE=$2; shift;;
        -K|--keygen) KEYGEN="yes" ;;
        -n|--noech) NOECH="yes" ;;
        -p|--port) SUPPLIEDPORT=$2; shift;;
        -P|--pad) ECHPAD="yes";;
        -T|--trialdecrypt) TRIALDECRYPT="yes"; shift;;
        -v|--valgrind) VG="yes" ;;
        -w|--web) WEBSERVER=" -WWW " ;;
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

# Set preferred ALPN - can parameterise later if/as needed
alpn_cmd=" -alpn http/1.1,h2 "

# Set padding if needed
echpad_cmd=""
if [[ "$ECHPAD" == "yes" ]]
then
    echpad_cmd=" -echspecificpad "
fi

KEYFILE1=$CFGTOP/esnistuff/cadir/$clear_sni.priv
CERTFILE1=$CFGTOP/esnistuff/cadir/$clear_sni.crt
KEYFILE2=$CFGTOP/esnistuff/cadir/$hidden.priv
CERTFILE2=$CFGTOP/esnistuff/cadir/$hidden.crt
KEYFILE3=$CFGTOP/esnistuff/cadir/$HIDDEN2.priv
CERTFILE3=$CFGTOP/esnistuff/cadir/$HIDDEN2.crt

if [[ "$KEYGEN" == "yes" ]]
then
	echo "Generating kays and exiting..."
	./make-example-ca.sh
	exit
fi

keyfile1="-key $KEYFILE1 -cert $CERTFILE1"
keyfile2="-key2 $KEYFILE2 -cert2 $CERTFILE2"
#keyfile3="-key2 $KEYFILE3 -cert2 $CERTFILE3"

# figure out if we have tracing enabled within OpenSSL
# there's probably an easier way but s_server -help
# ought work
TRACING=""
tmpf=`mktemp`
$CODETOP/apps/openssl s_server -help >$tmpf 2>&1
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
    #dbgstr="-msg $TRACING -debug -security_debug_verbose -state -tlsextdebug -keylogfile srv.keys"
    dbgstr="-msg $TRACING -tlsextdebug "
fi

vgcmd=""
if [[ "$VG" == "yes" ]]
then
    vgcmd="valgrind --track-origins=yes --leak-check=full "
fi

if [[ "$SUPPLIEDPORT" != "" ]]
then
    PORT=$SUPPLIEDPORT
fi
portstr=" -port $PORT "

echdir=$ECHDIR
if [[ "$SUPPLIEDDIR" != "" ]]
then
	echdir=$SUPPLIEDDIR
fi

if [[ "$BADKEY" == "yes" ]]
then
    if [[ "$echdir" == "" ]]
    then
        echo "Can't feed bad key pair without setting echkeydir"
        exit 88
    else
        echo "Feeding bogus key pair to server for test"
        echo "boguscfg" >$echdir/badconfig.pem
    fi
fi

echstr=""
if [[ "$SUPPLIEDKEYFILE" != "" ]]
then
    ECHKEYFILE="$SUPPLIEDKEYFILE"
fi
if [ -f $ECHKEYFILE ]
then
    echo "Using key pair from $ECHKEYFILE"
    echstr="$echstr -echkey $ECHKEYFILE "
fi
if [ -d $echdir ]
then
    echo "Using all key pairs found in $echdir "
	echstr="$echstr -echdir $echdir"
fi

if [[ "$NOECH" == "yes" ]]
then
    echo "Not trying ECH"
    echstr=""
fi

hardfail=""
if [[ "$HARDFAIL" == "yes" ]]
then
    hardfail=" -echhardfail"
fi
trialdecrypt=""
if [[ "$TRIALDECRYPT" == "yes" ]]
then
    trialdecrypt=" -echtrialdecrypt"
fi

# tell it where CA stuff is...
certsdb=" -CApath $CAPATH"

# force tls13
#force13="-no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-tls1_3 -cipher TLS13-AES-128-GCM-SHA256 "
force13="-tls1_3 "

# catch the ctrl-C used to stop the server and do any clean up needed
cleanup() {
    echo "Cleaning up after ctrl-c"
    if [[ "$BADKEY" == "yes" ]]
    then
        rm -f $echdir/badkey.pub $echdir/badkey.priv
    fi
}
trap cleanup SIGINT

if [[ "$DEBUG" == "yes" ]]
then
    echo "Running: $vgcmd $CODETOP/apps/openssl s_server $dbgstr $keyfile1 $keyfile2 $certsdb $portstr $force13 $echstr $snicmd $hardfail $trialdecrypt $alpn_cmd $echpad_cmd $WEBSERVER"
fi
$vgcmd $CODETOP/apps/openssl s_server $dbgstr $keyfile1 $keyfile2 $certsdb $portstr $force13 $echstr $snicmd $hardfail $trialdecrypt $alpn_cmd $echpad_cmd $WEBSERVER


