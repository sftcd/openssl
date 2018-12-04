#!/bin/bash

#set -x

# to pick up correct .so's - maybe note 
TOP=$HOME/code/openssl
export LD_LIBRARY_PATH=$TOP

ESNIPUB=$TOP/esnistuff/esnikeys.pub
ESNIPRIV=$TOP/esnistuff/esnikeys.priv
HIDDEN="foo.example.com"
COVER="example.com"

SSLCFG="/etc/ssl/openssl.cnf"

# variables/settings
VG="no"
NOESNI="no"
DEBUG="no"
KEYGEN="no"
PORT="443"
SUPPLIEDPORT=""

SUPPLIEDKEYFILE=""
SUPPLIEDHIDDEN=""
SUPPLIEDCOVER=""
CAPATH="/etc/ssl/certs/"

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

echo "Running $0 at $NOW"

function usage()
{
    echo "$0 [-cHpsdnlvhK] - try out encrypted SNI via openssl s_server"
    echo "  -H means serve that hidden server"
    echo "  -d means run s_server in verbose mode"
    echo "  -v means run with valgrind"
    echo "  -n means don't trigger esni at all"
	echo "  -c [name] specifices a covername that I'll accept as a clear SNI (NONE is special)"
    echo "  -p [port] specifices a port (default: 443)"
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
if ! options=$(/usr/bin/getopt -s bash -o c:H:p:Kdlvnh -l cover:,hidden:,port:,keygen,debug,stale,valgrind,noesni,help -- "$@")
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

KEYFILE1=$TOP/esnistuff/$cover.pem
CERTFILE1=$TOP/esnistuff/$cover.crt
KEYFILE2=$TOP/esnistuff/$hidden.pem
CERTFILE2=$TOP/esnistuff/$hidden.crt

if [[ "$KEYGEN" == "yes" ]]
then
	echo "Generating kays and exiting..."
	$TOP/apps/openssl req -x509 -config $SSLCFG -newkey rsa:2048 -keyout $KEYFILE1 -out $CERTFILE1 -days 365 -nodes -subj "/C=IE/CN=$cover"
	$TOP/apps/openssl req -x509 -config $SSLCFG -newkey rsa:2048 -keyout $KEYFILE2 -out $CERTFILE2 -days 365 -nodes -subj "/C=IE/CN=$hidden"
	exit
fi

keyfile1="-key $KEYFILE1 -cert $CERTFILE1"
keyfile2="-key2 $KEYFILE2 -cert2 $CERTFILE2"

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

esnistr="-esni $hidden -esnipub $ESNIPUN -esnipriv $ESNIPRIV "
if [[ "$NOESNI" == "yes" ]]
then
    echo "Not trying ESNI"
    esnistr=""
fi

# tell it where CA stuff is...
certsdb=" -CApath $CAPATH"

# force tls13
force13="-cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-tls1_3 -cipher TLS13-AES-128-GCM-SHA256 "

set -x
#TMPF=`mktemp /tmp/esnitestXXXX`
#$vgcmd $TOP/apps/openssl s_server $dbgstr $keyfile1 $keyfile2 $certsdb $portstr $force13 $esnistr $snicmd >$TMPF 2>&1
$vgcmd $TOP/apps/openssl s_server $dbgstr $keyfile1 $keyfile2 $certsdb $portstr $force13 $esnistr $snicmd 
exit

c200=`grep -c "200 OK" $TMPF`
c4xx=`grep -ce "^HTTP/1.1 4[0-9][0-9] " $TMPF`

if [[ "$DEBUG" == "yes" ]]
then
	echo "$0 All output" 
	cat $TMPF
	echo ""
fi
if [[ "$VG" == "yes" ]]
then
	vgout=`grep -e "^==" $TMPF`
	echo "$0 Valgrind" 
	echo "$vgout"
	echo ""
fi
echo "$0 Summary: "
if [[ "$DEBUG" == "yes" ]]
then
	noncestr=`grep -A1 "ESNI Nonce" $TMPF`
	eestr=`grep -A2 EncryptedExtensions $TMPF`
	echo "Nonce sent: $noncestr"
	echo "Nonce Back: $eestr"
	grep -e "^ESNI: " $TMPF
else
	echo "Looks like $c200 ok's and $c4xx bad's."
fi
echo ""
rm -f $TMPF

