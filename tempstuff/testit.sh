#!/bin/bash

#set -x

# to pick up correct .so's - maybe note 
TOP=$HOME/code/openssl
export LD_LIBRARY_PATH=$TOP

# this is one I downloaded manually via dig +short TXT _esni.encryptedsni.com
ESNI="/wHHBBOoACQAHQAg4YSfjSyJPNr1z3F8KqzBNBnMejim0mJZaPmria3XsicAAhMBAQQAAAAAW9pQEAAAAABb4jkQAAA="
COVER="cloudflare.net"
#COVER="cf.net"
#COVER="tls13.crypto.mozilla.org"
HIDDEN="encryptedsni.com"
#HIDDEN="2l.com"
VG="no"
FRESH="no"
NOESNI="no"
DEBUG="no"
SUPPLIEDSERVER=""

#default SNI to use
SERVERNAME=$COVER

URL="https://cloudflare.com/cdn-cgi/trace"

function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)
startdir=`/bin/pwd`

echo "Running $0 at $NOW"

function usage()
{
	echo "$0 [-dnfvh] - try out encrypted SNI via openssl s_client"
	echo "	-h means print this"
	echo "	-d means run s_client in verbose mode"
	echo "	-v means run with valgrind"
	echo "  -f means first get fresh ESNIKeys from DNS (via dig)"
	echo "  -n means don't trigger esni at all"
	echo "  -s [name] specifices a servername ('NONE' is special)"
	exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o s:dfvnh -l servername:,debug,fresh,valgrind,noesni,help -- "$@")
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

snicmd="-servername $SERVERNAME "
target=" -connect $COVER:443"
if [[ "$SUPPLIEDSERVER" != "" ]]
then
	if [[ "$SUPPLIEDSERVER" == "NONE" ]]
	then
		snicmd="-noservername "
	else
		snicmd="-servername $SUPPLIEDSERVER "
		target=" -connect $SUPPLIEDSERVER:443"
	fi
fi

# force tls13
#force13="-cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
force13="-tls1_3 -cipher TLS13-AES-128-GCM-SHA256 "

$vgcmd $TOP/apps/openssl s_client $dbgstr $target $esnistr $snicmd $force13
