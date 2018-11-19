#!/bin/bash

#set -x

# to pick up correct .so's - maybe note 
TOP=$HOME/code/openssl
export LD_LIBRARY_PATH=$TOP

# this is one I downloaded manually via dig +short TXT _esni.encryptedsni.com
ESNI="/wHHBBOoACQAHQAg4YSfjSyJPNr1z3F8KqzBNBnMejim0mJZaPmria3XsicAAhMBAQQAAAAAW9pQEAAAAABb4jkQAAA="
COVER="cloudflare.net"
HIDDEN="encryptedsni.com"
VG="no"
FRESH="no"
NOHOST="no"


function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)
startdir=`/bin/pwd`

echo "Running $0 at $NOW"

function usage()
{
	echo "$0 [-nfvh] - try out encrypted SNI via openssl s_client"
	echo "	-h means print this"
	echo "	-v means run with valgrind"
	echo "  -f means first get fresh ESNIKeys from DNS (via dig)"
	echo "  -n means don't provide a HOST:PORT so we bail before sending anything"
	exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o fvnh -l fresh,valgrind,noconn,help -- "$@")
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
		-f|--fresh) FRESH="yes" ;;
		-v|--valgrind) VG="yes" ;;
		-n|--noconn) NOHOST="yes" ;;
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

target=" -connect $COVER:443"
if [[ "$NOHOST" == "yes" ]]
then
	echo "Not connecting"
	target=""
fi

vgcmd=""
if [[ "$VG" == "yes" ]]
then
	vgcmd="valgrind --leak-check=full "
fi
$vgcmd $TOP/apps/openssl s_client $target -esni $HIDDEN -esnirr $ESNI -servername $COVER
