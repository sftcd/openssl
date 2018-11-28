#!/bin/bash

#set -x

# to pick up correct .so's - maybe note 
TOP=$HOME/code/openssl
export LD_LIBRARY_PATH=$TOP

# An old value...
#ESNI="/wHHBBOoACQAHQAg4YSfjSyJPNr1z3F8KqzBNBnMejim0mJZaPmria3XsicAAhMBAQQAAAAAW9pQEAAAAABb4jkQAAA="


# variables/settings
VG="no"
STALE="no"
NOESNI="no"
DEBUG="no"
PORT="443"
SUPPLIEDPORT=""
HTTPPATH="/cdn-cgi/trace"

# Explaining this to myself... :-)
#
# You can indpendendtly set the 
# hidden - the name used in the ESNI
#      that defaults to encryptedsni.com
# cover - the name used in (clear) SNI
# server - we'll connect to that IP or the A/AAAA for that name
# if server isn't set, it defaults to cover
# if cover isn't set it defaults to www.cloudflare.com
# if cover is "NONE" we send no (clear) SNI at all and 
#      server falls back to wwww.cloudflare.com

# DNS lookups
# _esni.$hidden is checked first, if nothing there then
# we check _esni.$cover and finally _esni.$server

# Using an IP address instead of a name may work sometimes but
# not always


SUPPLIEDSERVER=""
SUPPLIEDHIDDEN=""
SUPPLIEDCOVER=""
HIDDEN="encryptedsni.com"
COVER="www.cloudflare.com"

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

echo "Running $0 at $NOW"

function usage()
{
    echo "$0 [-cHpsdnfvh] - try out encrypted SNI via openssl s_client"
    echo "  -H means try connect to that hidden server"
    echo "  -d means run s_client in verbose mode"
    echo "  -v means run with valgrind"
    echo "  -l means use stale ESNIKeys"
    echo "  -n means don't trigger esni at all"
    echo "  -s [name] specifices a server to which I'll connect"
	echo "  -c [name] specifices a covername that I'll send as a clear SNI (NONE is special)"
    echo "  -p [port] specifices a port (default: 442)"
    echo "  -h means print this"

	echo ""
	echo "The following should work:"
	echo "    $0 -c www.cloudflare.com -s NONE -H www.ietf.org"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o c:H:p:s:dfvnh -l cover:,hidden:,port:,server:,debug,stale,valgrind,noesni,help -- "$@")
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
        -l|--stale) STALE="yes" ;;
        -v|--valgrind) VG="yes" ;;
        -n|--noesni) NOESNI="yes" ;;
        -c|--cover) SUPPLIEDCOVER=$2; shift;;
        -s|--server) SUPPLIEDSERVER=$2; shift;;
        -H|--hidden) SUPPLIEDHIDDEN=$2; shift;;
        -p|--port) SUPPLIEDPORT=$2; shift;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done

if [[ "$STALE" == "yes" ]]
then
	ESNI="/wHHBBOoACQAHQAg4YSfjSyJPNr1z3F8KqzBNBnMejim0mJZaPmria3XsicAAhMBAQQAAAAAW9pQEAAAAABb4jkQAAA="
    echo "Using stale ESNI value: $ESNI" 
fi    

hidden=$HIDDEN
if [[ "$SUPPLIEDHIDDEN" != "" ]]
then
	hidden=$SUPPLIEDHIDDEN
fi

dbgstr=" -verify_quiet"
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

# Set SNI
cover=$COVER
snicmd="-servername $cover"
if [[ "$SUPPLIEDCOVER" != "" ]]
then
    if [[ "$SUPPLIEDCOVER" == "NONE" ]]
    then
        snicmd="-noservername "
    else
        snicmd=" -servername $SUPPLIEDCOVER "
    fi
fi

# Set address of target 
target=" -connect $COVER:$PORT "
if [[ "$SUPPLIEDSERVER" != "" ]]
then
	target=" -connect:$SUPPLIEDSERVER:$PORT"
fi

# Seems like the ESNI value is rotated often
# 
# Sometimes this fails on me, not sure if that's stubby (which I use locally),
# or generic DNS weirdness or IPv6 or some other CF issue but ignoring for now
# and maybe check later
if [[ "$NOESNI" != "yes" ]]
then
	ESNI=`dig +short txt _esni.$hidden | sed -e 's/"//g'`
	if [[ "$ESNI" == "" ]]
	then
		ESNI=`dig +short txt _esni.$cover | sed -e 's/"//g'`
		if [[ "$ESNI" == "" ]]
		then
			ESNI=`dig +short txt _esni.$server | sed -e 's/"//g'`
			if [[ "$ESNI" == "" ]]
			then
				echo "Not trying - no sign of ESNIKeys TXT RR at _esni.$hidden nor _esni.$cover nor _esni.$server"
				exit 100
			fi
		fi
	fi
fi

esnistr="-esni $hidden -esnirr $ESNI "
if [[ "$NOESNI" == "yes" ]]
then
    echo "Not trying ESNI"
    esnistr=""
fi

httpreq="GET $HTTPPATH\\r\\n\\r\\n"

# force tls13
force13="-cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-tls1_3 -cipher TLS13-AES-128-GCM-SHA256 "

set -x
echo "$httpreq" | $vgcmd $TOP/apps/openssl s_client $dbgstr $force13 $target $esnistr $snicmd

