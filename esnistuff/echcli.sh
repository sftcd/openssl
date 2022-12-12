#!/bin/bash

# Script to run basic tests using the openssl command line tool.
# Equivalent tests should migrate to being run as part of ``make test``

# set -x


# to pick up correct .so's - maybe note 
: ${CODETOP:=$HOME/code/openssl}
export LD_LIBRARY_PATH=$CODETOP
# to pick up the relevant configuration
: ${CFGTOP:=$HOME/code/openssl}
: ${GETOPTDIR:=/usr/bin}
# DNS recursive to use (don't ask:-)
: ${DNSRECURSIVE=""}

# variables/settings
# use Valgrind or not
VG="no"
# print loads or not
DEBUG="no"
# run without doing ECH at all
NOECH="no"
# whether or not to grease (only makes sense with NOECH==yes)
GREASE="no"
# the specific HPKE suite to use for grease, if so instructed
GSUITE="0x20,1,1"
GSUITESET="no"
# GTYPE="65034" # that's 0xfe0a - for draft-10
GTYPE="65037" # that's 0xfe0d - for draft-13


# Protocol parameters

# note that cloudflare do actually turn on h2 if we ask for that so
# you might see binary cruft if that's selected
DEFALPNVAL="-alpn inner,secret,http/1.1 -alpn-outer outer,public,h2"
DOALPN="yes"

# default port
PORT="443"
# port from commeand line
SUPPLIEDPORT=""
# HTTPPATH="index.html"
HTTPPATH=""

# the name or IP of the host to which we'll connect
SUPPLIEDSERVER=""
# the name that we'll put in inne CH - the ECH/SNI
SUPPLIEDHIDDEN=""

# PNO is the public_name_override that'll be sent as clear_sni
SUPPLIEDPNO=""

# ECH (or filename) from command line
SUPPLIEDECH=""

# CA info for server
SUPPLIEDCADIR=""

# stored session
SUPPLIEDSESSION=""
# re-using a session allows early data, so note that, if so
REUSINGSESSION="no"


# default values
HIDDEN="crypto.cloudflare.com"
DEFFRAG="/cdn-cgi/trace" # what CF like for giving a hint as to whether ECH worked
PNO=""
CAPATH="/etc/ssl/certs/"
CAFILE="./cadir/oe.csr"
REALCERT="no" # default to fake CA for localhost
CIPHERSUITES="" # default to internal default
SELECTED=""
IGNORE_CID="no"
EARLY_DATA="no"
IP_PROTSEL=""


function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

echo "Running $0 at $NOW"

function usage()
{
    echo "$0 [-cdfgGhHPpsrnlvL] - try out encrypted client hello (ECH) via openssl s_client"
	echo "  -4 use IPv4"
	echo "  -6 use IPv6"
	echo "  -c [name] specifices a name that I'll send as an outer SNI (NONE is special)"
    echo "  -C [number] selects the n-th ECHConfig from input RR/PEM file (0 based)"
    echo "  -d means run s_client in verbose mode"
    echo "  -e measns send HTTP request (in ./ed_file) as early_data"
    echo "  -f [pathname] specifies the file/pathname to request (default: '/')"
    echo "  -g means GREASE (only applied with -n)"
    echo "  -G means set GREASE suite to default rather than randomly pick"
    echo "  -h means print this"
    echo "  -H means try connect to that hidden server"
    echo "  -I means to ignore the server's chosen config_id and send random"
    echo "  -j just use 0x1301 ciphersuite"
    echo "  -n means don't trigger ech at all"
    echo "  -N means don't send specific inner/outer alpns"
    echo "  -p [port] specifices a port (default: 443)"
	echo "  -P [filename] means read ECHConfigs public value from file and not DNS"
    echo "  -r (or --realcert) says to not use locally generated fake CA regardless"
	echo "  -s [name] specifices a server to which I'll connect (localhost=>local certs, unless --realcert)"
	echo "  -S [file] means save or resume session from <file>"
    echo "  -t [type] means to set the TLS extension type for GREASE to <type>"
    echo "  -v means run with valgrind"

	echo ""
	echo "The following should work:"
	echo "    $0 -H defo.ie"
    exit 99
}

# check we have what looks like a good getopt (the native version on macOS 
# seems to not be good)
if [ ! -f $GETOPTDIR/getopt ]
then
    echo "No sign of $GETOPTDIR/getopt - exiting"
    exit 32
fi
getoptcnt=`$GETOPTDIR/getopt --version | grep -c "util-linux"`
if [[ "$getoptcnt" != "1" ]]
then
    echo "$GETOPTDIR/getopt doesn't seem to be gnu-getopt - exiting"
    exit 32
fi

# options may be followed by one colon to indicate they have a required argument
if ! options=$($GETOPTDIR/getopt -s bash -o 46C:c:def:gGhH:IjnNp:P:rs:S:t:v -l four,six,choose:,clear_sni:,debug,early,filepath:,grease,greasesuite,help,hidden:,ignore_cid,just,noech,noalpn,port:,echpub:,realcert,server:,session:,gtype:,valgrind -- "$@")
then
    # something went wrong, getopt will put out an error message for us
    exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
    case "$1" in
        -4|--four) IP_PROTSEL=" -4 ";;
        -6|--six) IP_PROTSEL=" -6 ";;
        -c|--clear_sni) SUPPLIEDPNO=$2; shift;;
        -C|--choose) SELECTED=$2; shift;;
        -d|--debug) DEBUG="yes" ;;
        -e|--early) EARLY_DATA="yes" ;;
        -f|--filepath) HTTPPATH=$2; shift;;
		-g|--grease) GREASE="yes";;
		-G|--greasesuite) GSUITESET="yes";;
        -h|--help) usage;;
        -H|--hidden) SUPPLIEDHIDDEN=$2; shift;;
        -I|--ignore_cid) IGNORE_CID="yes" ;;
        -j|--just) CIPHERSUITES=" -ciphersuites TLS_AES_128_GCM_SHA256 " ;;
        -n|--noech) NOECH="yes" ;;
        -N|--noalpn) DOALPN="no" ;;
        -p|--port) SUPPLIEDPORT=$2; shift;;
		-P|--echpub) SUPPLIEDECH=$2; shift;;
        -r|--realcert) REALCERT="yes" ;;
        -s|--server) SUPPLIEDSERVER=$2; shift;;
        -S|--session) SUPPLIEDSESSION=$2; shift;;
        -t|--gtype) GTYPE=$2; shift;;
        -v|--valgrind) VG="yes" ;;
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

# figure out if we have tracing enabled within OpenSSL
# there's probably an easier way but s_client -help
# ought work
TRACING=""
tmpf=`mktemp`
$CODETOP/apps/openssl s_client -help >$tmpf 2>&1
tcount=`grep -c 'trace output of protocol messages' $tmpf`
if [[ "$tcount" == "1" ]]
then
    TRACING="-trace "
fi
rm -f $tmpf

# check we have dig
if [[ "``which dig``" == "" ]]
then
    echo "Can't find the dig command - exiting"
    exit 12
fi

#dbgstr=" -verify_quiet"
dbgstr=" "
#dbgstr=" "
if [[ "$DEBUG" == "yes" ]]
then
    #dbgstr="-msg -debug $TRACING -security_debug_verbose -state -tlsextdebug -keylogfile cli.keys"
    dbgstr="-msg -debug $TRACING"
    #dbgstr="-msg -debug $TRACING -tlsextdebug -keylogfile keys.cli"
fi

vgcmd=""
if [[ "$VG" == "yes" ]]
then
    #vgcmd="valgrind --leak-check=full "
    vgcmd="valgrind --leak-check=full --error-limit=no --track-origins=yes "
fi

if [[ "$SUPPLIEDPORT" != "" ]]
then
    PORT=$SUPPLIEDPORT
fi

snioutercmd=" "
if [[ "$SUPPLIEDPNO" != "" && "$NOECH" != "yes" ]] 
then
    snioutercmd="-sni-outer $SUPPLIEDPNO"
fi

# Set address of target 
if [[ "$SUPPLIEDPNO" != "" && "$hidden" == "" ]]
then
    target=" -connect $SUPPLIEDPNO:$PORT "
else
    # I guess we better connect to hidden 
    # Note that this could leak via DNS again
    target=" -connect $hidden:$PORT "
fi
server=$hidden
if [[ "$SUPPLIEDSERVER" != "" ]]
then
	target=" -connect $SUPPLIEDSERVER:$PORT"
	server=$SUPPLIEDSERVER
fi

selstr=""
if [[ "$SELECTED" != "" ]]
then
    selstr=" -select $SELECTED "
fi

# set ciphersuites
ciphers=$CIPHERSUITES

if [[ "$NOECH" == "no" && "$GREASE" == "no" ]]
then
	if [[ "$SUPPLIEDECH" != "" ]]
	then
		if [ ! -f $SUPPLIEDECH ]
		then
            # if that value appears to be good ascii hex encoded, we'll assume it's an
            # HTTPS RR value 
            # we'll lowercase the string, then AH-decode and re-encode
            # and if result is the same then we think it's ascii-hex
            lse=`echo $SUPPLIEDECH | tr '[:upper:]' '[:lower:]'`
            dcheck=`echo $lse | xxd -r -p | xxd -p | tr -d '\n'`
            if [[ "$dcheck" == "$lse" ]]
            then
                ahres=0
            else
                ahres=1
            fi
            # if it's base64 we'll guess it's a b64'd ECHConfigList
            echo $SUPPLIEDECH | base64 -d >/dev/null 2>&1
            bres=$?
            # note: the same string can pass both tests in which case
            # we go for the HTTPS RR option
            if [[ "$ahres" == "0" ]]
            then
                echo "Assuming supplied ECH is RR value"
                ECH=" $selstr -svcb $SUPPLIEDECH "
            elif [[ "$bres" == "0" ]]
            then
                echo "Assuming supplied ECH is base64 encoded ECHConfigList"
                ECH=" $selstr -echconfigs $SUPPLIEDECH "
            else
                echo "Supplied ECH is neither ascii-hex nor base64 - exiting "
                exit 44
            fi
        else
		    # check if file suffix is .pem (base64 encoding) 
		    # and react accordingly, don't take any other file extensions
		    ssfname=`basename $SUPPLIEDECH`
		    if [ `basename "$ssfname" .pem` != "$ssfname" ]
		    then
			    ECH=" $selstr -echconfigs `tail -2 $SUPPLIEDECH | head -1`" 
		    else
			    echo "Not sure of file type of $SUPPLIEDECH - try make a PEM file to help me"
			    exit 8
		    fi
		fi
	else
        # try draft-13 only for now, i.e. HTTPS
        # kill the spaces and joing the lines if multi-valued seen 
        qname=$hidden
        if [[ "$PORT" != "" && "$PORT" != "443" ]]
        then
            qname="_$PORT._https.$hidden"
        fi
        recursivestr=""
        if [[ "$DNSRECURSIVE" != "" ]]
        then
            echo "Using DNS recursive: $DNSRECURSIVE"
            recursivestr=" @$DNSRECURSIVE "
        fi
        digval="`dig +unknownformat +short $recursivestr -t TYPE65 $qname | tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' `"
        # digval used have one more sed command as per below...
        # digval="`dig +short -t TYPE65 $qname | tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`"
        # I think that's a hangover from some other script that had to merge lines, e.g. if the RR value is 
        # very very big - but since we're doing a tail -1 here (ignoring all but one RR value) that shouldn't
        # be needed (and it caused a problem for someone who didn't have GNU sed)

        if [[ "$digval" == "" ]]
        then
            echo "Didn't get any HTTPS RR value for $qname - exiting"
            exit 22
        fi
        ECH=" $selstr -svcb $digval "
	fi
fi

if [[ "$NOECH" == "no" && "$GREASE" == "no" && "$ECH" == "" ]]
then
    echo "Not trying - no sign of ECHKeys ECH "
    exit 100
fi

grease_str=" -ech_grease -ech_grease_type=$GTYPE"
if [[ "$GSUITESET" == "yes" ]]
then
    grease_str=" -ech_grease -ech_grease_suite=$GSUITE -ech_grease_type=$GTYPE"
fi

ignore_str=" "
if [[ "$IGNORE_CID" == "yes" ]]
then
    ignore_str=" -ech_ignore_cid "
fi

# normally the inner SNI is what we want to hide
echstr="-servername $hidden $ECH $ignore_str "
if [[ "$NOECH" == "yes" ]]
then
    echo "Not trying ECH"
    if [[ "$SUPPLIEDPNO" != "" ]]
    then
        echstr="-servername $SUPPLIEDPNO $ignore_str "
    elif [[ "$SUPPLIEDPNO" == "" && "$hidden" != "" ]]
    then
        echstr="-servername $hidden $ignore_str "
    elif [[ "$hidden" == "" || "$SUPPLIEDPNO" == "NONE" ]]
    then
        echstr=" -noservername $ignore_str"
    fi
    if [[ "$GREASE" == "yes" ]]
    then
        echo "Trying to GREASE though"
        echstr=" $echstr $grease_str $ignore_str "
    fi
else
    if [[ "$GREASE" == "yes" && "$hidden" == "NONE" ]]
    then
        echo "Trying to GREASE"
        echstr=" -noservername $grease_str $ignore_str "
    elif [[ "$GREASE" == "yes" && "$hidden" != "NONE" ]]
    then
        echstr=" -servername $hidden $grease_str $ignore_str "
    elif [[ "$GREASE" == "no" && "$hidden" != "NONE" ]]
    then
        echstr=" -servername $hidden $ECH $ignore_str "
    elif [[ "$GREASE" == "no" && "$hidden" == "NONE" ]]
    then
        echstr=" -noservername $ECH $ignore_str "
    fi
fi

if [[ "$DOECH" == "yes" && "$SUPPLIEDHIDDEN" == "" && "$HTTPPATH" == "" ]]
then
    # we're at CF, set things to work nicely
    HTTPPATH=$DEFFRAG
    DOALPN="no"
fi

#httpreq="GET $HTTPPATH\\r\\n\\r\\n"
httphost=$hidden
if [[ "$NOECH" == "yes" ]]
then
    if [[ "$SUPPLIEDPNO" != "" ]]
    then
        httphost=$SUPPLIEDPNO
    elif [[ "$SUPPLIEDSERVER" != "" ]]
    then
        httphost=$SUPPLIEDSERVER
    else
        httphost="localhost"
    fi
fi
httpreq="GET /$HTTPPATH HTTP/1.1\\r\\nConnection: close\\r\\nHost: $httphost\\r\\n\\r\\n"

# tell it where CA stuff is...
if [[ "$server" != "localhost" ]]
then
	certsdb=" -CApath $CAPATH"
else
    if [[ "$REALCERT" == "no" && -f $CAFILE ]]
    then
	    certsdb=" -CAfile $CAFILE"
    else
	    certsdb=" -CApath $CAPATH"
    fi
fi

# force tls13
force13="-no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-tls1_3 -cipher TLS13-AES-128-GCM-SHA256 "

# session resumption
session=""
if [[ "$SUPPLIEDSESSION" != "" ]]
then
	if [ ! -f $SUPPLIEDSESSION ]
	then
		# save so we can resume
		session=" -sess_out $SUPPLIEDSESSION"
	else
		# resuming 
		session=" -sess_in $SUPPLIEDSESSION"
        REUSINGSESSION="yes"
	fi
fi

alpn=""
if [[ "$GREASE" == "no" && "$DOALPN" == "yes" && "$NOECH" == "no" ]]
then
    alpn=$DEFALPNVAL
fi

earlystr=""
if [[ "$EARLY_DATA" == "yes" ]]
then
    if [[ "$REUSINGSESSION" != "yes" ]]
    then
        echo "Can't send early data unless re-using a session"
        exit 87
    fi
    if [ ! -f ed_file ]
    then
        echo -e "$httpreq\n" >ed_file
    fi
    earlystr=" --early_data ed_file "
fi

TMPF=`mktemp /tmp/echtestXXXX`

if [[ "$DEBUG" == "yes" ]]
then
    echo "Running: $CODETOP/apps/openssl s_client $IP_PROTSEL $dbgstr $certsdb $force13 $target $echstr $snioutercmd $session $alpn $ciphers $earlystr"
fi
# seconds to sleep after firing up client so that tickets might arrive
sleepaftr=2

if [[ "$DEBUG" == "yes" ]]
then
    # bit slower so sleep a bit more
    sleepaftr=3
fi
if [[ "$VG" == "yes" ]]
then
    # bit slower so sleep a bit more
    sleepaftr=6
fi

if [[ "$EARLY_DATA" == "yes" ]]
then
    httpreq1=${httpreq/foo.example.com/barbar.example.com}
    ( echo -e "$httpreq1" ; sleep $sleepaftr) | $vgcmd $CODETOP/apps/openssl s_client $IP_PROTSEL $dbgstr $certsdb $force13 $target $echstr $snioutercmd $session $alpn $ciphers $earlystr >$TMPF 2>&1
else
    ( echo -e "$httpreq" ; sleep $sleepaftr) | $vgcmd $CODETOP/apps/openssl s_client $IP_PROTSEL $dbgstr $certsdb $force13 $target $echstr $snioutercmd $session $alpn $ciphers >$TMPF 2>&1
fi

c200=`grep -c "200 OK" $TMPF`
csucc=`grep -c "ECH: success" $TMPF`
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

goodresult=`grep -c "ECH: success" $TMPF`
echo "$0 Summary: "
allresult=`grep "ECH: " $TMPF`
sslerror=`grep ":error:" $TMPF`
rm -f $TMPF
if (( $goodresult > 0 ))
then
    echo "Looks like ECH worked ok"
    res=0
else
    if [[ "$NOECH" != "yes" && "$GREASE" != "yes" ]]
    then
        echo "Bummer - probably didn't work"
        res=1
    elif [[ "$NOECH" == "yes" ]]
    then
        echo "Didn't try ECH"
        res=0
    elif [[ "$GREASE" == "yes" ]]
    then
        echo "Only greased"
        res=0
    fi
fi
if [[ "$sslerror" != "" ]]
then
    echo "Got an SSL error though:"
    echo "$sslerror"
    res=1
fi
echo $allresult
exit $res
# exit with something useful
# not sure if this still useful, check sometime...
if [[ "$csucc" == "1" && "$c4xx" == "0" ]]
then
    exit 0
else
    exit 44
fi 
exit 66
