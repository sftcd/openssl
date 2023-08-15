#!/bin/bash

# Script to run smokeping like tests against CF, defo.ie and my-own.net
# using echcli.sh

# set -x

# structure is host:port mapped to pathname
declare -A targets=(
    [my-own.net]="ech-check.php"
    [my-own.net:8443]="ech-check.php"
    [defo.ie]="ech-check.php"
    [draft-13.esni.defo.ie:8413]="stats"
    [draft-13.esni.defo.ie:8414]="stats"
    [draft-13.esni.defo.ie:9413]=""
    [draft-13.esni.defo.ie:10413]=""
    [draft-13.esni.defo.ie:11413]=""
    [draft-13.esni.defo.ie:12413]=""
    [draft-13.esni.defo.ie:12414]=""
    [crypto.cloudflare.com]="cdn-cgi/trace"
)

# place to stash outputs when things go wrong
: ${bad_dir:="$HOME/logs/smoke_ech_baddies"}

# time to wait for a remote access to work, 10 seconds
: ${tout:="10s"}

: ${OSSL:="$HOME/code/openssl"}

: ${DOMAIL:="no"}

DEFPORT=443

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}

function fileage()
{
    echo $(($(date +%s) - $(date +%s -r "$1")))
}

function hostport2host()
{
    case $1 in
      *:*) host=${1%:*} port=${1##*:};;
        *) host=$1      port=$DEFPORT;;
    esac
    echo $host
}

function hostport2port()
{
    case $1 in
      *:*) host=${1%:*} port=${1##*:};;
        *) host=$1      port=$DEFPORT;;
    esac
    echo $port
}

TMPD=`mktemp -d`
allgood="yes"
digcmd="dig https"

NOW=$(whenisitagain)

cd $TMPD

logfile=$TMPD/$NOW.log

echo "-----" >>$logfile
echo "Running $0 at $NOW"  >>$logfile
echo "Running $0 at $NOW"

# check we have binaries
if [ ! -d $OSSL ] 
then
    allgood="no"
    echo "Can't see $OSSL - exiting" >>$logfile
fi
echcli=$OSSL/esnistuff/echcli.sh
if [ ! -f $echcli ]
then
    allgood="no"
    echo "Can't see $OSSL/esnistuff/echcli.sh - exiting" >>$logfile
fi
if [ ! -f $OSSL/apps/openssl ]
then
    allgood="no"
    echo "Can't see $OSSL/apps/openssl - exiting" >>$logfile
fi

# check if dig knows https or not
digcmd="dig https"
dout=`dig +short https defo.ie`
if [[ $dout != "1 . ech="* ]]
then
    digcmd="dig -t TYPE65"
fi

if [[ "$allgood" == "yes" ]]
then
    for targ in "${!targets[@]}"
    do
        host=$(hostport2host $targ)
        port=$(hostport2port $targ)
        path=${targets[$targ]}
        pathstr=""
        if [[ "$path" != "" ]]
        then
            pathstr="-f $path"
        fi
        wkurl="https://$host:$port/.well-known/origin-svcb"
        qname=$host
        if [[ "$port" != "$DEF_PORT" ]]
        then
            qname="_$port._https.$host"
        fi
        echo "Checking $host:$port/$path and $wkurl" >>$logfile
        # get wkurl
        if [[ "$host" != "crypto.cloudflare.com" ]]
        then
            timeout $tout curl -o $host.$port.json -s $wkurl
            cres=$?
            if [[ "$cres" == "124" ]] 
            then
                allgood="no"
                echo "Timeout getting $wkurl" >>$logfile
            fi
        else
            echo "{ \"No .well-known for $host \"}" >$host.$port.json
        fi
        # grab DNS
        $digcmd $qname >$host.$port.dig 2>&1
        # try ECH 
        timeout $tout $echcli -H $host -p $port $pathstr -d >$host.$port.echcli.log
        eres=$?
        if [[ "$eres" == "124" ]] 
        then
            allgood="no"
            echo "Timeout running echcli.sh for $host:$port/$path" >>$logfile
        fi
        if [[ "$eres" != "0" ]] 
        then
            allgood="no"
            echo "Errot ($eres) from echcli.sh for $host:$port/$path" >>$logfile
        fi
    done
fi

END=$(whenisitagain)
echo "Finished $0 at $END"  >>$logfile
echo "-----" >>$logfile
cd -

if [[ "$allgood" == "yes" ]]
then
    rm -rf $TMPD
    echo "Finished $0 at $END"
    echo "All good"
    exit 0
fi

# stash bad stuff
if [ ! -d $bad_dir ]
then
    mkdir -p $bad_dir
    if [ ! -d $bad_dir ]
    then
        echo "Can't create $bad_dir - exiting"
        exit 1
    fi
fi
# stash badness
mv $TMPD $bad_dir/$NOW
# send a mail to root (will be fwd'd)
if [[ "$DOMAIL" == "yes" ]]
then
    echo "ECH baddness at $NOW" | mail -s "ECH badness at $NOW" root
fi
exit 2
