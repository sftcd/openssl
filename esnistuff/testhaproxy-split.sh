#!/bin/bash

# set -x

# Split-mode (only) haproxy setup for testing ECH

# base build dir
: ${OSSL:="$HOME/code/openssl"}
# haproxy build dir
: ${HAPPY:=$HOME/code/haproxy}
# backend web server - lighttpd for now - can be any ECH-aware server
: ${LIGHTY:="$HOME/code/lighttpd1.4"}

SERVERS="yes"
CLIENT="no"
EARLY="no"
HRR="no"

SERVER="lighty"

if [[ "$1" == "client" ]]
then
    CLIENT="yes"
fi
if [[ "$1" == "ossl" ]]
then
    SERVER="s_server"
fi
if [[ "$1" == "early" ]]
then
    EARLY="yes"
    SERVER="s_server"
fi
if [[ "$1" == "hrr" ]]
then
    HRR="yes"
fi

export TOP=$OSSL
export LD_LIBRARY_PATH=$OSSL

# nginx build statically links openssl for now 

# Kill off old processes from the last test
killall haproxy

# set to use valgrind, unset to not
# VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
# VALGRIND="valgrind --leak-check=full "
VALGRIND=""

vparm=""
# if you want echcli.sh tracing
vparm=" -d "

if [[ "$SERVERS" == "yes" ]]
then

    # We want lighttpd for backend if not doing early data but s_server
    # if we do want early data. And make sure just one is left running
    # as we want to use the same port (9444).

    # Check if a lighttpd BE is running
    lrunning=`ps -ef | grep lighttpd | grep -v grep | grep -v tail | awk '{print $2}'`
    srunning=`ps -ef | grep s_server | grep -v grep | grep -v tail | awk '{print $2}'`
    # Kill if needed
    if [[ "$SERVER" == "s_server" && "$lrunning" != "" ]]
    then
        kill $lrunning
    fi
    if [[ "$SERVER" == "lighty" && "$srunning" != "" ]]
    then
        kill $srunning
    fi
    if [[ "$SERVER" == "lighty" ]]
    then
       if  [[  "$lrunning" == "" ]]
        then
            echo "Executing: $LIGHTY/src/lighttpd -f $OSSL/esnistuff/lighttpd4haproxy-split.conf -m $LIGHTY/src/.libs"
            $LIGHTY/src/lighttpd -f $OSSL/esnistuff/lighttpd4haproxy-split.conf -m $LIGHTY/src/.libs
        else
            echo "Lighttpd already running: $lrunning"
        fi
    fi
    if [[ "$SERVER" == "s_server" ]]
    then
        if [[ "$srunning" == "" ]]
        then
            # ditch or keep server tracing
            # outf="/dev/null"
            outf="s_server.log"
            # outf=`mktemp`
            if [[ "$HRR" == "yes" ]]
            then
                # you may need to manually kill s_server if switching between
                # HRR and non-HRR tests
                echo "Executing: $OSSL/esnistuff/echsvr.sh -e -k d13.pem -p 9444 $vparm >$outf 2>&1 &"
                $OSSL/esnistuff/echsvr.sh -e -k d13.pem -p 9444 $vparm -R >$outf 2>&1 &
            else
                echo "Executing: $OSSL/esnistuff/echsvr.sh -e -k d13.pem -p 9444 $vparm >$outf 2>&1 &"
                $OSSL/esnistuff/echsvr.sh -e -k d13.pem -p 9444 $vparm >$outf 2>&1 &
            fi
        else
            echo "s_server already running: $srunning"
        fi
    fi

    echo "Executing: $VALGRIND $HAPPY/haproxy -f $OSSL/esnistuff/haproxy-split.conf -DdV"
    # move over there to run code, so config file can have relative paths
    cd $OSSL/esnistuff
    $VALGRIND $HAPPY/haproxy -f $OSSL/esnistuff/haproxy-split.conf -DdV
    cd -
fi

if [[ "$CLIENT" == "yes" ]]
then
    echo "Running: $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem $vparm -f index.html"
    $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem $vparm -f index.html
fi

if [[ "$EARLY" == "yes" ]]
then
    tmpf=`mktemp`
    rm -f $tmpf
    echo "Running: $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem $vparm -f index.html -S $tmpf"
    $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem $vparm -f index.html -S $tmpf
    if [ ! -f $tmpf ]
    then
        echo "No session so no early data - exiting"
        exit 1
    fi
    echo "Running: $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem $vparm -f index.html -S $tmpf -e"
    $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem $vparm -f index.html -S $tmpf -e
    rm -f $tmpf
fi

if [[ "$HRR" == "yes" ]]
then
    # back-end lighttpd server has P384 turned off so client using that will trigger HRR
    echo "Running: $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem $vparm -f index.html -R"
    $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem $vparm -f index.html -R
fi
