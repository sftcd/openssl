#!/bin/bash

# set -x

# Split-mode nginx setup via streams (first step is just streams)

# base build dir
: ${OSSL:="$HOME/code/openssl"}
# nginx build dir
: ${NGINXH:=$HOME/code/nginx}
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
killall nginx

# make directories for DocRoot/logs as needed
mkdir -p $OSSL/esnistuff/nginx/fe/logs
mkdir -p $OSSL/esnistuff/nginx/fe/www

# in case we wanna dump core and get a backtrace, make a place for
# that (dir name is also in nginxmin-split.conf)
mkdir -p /tmp/cores

# check for/make a home page for example.com and other virtual hosts
if [ ! -f $OSSL/esnistuff/nginx/fe/www/index.html ]
then
    cat >$OSSL/esnistuff/nginx/fe/www/index.html <<EOF

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>nginx split-mode front-end top page.</title>
</head>
<!-- Background white, links blue (unvisited), navy (visited), red
(active) -->
<body bgcolor="#FFFFFF" text="#000000" link="#0000FF"
vlink="#000080" alink="#FF0000">
<p>This is the pretty dumb top page for testing nginx split-mode front-end.</p>

</body>
</html>

EOF
fi

# set to use valgrind, unset to not
# VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
# VALGRIND="valgrind --leak-check=full "
VALGRIND=""

vparm=""
# if you want echcli.sh tracing
# vparm=" -d "

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
            echo "Executing: $LIGHTY/src/lighttpd $FOREGROUND -f $OSSL/esnistuff/lighttpd4nginx-split.conf -m $LIGHTY/src/.libs"
            $LIGHTY/src/lighttpd $FOREGROUND -f $OSSL/esnistuff/lighttpd4nginx-split.conf -m $LIGHTY/src/.libs
        else
            echo "Lighttpd already running: $lrunning"
        fi
    fi
    if [[ "$SERVER" == "s_server" ]]
    then
        if [[ "$srunning" == "" ]]
        then
            # ditch or keep server tracing
            outf="/dev/null"
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

    echo "Executing: $VALGRIND $NGINXH/objs/nginx -c $OSSL/esnistuff/nginx-split.conf"
    # move over there to run code, so config file can have relative paths
    cd $OSSL/esnistuff
    $VALGRIND $NGINXH/objs/nginx -c $OSSL/esnistuff/nginx-split.conf
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
