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

if [[ "$1" == "client" ]]
then
    CLIENT="yes"
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

if [[ "$SERVERS" == "yes" ]]
then

    # Check if a lighttpd BE is running
    lrunning=`ps -ef | grep lighttpd | grep -v grep | grep -v tail`
    if [[ "$lrunning" == "" ]]
    then
        echo "Executing: $VALGRIND $LIGHTY/src/lighttpd $FOREGROUND -f $OSSL/esnistuff/lighttpd4nginx-split.conf -m $LIGHTY/src/.libs"
        $LIGHTY/src/lighttpd $FOREGROUND -f $OSSL/esnistuff/lighttpd4nginx-split.conf -m $LIGHTY/src/.libs
    else
        echo "Lighttpd already running: $lrunning"
    fi
    
    echo "Executing: $VALGRIND $NGINXH/objs/nginx -c $OSSL/esnistuff/nginx-split.conf"
    # move over there to run code, so config file can have relative paths
    cd $OSSL/esnistuff
    $VALGRIND $NGINXH/objs/nginx -c $OSSL/esnistuff/nginx-split.conf
    cd -
fi

if [[ "$CLIENT" == "yes" ]]
then
    echo "Running: $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem"
    $OSSL/esnistuff/echcli.sh -H foo.example.com -s localhost -p 9443 -P d13.pem
fi
