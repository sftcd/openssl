#!/bin/bash

# set -x

# Run a haproxy on localhost:7443 with a backed of:
# a lighttpd on localhost:3480 with foo.example.com 

# Note on testing - if you have our curl build locally, and foo.example.com
# is in your /etc/hosts, then:
#       $ cd $HOME/code/curl
#       $ src/curl --echconfig AED+CgA8ogAgACCRR4BdUxMqi3p2QZxscc4yKK7SSEe6yvjD/XQcodPBLwAEAAEAAQAAAAtleGFtcGxlLmNvbQAA --cacert ../openssl/esnistuff/cadir/oe.csr https://foo.example.com:7443/index.html -v
#
# Replace the bas64 encoded stuff abouve with the right public key as
# needed.

: ${OSSL:="$HOME/code/openssl"}
: ${LIGHTY:="$HOME/code/lighttpd1.4"}
: ${HAPPY:="$HOME/code/haproxy"}
: ${ECHCONFIG:="d13.pem"}
# to pick up correct executables and .so's  
export TOP=$OSSL
export LD_LIBRARY_PATH=$OSSL

HLOGDIR="$OSSL/esnistuff/haproxy/logs"
HLOGFILE="$HLOGDIR/haproxy.log"
RSCFG="/etc/rsyslog.conf"

doclient="no"

if [[ "$1" == "client" ]]
then
    doclient="yes"
elif [[ "$1" != "" ]]
then
    echo "Unrecognised argument: $1"
    echo "usage: $0 [client]"
    exit -1
fi

# make directories for lighttpd stuff if needed
mkdir -p $OSSL/esnistuff/lighttpd/logs
mkdir -p $OSSL/esnistuff/lighttpd/www
mkdir -p $OSSL/esnistuff/lighttpd/baz
mkdir -p $HLOGDIR

if [ ! -f $HLOGFILE ]
then
    touch $HLOGFILE
    chmod a+w $HLOGFILE
fi

# Check if $RSCFG has an entry for our haproxy log file
if [ -f $RSCFG ] 
then
    syslogknowsalready=`grep -c "$HLOGFILE" $RSCFG`
    if [[ "$syslogknowsalready" == "0" ]]
    then
        echo "You need stanzas for haproxy logging in $RSCFG"
        echo "That should look like:" 
        echo ""
    cat <<EOF
# Haproxy - you might not want this here forever as it means packets
# rx'd could fill a disk maybe
\$ModLoad imudp
\$UDPServerAddress 127.0.4.5
\$UDPServerRun 7514
local0.* $HLOGFILE
EOF
    echo ""
    echo "You should fix that - exiting in the meantime"
    exit
    fi
else 
    echo "No sign of $RSCFG - exiting as haproxymin.conf needs that"
    exit
fi

# check for/make a home page for example.com and other virtual hosts
if [ ! -f $OSSL/esnistuff/lighttpd/www/index.html ]
then
    cat >$OSSL/esnistuff/lighttpd/www/index.html <<EOF

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Lighttpd top page.</title>
</head>
<!-- Background white, links blue (unvisited), navy (visited), red
(active) -->
<body bgcolor="#FFFFFF" text="#000000" link="#0000FF"
vlink="#000080" alink="#FF0000">
<p>This is the pretty dumb top page for testing. </p>

</body>
</html>

EOF
fi

# check for/make a slightly different home page for baz.example.com
if [ ! -f $OSSL/esnistuff/lighttpd/baz/index.html ]
then
    cat >$OSSL/esnistuff/lighttpd/baz/index.html <<EOF

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Lighttpd top page.</title>
</head>
<!-- Background white, links blue (unvisited), navy (visited), red
(active) -->
<body bgcolor="#FFFFFF" text="#000000" link="#0000FF"
vlink="#000080" alink="#FF0000">
<p>This is the pretty dumb top page for baz.example.com testing. </p>

</body>
</html>

EOF
fi

# set to run in foreground or as daemon -D => foreground
# unset =>daemon
# FOREGROUND="-D "

# set to use valgrind, unset to not
VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
#VALGRIND="valgrind --leak-check=full --error-limit=1 --track-origins=yes"
# VALGRIND=""

# Check if a lighttpd is running
lrunning=`ps -ef | grep lighttpd | grep -v grep | grep -v tail`

if [[ "$lrunning" == "" ]]
then
    echo "Executing: $VALGRIND $LIGHTY/src/lighttpd $FOREGROUND -f $OSSL/esnistuff/lighttpd4haproxymin.conf -m $LIGHTY/src/.libs"
    $LIGHTY/src/lighttpd $FOREGROUND -f $OSSL/esnistuff/lighttpd4haproxymin.conf -m $LIGHTY/src/.libs
else
    echo "Lighttpd already running: $lrunning"
fi

HAPDEBUGSTR=" -dV " 
if [[ "$doclient" == "yes" ]]
then
    # run server in background
    HAPDEBUGSTR=" -DdV " 
    # Kill any earlier haproxy running
    killall haproxy
fi


# Now start up a haproxy
echo "Executing: $VALGRIND $HAPPY/haproxy -f $OSSL/esnistuff/haproxymin.conf $HAPDEBUGSTR"
$VALGRIND $HAPPY/haproxy -f $OSSL/esnistuff/haproxymin.conf $HAPDEBUGSTR

if [[ "$doclient" == "yes" ]]
then
    echo "Doing client calls..."
    # Uncomment for loadsa logging...
    # clilog=" -d "
    for port in 7443 7444 7445 7446 
    do
        # do GREASEy case
        echo "**** Greasing: $OSSL/esnistuff/echcli.sh $clilog -gn -p $port \
                -c example.com -s localhost -f index.html"
        $OSSL/esnistuff/echcli.sh $clilog -gn -p $port \
                -c example.com -s localhost -f index.html
        echo "**** Above was Greasing: $OSSL/esnistuff/echcli.sh $clilog -gn -p $port \
                -c example.com -s localhost -f index.html"
        # do real ECH case
        echo "**** Real ECH: $OSSL/esnistuff/echcli.sh $clilog -s localhost -H foo.example.com  \
                -p $port \
                -P $ECHCONFIG \
                -f index.html -N "
        $OSSL/esnistuff/echcli.sh $clilog -s localhost -H foo.example.com  \
                -p $port \
                -P $ECHCONFIG \
                -f index.html -N
        res=$?
        if [[ "$res" == "0" ]]
        then
            echo "**** This worked: : $OSSL/esnistuff/echcli.sh $clilog -s localhost -H foo.example.com  \
                -p $port \
                -P $ECHCONFIG \
                -f index.html -N "
        else
            echo "**** This failed ($res): : $OSSL/esnistuff/echcli.sh $clilog -s localhost -H foo.example.com  \
                -p $port \
                -P $ECHCONFIG \
                -f index.html -N "
        fi

    done
fi
