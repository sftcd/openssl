#!/bin/bash

# set -x

PORT="8443"
SERVER="localhost"
HIDDEN="foo.example.com"
COVER="example.com"
SESSFILE="$HIDDEN.sess"
PUBKEY="esnikeys.pub"




rm -f $SESSFILE

if [[ "$1" != "NONE" ]]
then
    ./testclient.sh -p $PORT -s $SERVER -H $HIDDEN -c $COVER -P $PUBKEY -S $SESSFILE -v >/dev/null 2>&1
    if [ -f $SESSFILE ]
    then
        ./testclient.sh -p $PORT -s $SERVER -H $HIDDEN -c $COVER -P $PUBKEY -S $SESSFILE -d
    else
        echo "No $SESSFILE - exiting"
    fi
else
    httpreq="GET / HTTP/1.1\r\nConnection: close\r\nHost: $COVER\r\n\r\n"
    echo -e "$httpreq" | valgrind /home/stephen/code/openssl-tunnel/apps/openssl s_client -CAfile ./cadir/oe.csr -tls1_3 -connect localhost:$PORT -servername $COVER -sess_out $SESSFILE >/dev/null 2>&1
    if [ -f $SESSFILE ]
    then
        echo -e "$httpeq" | /home/stephen/code/openssl-tunnel/apps/openssl s_client -msg -CAfile ./cadir/oe.csr -tls1_3 -connect localhost:$PORT -servername $COVER -sess_in $SESSFILE
    else
        echo "No $SESSFILE - exiting"
    fi
fi

