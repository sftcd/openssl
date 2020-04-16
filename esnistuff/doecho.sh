#!/bin/bash

# set -x

# generate a key pair if needed, call s_client as well

TOP="$HOME/code/openssl"
export LD_LIBRARY_PATH=$TOP
EDIR="$TOP/esnistuff"

EFILE="$EDIR/echoconfig.pem"
PUBLIC_NAME="example.com"
HIDDEN_NAME="foo.example.com"

VALGRIND=""
if [[ "$1" == "-v" ]]
then
    VALGRIND=valgrind
fi


if [ ! -f $EFILE ]
then
    ../apps/openssl echo -public_name $PUBLIC_NAME -pemout $EFILE
fi
if [ ! -f $EFILE ]
then
    echo "Failed to make $EFILE - exiting"
    exit 1
fi

epub=`cat $EFILE | tail -2 | head -1`

echo "Running: ../apps/openssl s_client -servername $PUBLIC_NAME -echo $HIDDEN_NAME -echorr $epub"
$VALGRIND $TOP/apps/openssl s_client -servername $PUBLIC_NAME -echo $HIDDEN_NAME -echorr $epub

