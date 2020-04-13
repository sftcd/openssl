#!/bin/bash

# set -x

. ./env

# generate a key pair if needed, call s_client as well

EFILE="echoconfig.pem"
PUBLIC_NAME="example.com"
HIDDEN_NAME="foo.example.com"

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

../apps/openssl s_client -servername $PUBLIC_NAME -echo $HIDDEN_NAME -echorr $epub

