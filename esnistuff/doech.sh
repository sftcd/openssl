#!/bin/bash

# set -x

# generate a key pair if needed, call s_client as well

: ${TOP=$HOME/code/openssl}
export LD_LIBRARY_PATH=$TOP
EDIR="$TOP/esnistuff"

EFILE="$EDIR/echconfig.pem"
PUBLIC_NAME="example.com"
HIDDEN_NAME="foo.example.com"
RUNCLI="no" # can parameterise later if needed

VALGRIND=""
if [[ "$1" == "-v" ]]
then
    VALGRIND="valgrind --leak-check=full "
fi

if [ ! -d $EDIR ]
then
    mkdir -p $EDIR
fi

if [ ! -d $EDIR/echkeydir ]
then
    mkdir $EDIR/echkeydir
fi

if [ ! -f $EFILE ]
then
    ../apps/openssl ech -public_name $PUBLIC_NAME -pemout $EFILE
fi
if [ ! -f $EFILE ]
then
    echo "Failed to make $EFILE - exiting"
    exit 1
fi

ECHFILE="$EDIR/echkeydir/`basename $EFILE`.ech"
if [ ! -f $ECHFILE ]
then
	cp $EFILE $EDIR/echkeydir/`basename $EFILE`.ech
fi
if [ ! -f $ECHFILE ]
then
    echo "Failed to make $ECHFILE - exiting"
    exit 1
fi


if [[ "$RUNCLI" == "no" ]]
then
    exit 0
fi

epub=`cat $EFILE | tail -2 | head -1`
echo "Running: ../apps/openssl s_client -servername $PUBLIC_NAME -ech $HIDDEN_NAME -echconfigs $epub"
$VALGRIND $TOP/apps/openssl s_client -servername $PUBLIC_NAME -ech $HIDDEN_NAME -echconfigs $epub
