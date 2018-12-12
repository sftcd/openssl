#!/bin/bash

set -x

# Make ESNI key pairs - both main ones and some in a subdirectory

#set -x
DSTR=`date -u --rfc-3339=s | sed -e 's/ /T/' | sed -e 's/:/-/g'`
echo "Running $0 at $DSTR"

TOP=$HOME/code/openssl
MKBIN=$TOP/esnistuff/mk_esnikeys

#
# The ESNI keys we need are done below. Figure it out:-)

# make a 'main' key pair 

if [ ! -f $MKBIN ]
then
	echo "First build $MKBIN"
	exit 1
fi

$MKBIN -o esnikeys.pub -p esnikeys.priv

# this is where all the various files live
ESNIKEYDIR=esnikeydir

mkdir -p $ESNIKEYDIR
cd $ESNIKEYDIR
$MKBIN -o e2.pub -p e2.priv
$MKBIN -o e3.pub -p e3.priv

