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


# this is where all the various files live
ESNIKEYDIR=esnikeydir

mkdir -p $ESNIKEYDIR
cd $ESNIKEYDIR
# may as well name files based on addresses:-)
for fname in 127.0.0.99 127.0.0.100 127.0.0.101
do
    if [ ! -f $fname ]
    then
        echo "$fname" >$fname
    fi
done
$MKBIN -V 0xff02 -o e2.pub -p e2.priv -P foo.example.net -A 127.0.0.100
$MKBIN -V 0xff02 -o e3.pub -p e3.priv -P bar.example.net -A 127.0.0.101
cd ..
$MKBIN -V 0xff02 -o esnikeys.pub -p esnikeys.priv -P example.net -A esnikeydir/127.0.0.99
