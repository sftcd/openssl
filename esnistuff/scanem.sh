#!/bin/bash

# find which .c and .h files differ in two source trees 

# set -x

: ${ECHTOP:=$HOME/code/openssl}
: ${OTHERTOP:=$HOME/code/openssl-master}

startdir=`/bin/pwd`
cd $ECHTOP

sources=`find . -name '*.[ch]'`

for file in $sources
do
    diff -q $file $OTHERTOP/$file
    isdiff=$?
    if [[ "$isdiff" == "1" ]]
    then
        isech=`grep -c NO_ECH $file`
        if [[ "$isech" == "0" ]]
        then
            echo "     no sign of NO_ECH in $file"
        fi
    fi
done

cd $startdir
