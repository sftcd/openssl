#!/bin/bash

# set -x

# Fire up gdb with LD_LIBRARY_PATH setup for apache
# If you're following the setup I used (*) then this
# should help if you wanna use gdb for apache
# (*) https://github.com/sftcd/openssl/blob/master/esnistuff/apache2.md

OSSL_TOP=$HOME/code/openssl-draft-10
AP_TOP=$HOME/code/httpd-draft-10

OSSL_LP=$OSSL_TOP
HTTPD_LP=$AP_TOP/.libs
APR_LP=$AP_TOP/srclib/apr/.libs
MO_LP=$AP_TOP/modules/ssl/.libs
AAA_LP=$AP_TOP/modules/aaa/.libs
ENV_LP=$AP_TOP/modules/metadata/.libs/
CFG_LP=$AP_TOP/modules/loggers/.libs/
UNIX_LP=$AP_TOP/modules/arch/unix/.libs/

export LD_LIBRARY_PATH="$OSSL_LP:$HTTPD_LP:$APR_LP:$MO_LP:$ENV_LP:$CFG_LP:$UNIX_LP"

# kill off other processes
procs=`ps -ef | grep httpd | grep -v grep | awk '{print $2}'`
for proc in $procs
do
    echo "Killing $proc"
    kill -9 $proc
done
sleep 2

# go to the right place and fire up gdb, as needed
cd $OSSL/esnistuff
# we take one argument that can be a breakpoint
if [[ "$1" != "" ]]
then
    echo "Setting breakpoint to $1"
    gdb -ex "set breakpoint pending on" -ex "b \"$1\"" -exec $AP_TOP/.libs/httpd -ex "run -X -d . -f apachemin.conf -DFOREGROUND" 
else
    gdb -exec $AP_TOP/.libs/httpd -ex "run -X -d . -f apachemin.conf -DFOREGROUND" 
fi


