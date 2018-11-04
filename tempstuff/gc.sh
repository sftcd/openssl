#!/bin/bash

# Copyright (C) 2018 Stephen Farrell, stephen.farrell@cs.tcd.ie
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# This was initially copied from https://github.com/sftcd/surveys/clustertools/gc.sh
# I added some more openssl s_client debug stuff

# set -x

# use build version of openssl
export LD_LIBRARY_PATH="$HOME/code/openssl"
OBIN="$HOME/code/openssl/apps/openssl"

# Use openssl to dump a server cert 

error="nope"
HOST=$1
if [ "$HOST" == "" ]
then
	error="yep"
fi
PORT=$2
if [ "$PORT" == "" ]
then
	PORT=443
fi
case $PORT in
	25|110|143|443|587|993)
		;;
	*)
		error="yep"
		;;
esac

if [ "$error" == "yep" ]
then
	echo "usage: $0 <host> [<port>]"
	echo "    default port: 443,other ports supported 25,143,993"
	exit -1
fi

# check if host is up at all first
#ping -c 1 $HOST
#if [ "$?" != "0" ]
#then
	#echo "$HOST not answering a ping"
	#exit -1
#fi

OUTF=$HOST-$PORT.state.txt

# additional debug options, might need to vary by port later
SCARGS="-state -esni cloudflare.net"

echo "Getting cert for $HOST:$PORT"
if [ "$PORT" == "443" ]
then
	echo | $OBIN s_client $SCARGS -connect $HOST:$PORT >$OUTF 2>&1
fi
if [[ "$PORT" == "25" || "$PORT" == "587" ]]
then
	echo | $OBIN s_client $SCARGS -connect $HOST:$PORT -starttls smtp >$OUTF 2>&1
fi
if [ "$PORT" == "110" ]
then
	echo | $OBIN s_client $SCARGS -connect $HOST:$PORT -starttls pop3 >$OUTF 2>&1
fi
if [ "$PORT" == "143" ]
then
	echo | $OBIN s_client $SCARGS -connect $HOST:$PORT -starttls imap >$OUTF 2>&1
fi
if [ "$PORT" == "993" ]
then
	echo | $OBIN s_client $SCARGS -connect $HOST:$PORT >$OUTF 2>&1
fi

echo "Output is in $OUTF"
