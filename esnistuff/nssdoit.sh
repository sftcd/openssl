#!/bin/bash

DIR=/home/stephen/code/dist/Debug/

ESNI=`dig +short txt _esni.www.cloudflare.com`

export LD_LIBRARY_PATH=$DIR/lib

valgrind $DIR/bin/tstclnt -h www.cloudflare.com -p 443  \
	-d ~/.mozilla/eclipse/ \
	-N $ESNI
