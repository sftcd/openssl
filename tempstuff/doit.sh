#!/bin/bash

export LD_LIBRARY_PATH=$HOME/code/openssl
ESNI="/wHHBBOoACQAHQAg4YSfjSyJPNr1z3F8KqzBNBnMejim0mJZaPmria3XsicAAhMBAQQAAAAAW9pQEAAAAABb4jkQAAA="
COVER="cloudflare.net"
HIDDEN="encryptedsni.com"
VG="no"

if [[ "$VG" == "mo" ]]
then
	./esni $HIDDEN $COVER $ESNI
else
	valgrind --leak-check=full ./esni $HIDDEN $COVER $ESNI
fi
