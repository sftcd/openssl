#!/bin/bash

#set -x

# to pick up correct .so's - maybe note 
export LD_LIBRARY_PATH=$HOME/code/openssl

# this is one I downloaded manually via dig +short TXT _esni.encryptedsni.com
ESNI="/wHHBBOoACQAHQAg4YSfjSyJPNr1z3F8KqzBNBnMejim0mJZaPmria3XsicAAhMBAQQAAAAAW9pQEAAAAABb4jkQAAA="
COVER="cloudflare.net"
HIDDEN="encryptedsni.com"
VG="yes"

# should really add getopt but this is likely short-term (famous last
# words those:-)

if [[ "$1" == "fresh" ]]
then
	echo "Checking for fresh ESNI value from $HIDDEN"
	ESNI=`dig +short TXT _esni.$HIDDEN | sed -e 's/"//g'`	
	echo "Fresh ESNI value: $ESNI"
fi	

VCGMD="valgrind --leak-check=full "
if [[ "$VG" == "no" ]]
then
	VGCMD=""
fi
$VGDMD ../apps/openssl s_client -esni $HIDDEN -esnirr $ESNI -servername $COVER
