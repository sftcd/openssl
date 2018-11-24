#!/bin/bash

#set -x

# to pick up correct .so's - maybe note 
#export LD_LIBRARY_PATH=$HOME/code/openssl

# this is one I downloaded manually via dig +short TXT _esni.encryptedsni.com
# ESNI="/wHHBBOoACQAHQAg4YSfjSyJPNr1z3F8KqzBNBnMejim0mJZaPmria3XsicAAhMBAQQAAAAAW9pQEAAAAABb4jkQAAA="
# COVER="cloudflare.net"
# HIDDEN="encryptedsni.com"


# this is one I downloaded manually via dig +short TXT _esni.www.cloudflare.com on 20181121
#ESNI="/wEU528gACQAHQAguwSAYz57kzOUzDXCAZ7aBJLWPrQwvSuNsRZbi7JzqkYAAhMBAQQAAAAAW/E4IAAAAABb+SEgAAA="
ESNI=`dig +short txt _esni.www.cloudflare.com | sed -e 's/"//g'`
HIDDEN="www.cloudflare.com"
COVER="www.cloudflare.com"

# Run nssdoit.sh first, and it'll generate new values that should be
# good until CF change they public key share

# ASCII Hex of 1st private key in nss.ssl.debug, eliminate spaces etc.
PRIV="b24dc635cdaf48b449c928e6eaa2f2d9486546a8d6c63d7854638aba14305a3d"

# H/S key share - from AAD in nss.out
HSKS="fd7db46fbe19d12bac868bbed3ccf320c25667c052400d7c885cf9425656005e"

# Client_random
CRND="707800343affcdeda3ff0a0090eb4929e19e2efc0d68f3cc0fe97216097509b4"

VG="yes"

# should really add getopt but this is likely short-term (famous last
# words those:-)

if [[ "$1" == "fresh" ]]
then
	echo "Checking for fresh ESNI value from $HIDDEN"
	ESNI=`dig +short TXT _esni.$HIDDEN | sed -e 's/"//g'`	
	echo "Fresh ESNI value: $ESNI"
fi	

echo "gdb cheat: r $HIDDEN $COVER $ESNI"
if [[ "$VG" == "no" ]]
then
	./esni $HIDDEN $COVER $ESNI
else
	valgrind --leak-check=full ./esni -s $HIDDEN -f $COVER -e $ESNI -p $PRIV -r $CRND -k $HSKS
fi
