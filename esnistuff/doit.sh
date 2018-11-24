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
PRIV="73930029baeb928438fd65cdf0722c681f6c917d630e30ffa231679cf868dd2f"

# H/S key share
HSKS="1c34c18543b9098efc3de3a5af7ca90caafa6baee43f87dc62576207e92d987b"

# Client_random
CRND="348aa8e2d8745ceb91d40d47284a77436daa9b4dcd692a34938ea0ac9634383a"

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
