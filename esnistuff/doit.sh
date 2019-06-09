#!/bin/bash

#set -x

# Run nssdoit.sh first, and it'll generate new values that should be
# good until CF change their public key share (about every hour or
# so maybe)

# Then if you've compiled OpenSSL with "CRYPT_INTEROP" #define'd
# (it's in include/openssl/esni.h) you can generate commensurate
# outputs, if you grab the right/same inputs from the NSS files
# as per below.

ESNI="FF027CE3FD9C000B6578616D706C652E6E65740024001D00208C48CF4B00BAAF1191C8B882CFA43DC7F45796C7A0ADC9EB6329BE25B9464235000213010104000000005C9588C7000000005C9EC3470000FF02FF93090D000B6578616D706C652E636F6D0024001D00202857EF701013510D270E531232C40A09226A83391919F4ED3F6B3D08547A7F68000213010104000000005C93BA56000000005C9CF4D60000"
#ESNI="/wEhoY5aACQAHQAgHqTcPWLSyVnFusv84efGXK4JIC/oPRSs/va4mI661QUAAhMBAQQAAAAAW/XVYAAAAABb/b5gAAA="
HIDDEN="encryptedsni.com"
COVER="www.cloudflare.com"

# ASCII Hex of 1st private key in nss.ssl.debug, eliminate spaces etc.
PRIV="29ab54e6258de21b4178a6270db88ad411809199c267a6317646728966fdca02"

# H/S key share - from AAD in nss.out
HSKS="a8cc84eed13d54f62e69d269988d79ef0514f6a8e64dcb774369f2eff560b12b"

# Client_random
CRND="62ea83d6f9f946248fa41b29f0127e72a0aeadce44262bed399f2fc4a8365e0b"

# Nonce
NONCE="45a61b547439b11dac1274e301145084"

# should really add getopt but this is likely short-term (famous last
# words those:-)

if [[ "$1" == "fresh" ]]
then
	echo "Checking for fresh ESNI value from $HIDDEN"
	ESNI=`dig +short TXT _esni.$HIDDEN | sed -e 's/"//g'`	
	echo "Fresh ESNI value: $ESNI"
fi	

if [[ "$1" == "defo" ]]
then
    HIDDEN="only.esni.defo.ie"
	echo "Checking for fresh ESNI value from $HIDDEN"
    ESNI=`dig +short txt _esni.$HIDDEN | sed -e 's/"//g' | sed -e 'N;s/\n/;/'`
    COVER="cover.defo.ie"
	echo "Fresh ESNI value: $ESNI"
fi

# CRYPT_INTEROP Version
#valgrind --leak-check=full ./esni -s $HIDDEN -f $COVER -e $ESNI -p $PRIV -r $CRND -k $HSKS -n $NONCE

# "normal" version - doesn't take other folks' internal crypto inputs
echo "Running: valgrind --leak-check=full ./esni -s $HIDDEN -f $COVER -e $ESNI $*"
valgrind --leak-check=full ./esni -s $HIDDEN -f $COVER -e $ESNI $*
