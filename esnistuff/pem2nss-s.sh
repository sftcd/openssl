#!/bin/bash

# set -x

# map an ECH PEM file to (what I think) is needed for NSS's selfserve
# ECH input - a WIP as selfserve currently barfs with this input, for
# some reason (maybe pkcs#8 OID use, not sure)
#
# The code in $HOME/code/nss/cmd/selfserve/selfserve.c says the format
# expected is:
#
# struct {
#     opaque pkcs8_ech_keypair<0..2^16-1>;
#     ECHConfigs configs<0..2^16>; // draft-ietf-tls-esni-09
# } ECHKey;
#
# As of 20240126, selfserve needs more work for this to be possible.
# NSS devs know about it and will hopefully get to that in future.
# For now, this script can hang about 'till that's done, then we 
# may want it again, or they may have adopted our PEM format by
# then, if we're lucky.

# default
PEMF="$HOME/code/openssl/test/certs/echconfig.pem"

if [[ "$1" != "" ]]
then
    PEMF=$1
fi

priv=`head -2 $PEMF | tail -1`
ech=`tail -2 $PEMF | head -1`

privah=`echo $priv | base64 -d | xxd -ps -c200`
privah_len=${#privah}
echah=`echo $ech | base64 -d | xxd -ps -c200`
outah="`printf  "%04x" $((privah_len/2))`$privah$echah"
outb64=`echo "$outah" | xxd -p -r | base64 -w 0` 

echo $outb64
