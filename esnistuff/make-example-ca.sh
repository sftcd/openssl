#!/bin/bash

# Make key pairs for a fake local CA, example.com, foo.example.com
# and bar.example.com

#set -x
DSTR=`date -u --rfc-3339=s | sed -e 's/ /T/' | sed -e 's/:/-/g'`
echo "Running $0 at $DSTR"

#
# The keys we need are, done below. Figure it out:-)

# this is where all the various files live
CADIR=./cadir

mkdir -p $CADIR
cd $CADIR

touch lastrun
if [ "$?" == "1" ]
then
	echo "Can't write to $CADIR exiting";
	exit
fi

mkdir -p demoCA/newcerts

# the CA needs a file called serial
if [ ! -f serial ]
then
	# this should probably be random and longer
	# don't want it to be a fingerprint for this
	# service
	echo $RANDOM$RANDOM | openssl sha1 | awk '{print $2}' >serial
	cp serial serial.1st
fi

# same for index.txt
if [ ! -f index.txt ]
then
	touch index.txt
fi

# dunno (or care) where these ought be so put 'em everywhere
cp index.txt demoCA
cp serial serial.1st demoCA
cp index.txt demoCA/newcerts
cp serial serial.1st demoCA/newcerts

# an openssl config
if [ -f ../openssl.cnf ]
then
	cp ../openssl.cnf .
else
	cp /etc/ssl/openssl.cnf .
fi

# and an openssl config
if [ ! -f openssl.cnf ]
then
	echo "You need an openssl.cnf file sorry."
	exit 1
fi


# this isn't quite obfuscation, I think we'll delete the
# CA private key when done:-) So this means it'll not have
# been in clear on disk
PASS=$RANDOM$RANDOM$RANDOM$RANDOM
echo $PASS >pass

# HOST/SNI we'll use for grabbing
# this only needs to be in /etc/hosts on grabber
# and isn't needed in DNS or anywhere but there
NAMES="example.com foo.example.com bar.example.com baz.example.com"

# Ensure that the length of (RSA) keys for our 
# names vary, so that we can exercise padding that
# deals with more than just a few bytes difference
# in name lengths (e.g. example.com's cert is only
# 6 bytes shorter than foo.example.com's cert.)
# We'll choose a length that's one of these based
# on the index of our name in NAMES
LENGTHS=(2048 3072 4096)
# number of items in above array
NLENGTHS=${#LENGTHS[*]}

# make the root CA key pair
openssl req -batch -new -x509 -days 3650 -extensions v3_ca \
	-newkey rsa:4096 -keyout oe.priv  -out oe.csr  \
	-config openssl.cnf -passin pass:$PASS \
	-subj "/C=IE/ST=Laighin/O=openssl-esni/CN=ca" \
	-passout pass:$PASS \

# generate and sign a key for the TLS server
index=0
for host in $NAMES
do
	length=${LENGTHS[((index%NLENGTHS))]}

	echo "Doing name $index, at $length"
	openssl req -new -newkey rsa:$length -days 3650 -keyout $host.priv \
		-out tmp.csr -nodes -config openssl.cnf \
		-subj "/C=IE/ST=Laighin/L=dublin/O=openssl-esni/CN=$host"
	openssl ca -batch -in tmp.csr -out $host.crt \
		-days 3650 -keyfile oe.priv -cert oe.csr \
		-passin pass:$PASS -config openssl.cnf
	((index++))
done

# If we have an NSS build, create an NSS DB for our fake root so we can 
# use NSS' tstclnt (via nssdoit.sh) to talk to our s_server.
# Note: values below (LDIR and nssca dir) need to sync with nssdoit.sh 
# content and with your NSS code build (and I suspect it needs to be a 
# build as ESNI support in NSS isn't afaik released)
LDIR=$HOME/code/dist/Debug/
if [ -f $LDIR/bin/certutil ]
then
	mkdir -p nssca
	export LD_LIBRARY_PATH=$LDIR/lib
	$LDIR/bin/certutil -A -i oe.csr -n "oe" -t "CT,C,C" -d nssca/
fi

