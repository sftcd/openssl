#!/bin/bash

# set -x

# make up an ECHConfigList with multiple entries
# some but not all of which are known versions

# Our code now supports versions 10 and 13, the
# list should contain versions in this order:
# [13,10,9,13,10,13]

# Note that version 9 is supported only for 
# key gen for tests such as this (and only
# temporarily)

# We generate each, then merge the public values
# then ditch the tmp files

# to pick up correct executables and .so's  
: ${CODETOP:=$HOME/code/openssl}
export LD_LIBRARY_PATH=$CODETOP
# to pick up the relevant configuration
: ${CFGTOP:=$HOME/code/openssl}
# in case you want to re-use a tmp directory 
: ${SCRATCHDIR:=""}
# in case you want to keep output from this run, set this to something
: ${KEEP:=""}
# in case you'd like more detailed gibberish-like output:-)
: ${VERBOSE:=""}

startdir=`/bin/pwd`
ofile="listof6"

tdir=""
if [[ "$SCRATCHDIR" != "" ]]
then
    tdir=$SCRATCHDIR
else
    tdir=`mktemp -d`
fi

if [ ! -d $tdir ]
then
    echo "No $tdir - exiting"
    exit 1
fi

cd $tdir

pname="-public_name example.com"

$CODETOP/apps/openssl ech $pname -ech_version 13 -pemout 1.pem 
$CODETOP/apps/openssl ech $pname -ech_version 10 -pemout 2.pem 
$CODETOP/apps/openssl ech $pname -ech_version 9 -pemout 3.pem 
$CODETOP/apps/openssl ech $pname -ech_version 13 -pemout 4.pem 
$CODETOP/apps/openssl ech $pname -ech_version 10 -pemout 5.pem 
$CODETOP/apps/openssl ech $pname -ech_version 13 -pemout 6.pem 

$CODETOP/esnistuff/mergepems.sh *.pem -o $startdir/$ofile.pem

cd $startdir

if [[ "$SCRATCHDIR" == "" ]]
then
    rm $tdir/*.pem
    rmdir $tdir
fi




