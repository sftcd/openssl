#!/bin/bash

# set -x

# Merge a bunch of ECHConfigs found in PEM files
# We assume PEM files have the ECHConfig in the 2nd last line
# such as the example below...
#
# -----BEGIN ETAVIRP KEY-----
# MC4CAQAwBQYDK2VuBCIEIKB22iNxcmmOiIIiBjPIaXxwBHzrihukDewMm9N3cNh3
# -----END ETAVIRP KEY-----
# -----BEGIN ECHCONFIG-----
# AED+CgA8ogAgACCRR4BdUxMqi3p2QZxscc4yKK7SSEe6yvjD/XQcodPBLwAEAAEAAQAAAAtleGFtcGxlLmNvbQAA
# -----END ECHCONFIG-----
#
# Note: the above example has the string "PRIVATE" reversed
# so that github doesn't think we're leaking a significant 
# private key.


PEMFILES=""
OUTFILE="/dev/stdout"

function usage()
{
    echo "$0 [-o <file>] <pemfiles>"
    echo "  -o specifies an output file (default stdout)"
    echo "  -h means print this"
    echo "<pemfiles> is the list of input files"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o ho: -l help,output: -- "$@")
then
    # something went wrong, getopt will put out an error message for us
    exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
    case "$1" in
        -h|--help) usage;;
        -o|--output) OUTFILE=$2; shift;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done

PEMFILES="$@"

# echo "PEMFILES: $PEMFILES"
# echo "OUTFILE: $OUTFILE"

if [[ "$PEMFILES" == "" ]]
then
    echo "No input files provided - exiting"
    exit 98
fi

incount=0

for file in $PEMFILES 
do
    if [ -f $file ]
    then
        incount=$((incount+1))
    # else
        # echo "Skipping $file - doesn't seem to exist"
    fi
done

# echo "incount: $incount"

if ((incount <= 1))
then
    echo "Not enough existing input files provided ($incount)- exiting"
    exit 97
fi

ah_overall=""
overall_len=0
for file in $PEMFILES
do
    if [ ! -f $file ]
    then
        continue
    fi
    ah_ech=`cat $file | tail -2 | head -1 | base64 -d | xxd -ps -c 200 | tr -d '\n'`  
    ah_ech_no_len=${ah_ech:4}
    ah_overall="$ah_overall$ah_ech_no_len"
    ah_ech_len=${#ah_ech}
    ech_len=$((ah_ech_len/2-2))
    overall_len=$((overall_len+ech_len))
    # echo "$file $ech_len $overall_len"
done

ah_overall="`printf  "%04x" $((overall_len))`$ah_overall"

# echo "ah_overall: $ah_overall"
b64str=`echo "$ah_overall" | xxd -p -r | base64 -w 0` 

echo "-----BEGIN ECHCONFIG-----" >$OUTFILE
echo "$b64str" >>$OUTFILE
echo "-----END ECHCONFIG-----" >>$OUTFILE

exit 0
