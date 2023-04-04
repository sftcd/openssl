#!/bin/bash

# set -x

# Take a set of named PNGs (cat pics) and make those into a 
# file that can be included into an ECHConfig as extensions. 
# We omit the overall extensions length so we can still
# catenate files if we want (and because ``openssl ech`` will 
# add that anyway). Extension type is made up.

OUTFILE="cat.ext" # default output
CATPICTYPE=65482  # 0xffca is the 1st extension type - we'll incrememt after

function usage()
{
    echo "Read the code, sorry"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o o:h -l output:,help -- "$@")
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

infiles=$*

exttype=$CATPICTYPE

if [ -f $OUTFILE ]
then
    # one backup is enough
    mv $OUTFILE $OUTFILE.bak
fi

for file in $infiles
do
    echo $file
    if [ ! -f $file ] 
    then
        # add empty extension
        flen=0
    else
        flen=`wc -c $file | awk '{print $1}'`
    fi
    # output type, length, value to $OUTFILE
    ah_type="`printf  "%04x" $((exttype))`"
    exttype=$((exttype+1))
    echo $ah_type | xxd -p -r >>$OUTFILE
    ah_flen="`printf  "%04x" $((flen))`"
    echo $ah_flen | xxd -p -r >>$OUTFILE
    if [ -f $file ]
    then
        cat $file >>$OUTFILE
    fi
done
