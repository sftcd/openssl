#!/bin/bash

# set -x

# map the ECHCOnfigs from a PEM file to an ascii HEX RR that
# could be included in a zone file

PEMFILE="echconfig.pem"
RRFILE="/dev/stdout"
DOMAIN=""
IPV4=""
IPV6=""

function usage()
{
    echo "$0 [-pr] - map a PEMFile containing an ECHConfigs to an ascii hex RR value"
    echo "  -p [pemfile] specifies the pemfile input (default $PEMFILE)"
    echo "  -r [rrfiles] specifies the output (default $RRFILE)"
    echo "  -h means print this"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o hp:r: -l help,pemfile:,rrfile: -- "$@")
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
        -p|--pemfile) PEMFILE=$2; shift;;
        -d|--domain) DOMAIN=$2; shift;;
        -4|--ipv4) IPV4=$2; shift;;
        -6|--ipv6) IPV6=$2; shift;;
        -r|--rrfile) RRFILE=$2; shift;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done

if [ ! -f $PEMFILE ]
then
    echo "Can't read $PEMFILE - exiting"
    exit 1
fi

rr_preamble="000100"
ah_ech=`cat $PEMFILE | tail -2 | head -1 | base64 -d | xxd -ps -c 200 | tr -d '\n'`  
ah_ech_len=${#ah_ech}
ah_ech_len=`printf  "%04x" $((ah_ech_len/2))`
ah_ech_header="0005${ah_ech_len}"
# if you're good with no more...
# rr_postamble=""
# If you'd like a real one - this is the end of the output from ``dig type65 www.ietf.org``
rr_postamble="0100030268320004000C68146E0668146F06AC4321F90006003026064700001000000000000068146E0626064700001000000000000068146F06260647000010000000000000AC4321F9"

echo "$rr_preamble$ah_ech_header$ah_ech$rr_postamble" >$RRFILE
