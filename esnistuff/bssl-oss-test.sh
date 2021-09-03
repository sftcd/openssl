#!/bin/bash

# set -x

# Do one of 5 things:
# 1. (g) generate ECH credentials for boringssl 
# 2. (l) run a boringssl s_client against localhost:8443 (default)
# 3. (c) run a boringssl s_client against cloudflare
# 4. (s) run a boringssl s_server on localhost:8443
# 5. (d) run a boringssl s_client against draft-13.esni.defo.ie:8413

# The setup here depends on me having generated keys etc in
# my ususal $HOME/code/openssl/esnistuff setup.

# to pick up correct .so's - maybe note 
: ${CODETOP:=$HOME/code/openssl}
export LD_LIBRARY_PATH=$CODETOP
# to pick up the relevant configuration
: ${CFGTOP:=$HOME/code/openssl/esnistuff}
# to pick up the boringssl build
: ${BTOP:=$HOME/code/boringssl}
# to pickup a different ECH config file
: ${ECHCONFIGFILE="$CFGTOP/echconfig.pem"}

BTOOL="$BTOP/build/tool"
BFILES="$CFGTOP/bssl"
httphost=foo.example.com
httpreq="GET /stats HTTP/1.1\\r\\nConnection: close\\r\\nHost: $httphost\\r\\n\\r\\n"
cfhost="crypto.cloudflare.com"
cfhttpreq="GET / HTTP/1.1\\r\\nConnection: close\\r\\nHost: $cfhost\\r\\n\\r\\n"

defohost="draft-13.esni.defo.ie"
defoport="8413"
defohttpreq="GET /stats HTTP/1.1\\r\\nConnection: close\\r\\nHost: $defohost\\r\\n\\r\\n"

KEYFILE1=$CFGTOP/cadir/$clear_sni.priv
CERTFILE1=$CFGTOP/cadir/$clear_sni.crt
KEYFILE2=$CFGTOP/cadir/$httphost.priv
CERTFILE2=$CFGTOP/cadir/$httphost.crt


todo="l" 

# turn this on for a little more tracing
debugstr=" -debug "
# debugstr=""

# Turn this on to have a server trigger HRR from any 
# (reasonable:-) client
hrrstr=" -curves P-384 "
# hrrstr=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o cdgls -l cloudflare,defo,generate,localhost,server  -- "$@")
then
    # something went wrong, getopt will put out an error message for us
    exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
    case "$1" in
        -c|--cloudflare) todo="c" ;;
        -d|--defo) todo="d" ;;
        -g|--generate) todo="g" ;;
        -l|--localhost) todo="l" ;;
        -s|--server) todo="s" ;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done

if [ ! -f $BTOOL/bssl ]
then
    echo "You probably need to build $BTTOL/bssl - exiting"
    exit 1
fi

if [ ! -d $BFILES ]
then
    mkdir -p $BFILES
fi

if [[ "$todo" == "l" ]]
then
    if [ ! -f $CFGTOP/cadir/oe.csr ]
    then
        echo "Missing root CA public key - exiting"
        exit 4
    fi
    if [ ! -f $BFILES/os.ech ]
    then
        # make it
        if [ ! -f $ECHCONFIGILE ]
        then
            echo "Missing ECHConfig - exiting"
            exit 3
        fi
        cat $ECHCONFIGFILE | tail -2 | head -1 | base64 -d >$BFILES/os.ech
    fi
    echo "Running bssl s_client against localhost"
    ( echo -e $httpreq ; sleep 2) | $BTOOL/bssl s_client -connect localhost:8443 \
        -ech-config-list $BFILES/os.ech \
        -server-name $httphost $debugstr \
        -root-certs $CFGTOP/cadir/oe.csr
    res=$?
    if [[ "$res" != "0" ]]
    then
        echo "Error from bssl ($res)"
    fi
    exit $res
fi

if [[ "$todo" == "d" ]]
then
    # Grab a fresh ECHConfigList from the DNS
    # An example SVCB we get would be the catenation of the next 2 lines:
    #     00010000050042
    #     0040FE0D003C0200200020AE5F0D36FE5516C60322C21859CE390FD752F1A13C22E132F10C7FE032D54121000400010001000D636F7665722E6465666F2E69650000
    # The 2nd one is what we want and we'll grab it based purely on known
    # lengths for now - if defo.ie (me:-) change things we'll need to adjust
    ECH=`dig +short -t TYPE65 "_$defoport._https.$defohost" | \
        tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`
    if [[ "$ECH" == "" ]]
    then
        echo "Can't read ECHConfigList for $defohost:$defoport"
        exit 2
    fi
    ah_ech=${ECH:14}
    echo $ah_ech | xxd -p -r >$BFILES/defo.ech
    echo "Running bssl s_client against $defohost:$defoport"
    ( echo -e $defohttpreq ; sleep 2) | $BTOOL/bssl s_client \
        -connect $defohost:$defoport \
        -ech-config-list $BFILES/defo.ech \
        -server-name $defohost $debugstr
    res=$?
    if [[ "$res" != "0" ]]
    then
        echo "Error from bssl ($res)"
    fi
    exit $res
fi

if [[ "$todo" == "c" ]]
then
    # Grab a fresh ECHConfigList from the DNS
    # An example SVCB we get would be the catenation of the next 3 lines:
    # 0001000001000302683200040008A29F874FA29F884F00050048
    # 0046FE0D0042470020002049581350C8875700D27847CE0D826A25B5420B61AE7CAC9FE84D3259B05EAE690004000100010013636C6F7564666C6172652D65736E692E636F6D0000
    # 00060020260647000007000000000000A29F874F260647000007000000000000A29F884F
    # The middle one is what we want and we'll grab it based purely on known
    # lengths for now - if CF change things we'll need to adjust
    ECH=`dig +short -t TYPE65 $cfhost | tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`
    if [[ "$ECH" == "" ]]
    then
        echo "Can't read ECHConfigList for $cfhost"
        exit 2
    fi
    ah_ech=${ECH:52:144}
    echo $ah_ech | xxd -p -r >$BFILES/cf.ech
    echo "Running bssl s_client against cloudflare"
    ( echo -e $cfhttpreq ; sleep 2) | $BTOOL/bssl s_client \
        -connect $cfhost:443 \
        -ech-config-list $BFILES/cf.ech \
        -server-name $cfhost $debugstr
    res=$?
    if [[ "$res" != "0" ]]
    then
        echo "Error from bssl ($res)"
    fi
    exit $res
fi

if [[ "$todo" == "g" ]]
then
    echo "Generating ECH keys for a bssl s_server."
    $BTOOL/bssl generate-ech -out-ech-config-list $BFILES/bs.list \
        -out-ech-config $BFILES/bs.ech -out-private-key $BFILES/bs.key \
        -public-name example.com -config-id 222 -max-name-length 0
    res=$?
    # the b64 form is friendlier for echcli.sh
    cat $BFILES/bs.list | base64 -w0 >$BFILES/bs.pem
    if [[ "$res" != "0" ]]
    then
        echo "Error from bssl ($res)"
    fi
    exit $res
fi

# catch the ctrl-C used to stop the server and do any clean up needed
cleanup() {
    echo "Cleaning up after ctrl-c"
    exit 0
}
trap cleanup SIGINT

if [[ "$todo" == "s" ]]
then
    echo "Running bssl s_server with ECH keys"
    if [[ "$hrrstr" != "" ]]
    then
        echo "*** We're set to generate HRR ($hrrstr) ***"
    fi
    $BTOOL/bssl s_server \
        -accept 8443 \
        -key $KEYFILE2 -cert $CERTFILE2 \
        -ech-config $BFILES/bs.ech -ech-key $BFILES/bs.key \
        -www -loop $hrrstr $debugstr
    res=$?
    if [[ "$res" != "0" ]]
    then
        echo "Error from bssl ($res)"
    fi
    exit $res
fi

echo "Dunno how I got here... Odd."
exit 99
