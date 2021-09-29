#!/bin/bash

# set -x

# Do one of these things:
# 1. (g) generate ECH credentials for boringssl 
# 2. (l) run a boringssl s_client against localhost:8443 (default)
# 3. (c) run a boringssl s_client against cloudflare
# 4. (s) run a boringssl s_server on localhost:8443
# 5. (d) run a boringssl s_client against draft-13.esni.defo.ie:8413
# 6. (e) run a boringssl s_server accepting early data on localbost:8443
# 7. (E) run a boringssl s_client sending early data to localhost:8443

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
# to pick up correct .so's - maybe note 
: ${VERBOSE:="no"}

BTOOL="$BTOP/build/tool"
BFILES="$CFGTOP/bssl"
httphost=foo.example.com
httpreq="GET /stats HTTP/1.1\\r\\nConnection: close\\r\\nHost: $httphost\\r\\n\\r\\n"
cfhost="crypto.cloudflare.com"
cfhttpreq="GET / HTTP/1.1\\r\\nConnection: close\\r\\nHost: $cfhost\\r\\n\\r\\n"

defohost="draft-13.esni.defo.ie"
defoport="8413"
defohttpreq="GET /stats HTTP/1.1\\r\\nConnection: close\\r\\nHost: $defohost\\r\\n\\r\\n"

# KEYFILE1=$CFGTOP/cadir/$clear_sni.priv
# CERTFILE1=$CFGTOP/cadir/$clear_sni.crt
KEYFILE2=$CFGTOP/cadir/$httphost.priv
CERTFILE2=$CFGTOP/cadir/$httphost.crt
CHAINFILE2=$CFGTOP/cadir/$httphost.chain

if [ ! -f $CHAINFILE2 ]
then
    cat $CERTFILE2 $CFGTOP/cadir/oe.csr >$CHAINFILE2
fi

todo="l" 

# turn this on for a little more tracing
debugstr=" -debug "
# debugstr=""

# Turn HRR on via -R
hrrstr=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o ERcdegls -l early_cient,HRR,cloudflare,defo,early_server,generate,localhost,server  -- "$@")
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
        -e|--early_server) todo="e";;
        -E|--early_client) todo="E";;
        -g|--generate) todo="g" ;;
        -l|--localhost) todo="l" ;;
        -s|--server) todo="s" ;;
        -R|--HRR) hrrstr=" -curves P-384 ";;
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
    # for now the ECHConfiList is too "sticky" so if switching
    # (which is needed when swapping between openssl and boringssl
    # servers) then you need to remember to manually delete the
    # $BFILES/os.ech file. I may fix that later, but it's a rare
    # thing to do, so I'll leave it for the moment.
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
    if [[ "$VERBOSE" == "yes" ]]
    then
        echo "Command to run: " \
        " ( echo -e $httpreq ; sleep 2) | $BTOOL/bssl s_client -connect localhost:8443 " \
        "-ech-config-list $BFILES/os.ech " \
        "-server-name $httphost $debugstr " \
        "-root-certs $CFGTOP/cadir/oe.csr" 
    fi
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

if [[ "$todo" == "E" ]]
then
    if [ ! -f $CFGTOP/cadir/oe.csr ]
    then
        echo "Missing root CA public key - exiting"
        exit 4
    fi
    # for now the ECHConfiList is too "sticky" so if switching
    # (which is needed when swapping between openssl and boringssl
    # servers) then you need to remember to manually delete the
    # $BFILES/os.ech file. I may fix that later, but it's a rare
    # thing to do, so I'll leave it for the moment.
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
    if [ ! -f $CFGTOP/ed_file ]
    then
        cat >$CFGTOP/ed_file <<EOF
GET /index.html HTTP/1.1
Connection: close
Host: foo.example.com


EOF
    fi
    # we need to make 2 calls, 1 to get a session and 2nd to send early data
    echo "Running bssl s_client sending early_data to localhost"
    # remove old session
    rm -f $BFILES/bssl.sess
    # get session
    ( echo -e $httpreq ; sleep 2) | $BTOOL/bssl s_client -connect localhost:8443 \
        -session-out $BFILES/bssl.sess \
        -ech-config-list $BFILES/os.ech \
        -server-name $httphost $debugstr \
        -root-certs $CFGTOP/cadir/oe.csr
    res=$?
    if [[ "$res" != "0" ]]
    then
        echo "Error from 1st call to bssl establishing session ($res)"
        # don't exit - that's probably just an EOF error
    fi
    if [ ! -f $BFILES/bssl.sess ]
    then
        echo "1st call to bssl didn't establish session"
        exit 65
    else
        echo "1st call to bssl established session"
    fi
    sleep 2
    # 2nd to try send early data
    (echo -e "" ; sleep 2) | $BTOOL/bssl s_client -connect localhost:8443 \
        -session-in $BFILES/bssl.sess \
        -early-data @$CFGTOP/ed_file \
        -ech-config-list $BFILES/os.ech \
        -server-name $httphost $debugstr \
        -root-certs $CFGTOP/cadir/oe.csr
    res=$?
    if [[ "$res" != "0" ]]
    then
        echo "Error from 2nd call to bssl sending early data ($res)"
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
    # 
    # If httstr isn't empty we'll switch port to 8414 where a
    # P-384 only server runs
    if [[ "$hrrstr" != "" ]]
    then
        defoport="8414"
    fi
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
        -key $KEYFILE2 -cert $CHAINFILE2 \
        -ech-config $BFILES/bs.ech -ech-key $BFILES/bs.key \
        -www -loop $hrrstr $debugstr
    res=$?
    if [[ "$res" != "0" ]]
    then
        echo "Error from bssl ($res)"
    fi
    exit $res
fi

if [[ "$todo" == "e" ]]
then
    echo "Running bssl s_server with ECH keys allowing early_data"
    if [[ "$hrrstr" != "" ]]
    then
        echo "*** We're set to generate HRR ($hrrstr) ***"
    fi
    $BTOOL/bssl s_server \
        -early-data \
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

if [[ "$todo" == "e" ]]
then
    echo "Running bssl s_server with ECH keys allowing early_data"
    if [[ "$hrrstr" != "" ]]
    then
        echo "*** We're set to generate HRR ($hrrstr) ***"
    fi
    $BTOOL/bssl s_server \
        -early-data \
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
