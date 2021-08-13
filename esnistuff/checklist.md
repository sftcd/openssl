
# ECH test checklist

Note: Our ECH code is still not to really tested. This is a development branch
in a state of flux. Do not use this other than for testing.

For situations where a major change is made (e.g. the new branch that removes
ESNI code), a test checklist is as below. This is not a detailed test plan so
only really expected to be useful to the developer. There are a couple of 
such situtions coming up, so no harm to write this down.

## Checklist

1. Basic build is clean on dev machine
1. Ditto for clean build on other machine 
1. echcli.sh works against CF and/or a defo.ie server 

            $ cd $HOME/code/openssl/esnistuff
            $ ./echcli.sh # run vs. CF with sensible defaults
            $ ./echcli.sh -H draft-10.esni.defo.ie -p 10410
            $ ./echcli.sh -H draft-10.esni.defo.ie -p 8410 -f stats -d

1. echsrv.sh and echcli.sh work against one another on localhost

            $ cd $HOME/code/openssl/esnistuff
            $ ./echsvr.sh -d
            ... in another window or whatever
            ... and assuming your ECHConfig is is ``echconfig.pem``
            $ ./echcli.sh -d -p 8443 -s localhost -H foo.example.com -P `./pem2rr.sh -p echconfig.pem`
            ... and see how it goes
            ... for now, it works but does no ECH at all

1. curl builds and works against CF and defo.ie servers

            # defo.ie server's easier as we use a fixed key, for CF need to grab latest
            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            $ cd $HOME/code/curl
            $ src/curl --echconfig AEL+CgA+8QAgACCsEiogyYobxSGHLGd6uSDbuIbW05M41U37vsypEWdqZQAEAAEAAQAAAA1jb3Zlci5kZWZvLmllAAA= https://draft-10.esni.defo.ie:10410/ 
            ...stuff...
            SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
            ...stuff...

1. clean re-build of lighttpd, nginx and apache on dev machine
    - See [HOWTOs](HOWTOs) below.

1. localhost tests of of lighttpd, nginx and apache on dev machine

    - lighttpd:
            $ cd $HOME/code/openssl/esnistuff
            # you need to have done ``make keys`` sometime in this dir
            $ ./testlighttpd.sh
            ...stuff, server is listening on port 3443...
            $  ./echcli.sh -d -p 3443 -s localhost -H foo.example.com -c example.com -P `./pem2rr.sh -p echconfig-10.pem` -v -f index.html
            ...usual expected output...
    - nginx:
            $ ./testnginx-draft-10.sh
            ... stuff ...
            $ ./echcli.sh -p 5443 -s localhost -H foo.example.com  -P `./pem2rr.sh -p echconfig.pem`
            Running ./echcli.sh at 20210420-001300
            Assuming supplied ECH is RR value
            ./echcli.sh Summary: 
            Looks like it worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'

    - apache:
            $ cd $HOME/code/openssl/esnistuff
            $ ./testapache-draft-10.sh 
            Killing old httpd in process 303611
            Executing:  httpd -f apachemin.conf
            $ ./echcli.sh -p 9443 -s localhost -H foo.example.com  -P `./pem2rr.sh -p echconfig.pem` -f index.html
            Running ./echcli.sh at 20210421-143445
            Assuming supplied ECH is RR value
            ./echcli.sh Summary: 
            Looks like it worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'

1. deploy new code for ``s_server`` on defo.ie
1. lighttpd builds and deployed on defo.ie
1. nginx builds and deployed on defo.ie
1. apache builds and deployed on defo.ie
1. check 32-bit build

## List of build HOWTOs {#HOWTOs}

    - [curl](building-curl-openssl-with-ech.md)
    - [lighttpd](lighttpd.md)
    - [nginx](nginx.md)
    - [apache](apache2.md)

## List of services {#services}

    - [cloudflare](https://crypto.cloudflare.com/)
    - [``s_server``](https://draft-10.esni.defo.ie:8410/stats)
    - [lighttpd](https://draft-10.esni.defo.ie:9410/)
    - [nginx](https://draft-10.esni.defo.ie:10410/)
    - [apache](https://draft-10.esni.defo.ie:11410/)

## Useful command line snippets:
