
# Notes on building/integrating with haproxy

These are from May 2021.

## Clone and build

I forked the [upstream repo](https://github.com/haproxy/haproxy) and made
an ``ECH-experimental`` branch, so then...

            $ git clone https://github.com/sftcd/haproxy.git
            $ git checkout ECH-experimental

To build that with a non-standard build of OpenSSL...

            $ make SSL_INC=$HOME/code/openssl/include/ SSL_LIB=$HOME/code/openssl TARGET=linux-glibc USE_OPENSSL=1

But we get lots of errors, as our bleeding-edge OpenSSL produces errors for
a whole pile of now-deprecated functions that are used by haproxy, so...

            $ make SSL_INC=$HOME/code/openssl/include/ SSL_LIB=$HOME/code/openssl TARGET=linux-glibc USE_OPENSSL=1 DEFINE="-DOPENSSL_SUPPRESS_DEPRECATED"

In another case, to see what was happening in the build and turn off optimisation (to make gdb "pleasant":-), I built using:

            $ make V=1 SSL_INC=$HOME/code/openssl/include/ SSL_LIB=$HOME/code/openssl TARGET=linux-glibc USE_OPENSSL=1 DEFINE="-DOPENSSL_SUPPRESS_DEPRECATED -DDEBUG -O0"

That still needed a couple of tweaks to work, there're a couple of lines
in ``src/ssl_sock.c`` like this:

            #if SSL_OP_NO_TLSv1_3

but that causes a compile problem for some reason, not sure why, didn't really
look;-) ... because a simple change to 

            #ifdef SSL_OP_NO_TLSv1_3

All my code code changes, are protected using ``#ifndef OPENSSL_NO_ECH``

## Minimal haproxy configuration

Still learning this so I'll follow [this guide](https://www.haproxy.com/blog/the-four-essential-sections-of-an-haproxy-configuration/)
and put my test script [here](testhaproxy.sh) with a minimal config [here](haproxymin.conf).
That test script starts a lighttpd as needed to act as a back-end server.

A typical haproxy config will include lines like:

            bind :7443 ssl crt cadir/foo.example.com.pem 

Our first plan is to simply extend that to add the ECH keypair filename
to that list, e.g.:

            bind :7443 ech echconfig.pem ssl crt cadir/foo.example.com.pem

Code for that is in ``src/cfgparse-ssl.c`` and the new code to read in the ECH
pem file is in ``src/ssl-sock.c``; the header files I changed were
``include/haproxy/openssl-compat.h`` and ``include/haproxy/listener-t.h``
but the changes to all those are pretty obvious and minimal for now.

## Test runs

I have ``/etc/hosts`` entries for example.com and foo.example.com
that map those to localhost.

Start our test server instances, with a lighttpd listening on localhost:3480 for cleartext
HTTP and an haproxy instance listening on localhost:7443 for TLS with ECH. (If there's
already a lighttpd running a new one won't be started.)

            $ ./testhaproxy.sh
            Lighttpd already running: stephen    13649    2556  0 00:44 ?        00:00:01 /home/stephen/code/lighttpd1.4-gstrauss/src/lighttpd -f /home/stephen/code/openssl/esnistuff/lighttpd4haproxymin.conf -m /home/stephen/code/lighttpd1.4-gstrauss/src/.libs
            Executing:  /home/stephen/code/haproxy/haproxy -f /home/stephen/code/openssl/esnistuff/haproxymin.conf  -dV
            $

A basic test to see if we're up and running is to just use curl:

            $ curl -v --cacert cadir/oe.csr https://foo.example.com:7443/index.html
            *   Trying 127.0.1.3:7443...
            * TCP_NODELAY set
            * Connected to foo.example.com (127.0.1.3) port 7443 (#0)
            * ALPN, offering h2
            * ALPN, offering http/1.1
            * successfully set certificate verify locations:
            *   CAfile: cadir/oe.csr
                CApath: /etc/ssl/certs
            * TLSv1.3 (OUT), TLS handshake, Client hello (1):
            * TLSv1.3 (IN), TLS handshake, Server hello (2):
            * TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
            * TLSv1.3 (IN), TLS handshake, Certificate (11):
            * TLSv1.3 (IN), TLS handshake, CERT verify (15):
            * TLSv1.3 (IN), TLS handshake, Finished (20):
            * TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
            * TLSv1.3 (OUT), TLS handshake, Finished (20):
            * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
            * ALPN, server did not agree to a protocol
            * Server certificate:
            *  subject: C=IE; ST=Laighin; O=openssl-esni; CN=foo.example.com
            *  start date: Apr 29 13:17:33 2021 GMT
            *  expire date: Apr 27 13:17:33 2031 GMT
            *  subjectAltName: host "foo.example.com" matched cert's "foo.example.com"
            *  issuer: C=IE; ST=Laighin; O=openssl-esni; CN=ca
            *  SSL certificate verify ok.
            > GET /index.html HTTP/1.1
            > Host: foo.example.com:7443
            > User-Agent: curl/7.68.0
            > Accept: */*
            > 
            * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
            * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
            * old SSL session ID is stale, removing
            * Mark bundle as not supporting multiuse
            < HTTP/1.1 200 OK
            < content-type: text/html
            < etag: "2613545160"
            < last-modified: Thu, 29 Apr 2021 13:13:28 GMT
            < content-length: 459
            < accept-ranges: bytes
            < date: Thu, 27 May 2021 22:21:13 GMT
            < server: lighttpd/1.4.60-devel-lighttpd-1.4.53-1098-g66d95722
            < set-cookie: SERVERUSED=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/
            < cache-control: private
            < 
            
            <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
                "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
            <html xmlns="http://www.w3.org/1999/xhtml">
            <head>
            <title>Lighttpd top page.</title>
            </head>
            <!-- Background white, links blue (unvisited), navy (visited), red
            (active) -->
            <body bgcolor="#FFFFFF" text="#000000" link="#0000FF"
            vlink="#000080" alink="#FF0000">
            <p>This is the pretty dumb top page for testing. </p>
            
            </body>
            </html>
            
            * Connection #0 to host foo.example.com left intact

The ``SERVERUSED`` cookie was added by haproxy and the file served by lighttpd, as can
be seen from the lighttpd logs. That did use ECH even if it's not visible. But we can
also use our test client script (that uses ``s_client``) to make that visible:

            $ ./echcli.sh -s localhost -H foo.example.com -p 7443 -P `./pem2rr.sh echconfig.pem` -f index.html
            Running ./echcli.sh at 20210602-201418
            Assuming supplied ECH is RR value
            ./echcli.sh Summary: 
            Looks like it worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $

## Summary

We've done a most basic form of ECH-enabling haproxy, there's still a TODO: list. 

- There are leaks on exit - check if that's some effect of threads by running with
  vanilla OpenSSL libraries
- Extend the ECH config - if the string names a directory then load all PEM files
  from there etc.
- (Much later) think about split-mode ECH

