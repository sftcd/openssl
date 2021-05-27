
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

That still needed a couple of tweaks to work, there're a couple of lines
in ``src/ssl_sock.c`` like this:

            #if SSL_OP_NO_TLSv1_3

but that causes a compile problem for some reason, not sure why, didn't really
look;-) ... because a simple change to 

            #ifdef SSL_OP_NO_TLSv1_3

works fine, at least in terms of building it.

## Minimal haproxy configuration

Still learning this so I'll follow [this guide](https://www.haproxy.com/blog/the-four-essential-sections-of-an-haproxy-configuration/)
and put my test script [here](testhaproxy.sh) with a minimal config [here](haproxymin.cfg).
That test script starts a lighttpd as needed to act as a back-end server.

Right now, I'm still just at the point of getting that working without yet having made
any ECH code changes. 

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

The ``SERVERUSED`` cookie was added by haproxy and the file served by lighttpd.

## ECH Configurtion in haproxy

TBD of course:-)

