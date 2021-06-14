# Notes on building/integrating with haproxy

These are from May/June 2021.

## Clone and build

I forked the [upstream repo](https://github.com/haproxy/haproxy) and made
an ``ECH-experimental`` branch, so then...

            $ git clone https://github.com/sftcd/haproxy.git
            $ git checkout ECH-experimental

To build that with a non-standard build of OpenSSL...

            $ make SSL_INC=$HOME/code/openssl/include/ \
                SSL_LIB=$HOME/code/openssl \
                TARGET=linux-glibc USE_OPENSSL=1

But we get lots of errors, as our bleeding-edge OpenSSL produces errors for
a whole pile of now-deprecated functions that are used by haproxy, so...

            $ make SSL_INC=$HOME/code/openssl/include/ \
                SSL_LIB=$HOME/code/openssl \
                TARGET=linux-glibc USE_OPENSSL=1 \
                DEFINE="-DOPENSSL_SUPPRESS_DEPRECATED"

In another case, to see what was happening in the build and turn off
optimisation (to make gdb "pleasant":-), I built using:

            $ make V=1 SSL_INC=$HOME/code/openssl/include/ \
                SSL_LIB=$HOME/code/openssl \
                TARGET=linux-glibc USE_OPENSSL=1 \
                DEFINE="-DOPENSSL_SUPPRESS_DEPRECATED \
                -DDEBUG -O0"

That still needed a couple of tweaks to work, there're a couple of lines
in ``src/ssl_sock.c`` like this:

            #if SSL_OP_NO_TLSv1_3

but that causes a compile problem for some reason, not sure why, didn't really
look;-) ... because a simple change to

            #ifdef SSL_OP_NO_TLSv1_3

All my code code changes, are protected using ``#ifndef OPENSSL_NO_ECH``

## Shared-mode ECH Configuration in haproxy

"Shared-mode" in haproxy terms is where the frontend is a TLS terminator
and does all the ECH work.

We're still learning haproxy configuration, so we'll follow [this
guide](https://www.haproxy.com/blog/the-four-essential-sections-of-an-haproxy-configuration/)
and put my test script [here](testhaproxy.sh) with a minimal config
[here](haproxymin.conf).  That test script starts a lighttpd as needed to act
as a back-end server.

A typical haproxy config will include lines like:

            bind :7443 ssl crt cadir/foo.example.com.pem

Our first plan (which we've implemented) is to simply extend that to add the
ECH keypair filename to that list, e.g.:

            bind :7443 ech echconfig.pem ssl crt cadir/foo.example.com.pem

Code for that is in ``src/cfgparse-ssl.c`` and the new code to read in the ECH
pem file is in ``src/ssl-sock.c``; the header files I changed were
``include/haproxy/openssl-compat.h`` and ``include/haproxy/listener-t.h``
but the changes to all those are pretty obvious and minimal for now.

So far, we've just done the minimum, we need to consider at least the following
extensions:

* periodic re-load of ECH key pair
* if the ech string names a directory then load all working PEM files from there
  (ignoring but logging those that fail)
* a "trial decryption" option, defaulting to "off"
* consider how to answer GREASE if we don't have an ECHConfig for that SNI

In addition, we need to consider the "scope" of the set of loaded ECH keys -
previously we've considered it fine to decrypt an ECH based on any loaded ECH
private key, (we do provide a way an application can manage that set for a
given ``SSL_CTX`` or ``SSL`` session). It's not clear if that makes sense for
haproxy where (at least in principle) different frontends might each need their
own fully independent sets of ECH keys.

## Test runs

I have ``/etc/hosts`` entries for example.com and foo.example.com
that map those to localhost.

Start our test server instances, with a lighttpd listening on localhost:3480
for cleartext HTTP and an haproxy instance listening on localhost:7443 for TLS
with ECH. (If there's already a lighttpd running a new one won't be started.)

```asciidoc
$ ./testhaproxy.sh
Lighttpd already running: stephen    13649    2556  0 00:44 ?        00:00:01 /home/stephen/code/lighttpd1.4-gstrauss/src/lighttpd -f /home/stephen/code/openssl/esnistuff/lighttpd4haproxymin.conf -m /home/stephen/code/lighttpd1.4-gstrauss/src/.libs
Executing:  /home/stephen/code/haproxy/haproxy -f /home/stephen/code/openssl/esnistuff/haproxymin.conf  -dV
$
```

A basic test using our [ECH-enabled curl](building-curl-openssl-with-ech.md):

            $ cd $HOME/code/curl
            $ src/curl -v --echconfig AEL+CgA+8QAgACCsEiogyYobxSGHLGd6uSDbuIbW05M41U37vsypEWdqZQAEAAEAAQAAAA1jb3Zlci5kZWZvLmllAAA= \
                --cacert ../openssl/esnistuff/cadir/oe.csr https://foo.example.com:7443/index.html
            *   Trying 127.0.1.3:7443...
            * Connected to foo.example.com (127.0.1.3) port 7443 (#0)
            * ALPN, offering http/1.1
            *  CAfile: ../openssl/esnistuff/cadir/oe.csr
            * ECH: found STRING_ECH_CONFIG:
            *  AEL+CgA+8QAgACCsEiogyYobxSGHLGd6uSDbuIbW05M41U37vsypEWdqZQAEAAEAAQAAAA1jb3Zlci5kZWZvLmllAAA=
            * ECH: will use hostname 'foo.example.com' as ECH inner name
              ECH: will use string 'splodge.local' as ECH outer name
            * ECH: rv 0 from SSL_ech_server_name()
            * ECH: rv 1 from SSL_ech_add() [OK]
            * ECH: nechs 1 from SSL_ech_add() [OK]
            * ossl_connect_step1() returning CURLE_OK
            * ossl_connect_step2() starting
            * TLSv1.0 (OUT), TLS header, Certificate Status (22):
            * TLSv1.3 (OUT), TLS handshake, Client hello (1):
            * SSL_connect() returned -1, detail 2
            * ossl_connect_step2() starting
            * TLSv1.2 (IN), TLS header, Certificate Status (22):
            * TLSv1.3 (IN), TLS handshake, Server hello (2):
            * TLSv1.2 (IN), TLS header, Finished (20):
            * TLSv1.2 (IN), TLS header, Unknown (23):
            * TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
            * TLSv1.2 (IN), TLS header, Unknown (23):
            * TLSv1.3 (IN), TLS handshake, Certificate (11):
            * TLSv1.2 (IN), TLS header, Unknown (23):
            * TLSv1.3 (IN), TLS handshake, CERT verify (15):
            * TLSv1.2 (IN), TLS header, Unknown (23):
            * TLSv1.3 (IN), TLS handshake, Finished (20):
            * TLSv1.2 (OUT), TLS header, Finished (20):
            * TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
            * TLSv1.2 (OUT), TLS header, Unknown (23):
            * TLSv1.3 (OUT), TLS handshake, Finished (20):
            * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
            * ALPN, server did not agree to a protocol
            * ossl_connect_step2() returning CURLE_OK
            * Server certificate:
            *  subject: C=IE; ST=Laighin; O=openssl-esni; CN=foo.example.com
            *  start date: Apr 29 13:17:33 2021 GMT
            *  expire date: Apr 27 13:17:33 2031 GMT
            *  subjectAltName: host "foo.example.com" matched cert's "foo.example.com"
            *  issuer: C=IE; ST=Laighin; O=openssl-esni; CN=ca
            *  SSL certificate verify ok.
            * TLSv1.2 (OUT), TLS header, Unknown (23):
            > GET /index.html HTTP/1.1
            > Host: foo.example.com:7443
            > User-Agent: curl/7.77.0-DEV
            > Accept: */*
            >
            * TLSv1.2 (IN), TLS header, Unknown (23):
            * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
            * TLSv1.2 (IN), TLS header, Unknown (23):
            * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
            * old SSL session ID is stale, removing
            * TLSv1.2 (IN), TLS header, Unknown (23):
            * Mark bundle as not supporting multiuse
            < HTTP/1.1 200 OK
            < content-type: text/html
            < etag: "2613545160"
            < last-modified: Thu, 29 Apr 2021 13:13:28 GMT
            < content-length: 459
            < accept-ranges: bytes
            < date: Thu, 03 Jun 2021 20:44:44 GMT

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

The ``SERVERUSED`` cookie was added by haproxy and the file served by lighttpd,
as can be seen from the lighttpd logs. That did use ECH even if it's not
visible. But we can also use our test client script (that uses ``s_client``) to
make that visible:

            $ cd $HOME/code/openssl/esnistuff
            $ ./echcli.sh -s localhost -H foo.example.com -p 7443 -P `./pem2rr.sh echconfig.pem` -f index.html
            Running ./echcli.sh at 20210602-201418
            Assuming supplied ECH is RR value
            ./echcli.sh Summary:
            Looks like it worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $

[testhaproxy.sh](testhaproxy.sh) does pretty minimal logging in
``$HOME/code/openssl/esnistuff/haproxy/logs/haproxy.log`` but you
need to add some stanzas to ``/etc/rsyslog.conf`` to get that.
(Absent those, the test script will, for now, complain and exit.)

## Named Frontend/Backend Setups

There are a pile of variations possible, and they're hard to describe accurately
when chatting with people, so we'll name and document them like this:

            N. setup-name: Client <--[prot]--> frontend <--[prot]--> Backend

Where "N" is a number, "setup-name" is some catchy title we use just for ease
of reference, "client" is ``curl`` or ``s_client``, "frontend" is haproxy in
all cases so we'll just note the relevant port number used by our test setup,
and as the "backend" is also always lighttpd, we'll do the same for that.
Finally, "prot" is some string describing the protocol options on that hop.

With that our first and most basic setup is:

            1. ECH-front: Client <--[TLS+ECH]--> :7443 <--[Plaintext HTTP]--> :3480

The second one just turns on TLS, via two entirely independent TLS sessions, with no ECH to the backend:

            2. Two-TLS: Client <--[TLS+ECH]--> :7444 <--[other-TLS]--> :3481

The third has one TLS session from the client to backend, with the frontend
just using the (outer) SNI for e.g. routing, if at all, and so that the
frontend doesn't get to see the plaintext HTTP traffic. This isn't that
interesting for us (other than to understand how to set it up), but is on the
path to one we do want. (In the actual configuration we also have a backend
listener at :3483 to handle the case where an unknown (outer) SNI was
seen.)

            3. One-TLS: Client <--[TLS]--> :7445 <--[same-TLS]--> :3482

The three setups above work, it may be a while before we get a working version
of...

The fourth one we'll want (but are far from having) will be where we really
have a split-mode ECH, with the same TLS session between client and backend but
where the frontend did decrypt the ECH and just pass on the inner CH to the
backend, but where the frontend doesn't get to see the plaintext HTTP traffic.
(As in the previous case, we have another backend listener at :3485 to handle
the case of both an outer SNI and a failure to decrypt an ECH.)

            4. Split-mode: Client <--[TLS+ECH]--> :7446 <--[inner-CH]--> :3484

Note wrt split-mode: we're not yet even sure whether or not we need some other
wrapping around the TLS session between the frontend and backend here - that
could be needed a) for some kind of cover traffic or b) in order to enable the
backend to signal ECH success/acceptance to the client.

A fifth option that we don't plan to investigate but that may be worth naming
is where we have two separate TLS sessions both of which independently use ECH.
If that did prove useful, it'd probably be fairly easy to do.

            5. Two-ECH: Client <--[TLS+ECH]--> frontend <--[other-TLS+ECH]-->
               backend

## Split-Mode in More Detail

As a reminder "split-mode" in haproxy terms is where the frontend only
attempts ECH decryption, and all the rest of the TLS handling happens
in the backend.

Our split-mode needs a bit more detail before we can figure out what code is
needed where. We need to consider GREASE and failed-decryption, as well as
success. And then there's HRR, which is always a mystery;-)

### Code 

It's looking like the ``mode tcp`` code that detects an (outer) SNI is
in ``src/payload.c:smp_fetch_ssl_hello_sni``.

For a 1st attempt: I'll think about whether detecting and decrypting
an ECH in there might work.

### Nominal Messaging

The basic TLS1.3 1RTT handshake is as shown below, (from
[rfc8446bis](https://datatracker.ietf.org/doc/draft-ietf-tls-rfc8446bis/), both
for reference and so I can easily cut'n'paste text.

```asciidoc
       Client                                              Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*         -------->
                                                       ServerHello  ^ Key
                                                      + key_share*  | Exch
                                                 + pre_shared_key*  v
                                             {EncryptedExtensions}  ^  Server
                                             {CertificateRequest*}  v  Params
                                                    {Certificate*}  ^
                                              {CertificateVerify*}  | Auth
                                                        {Finished}  v
                                 <--------     [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}                -------->
       [Application Data]        <------->      [Application Data]
```

When using ECH in Split-mode, following the current
[draft-10](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/10/) of the
spec, we want to see the following flows in the nominal case, where the
frontend decrypts the outer ClientHello.  Note: we expect some minor changes in
upcoming ECH draft specs, but they likely won't affect the flows, only message
syntax and crypto calculations.

Notes:

* One important thing to note here is that the frontend only processes the
  OuterClientHello and after that (has worked), the frontend acts as a
  passthrough - in ``mode tcp`` in haproxy terms. The frontend also never sees
  the e.g. HTTP cleartext traffic, so isn't really in ``mode http`` either - it
  seems a new mode may be needed.
* One could argue that there's a need to be able to support cover traffic from
  frontend to backend and to have that, and subsequent traffic, use an ecrypted
  tunnel between frontend and backend. Otherwise a network observer who can see
  traffic between client and frontend, and also between frontend and backend, can
  easily defeat ECH as it'll simply see the result of ECH decryption. (That
  wouldn't be needed in all network setups, but in some.)
* There are likely to be some additional octets that need to be sent from
  frontend to backend, that would not be present in a "pure" client to backend
  TLS session. Those may be needed so that the backend has the full transcript
  (incl. outer CH) available to it for cryptographic calculations, either for the
  ServerHello ECH-acceptance signal, or for Finished message calculations.
  (Details there are liable to change though, based on recent discussion.)

```asciidoc
       Client                    Frontend                 Backend

Key  ^ OuterClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     | + ECH*
     v + pre_shared_key*   --->
                                ^ InnerClientHello
                                | + key_share*
                                | + signature_algorithms*
                                | + psk_key_exchange_modes*
                                | + ech-is-inner*
                                v + pre_shared_key*   ----------->

                                            ServerHello+ECH-accept  ^ Key
                                                      + key_share*  | Exch
                                                 + pre_shared_key*  v
                                             {EncryptedExtensions}  ^  Server
                                             {CertificateRequest*}  v  Params
                                                    {Certificate*}  ^
                                              {CertificateVerify*}  | Auth
                                                        {Finished}  v
                                 <--------     [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}                -------->
       [Application Data]        <------->      [Application Data]
```

### GREASE and Failed ECH Decryption

A GREASEd ClientHello contains an ECH extension with essentially random bits
but in the correct format. Doing this has two justifications - so as to
exercise code points as usual with GREASing, but also in this case to increase
the cost of blocking all ECH, if a sufficientl number of clients emit GREASEd
ECH even when not actually doing ECH.

For GREASEd ECH a server could just ignore the value, however, a client might
also have used an outdated ECHConfig and have actually attempted ECH. In that
case the server can't really distinguish the failed decryption from a GREASEd
ECH, so the spec calls for the server to respond with an ECH for the client
that has the up-to-date ECHConfig for that frontend.

If ECH decoding simply fails, then failing the entire session is correct. (Or
whatever else haproxy does today with such cases.)

One option (shown below, but not clearl what we want), might be for the
frontend to simply pass along the outer CH in the event of failed ECH
decryption of any kind, and to expect the backend to include the correct
ECHConfig in it's first flight. That implies that the backend is ECH-aware but
we already need that for the ServerHello ECH-acceptance signal. (And that's
probably a new configuration item for the backend servers - to load an
ECHConfig rather than an ECH key pair when acting only as a backend.)

```asciidoc
       Client                    Frontend                 Backend

Key  ^ OuterClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     | + ECH*
     v + pre_shared_key*   --->
                                ^ OuterClientHello
                                | + key_share*
                                | + signature_algorithms*
                                | + psk_key_exchange_modes*
                                | + ECH*
                                v + pre_shared_key*   ----------->

                                                       ServerHello  ^ Key
                                                      + key_share*  | Exch
                                                 + pre_shared_key*  v
                                             {EncryptedExtensions}  ^  Server
                                             {CertificateRequest*}  v  Params
                                                    {Certificate*}  ^
                                              {CertificateVerify*}  | Auth
                                                      {ECHConfig*}  |
                                                        {Finished}  v
                                 <--------     [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}                -------->
       [Application Data]        <------->      [Application Data]
```

### HRR - Hello Request Retry

HRR can at least notionally happen if the set of key shares in the inner CH
isn't acceptable to the backend, but all else is well. The TLS WG are still
considering how to handle HRR for ECH, so this is likely to change in the short
term. HRR+ECH is also not currently supported in our OpenSSL fork.

For ease of reference the usual HRR flow (without ECH) is as follows:

```asciidoc
         Client                                               Server

         ClientHello
         + key_share             -------->
                                                   HelloRetryRequest
                                 <--------               + key_share
         ClientHello
         + key_share             -------->
                                                         ServerHello
                                                         + key_share
                                               {EncryptedExtensions}
                                               {CertificateRequest*}
                                                      {Certificate*}
                                                {CertificateVerify*}
                                                          {Finished}
                                 <--------       [Application Data*]
         {Certificate*}
         {CertificateVerify*}
         {Finished}              -------->
```

### Split-mode state of play

We've added a new external API for split-mode (``SSL_CTX_ech_raw_decrypt``) that
takes the inbound ClientHello, and, if that contains an ECH, attempts decryption.
That API also returns the outer and inner SNI (if present) so that routing
can happen as needed.

So far, we've not figured how to properly handle configuring that, nor how to
handle injecting the decrypted "inner" ClientHello when decryption succeeds.
So it's a work-in-progress still.

## Summary

We've done a basic form of Shared-mode ECH-enabling haproxy, there's still a 
TODO: list.

* There are leaks on exit - check if that's some effect of threads by running
  with vanilla OpenSSL libraries
* More analysis of split-mode ECH.

