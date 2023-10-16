# Notes on building/integrating with haproxy

## October 2023

- 20231016 - rebased with upstream
- 20231016 - some fixes for CI issues, changed from ``#ifdndef OPENSSL_NO_ECH`` as 
  guard to ``#ifdef USE_ECH``

You need my haproxy fork and to use the ``ECH-experimental``
branch from that, so...

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/haproxy.git
            $ cd haproxy
            $ git checkout ECH-experimental

To build that with our ECH-enabled build of OpenSSL...

            export OSSL=$HOME/code/openssl
            export LD_LIBRARY_PATH=$OSSL
            make V=1  SSL_INC=$OSSL/include/ SSL_LIB=$OSSL TARGET=linux-glibc USE_OPENSSL=1 \
                DEFINE="-DOPENSSL_SUPPRESS_DEPRECATED -DDEBUG -O0 -DUSE_ECH"

Testing:

            $ ./testhaproxy.sh
            ...stuff... # hit ctrl-C to exit haproxy, killall lighttpd to kill backend

            $ # split-mode test
            $ ./echcli.sh -s localhost  -H foo.example.com -p 7446 -P `./pem2rr.sh d13.pem` -f index.html
            Running ./echcli.sh at 20230315-154634
            Assuming supplied ECH is encoded ECHConfigList or SVCB
            ./echcli.sh Summary: 
            Looks like ECH worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $ # shared-mode test
            $ ./echcli.sh -s localhost  -H foo.example.com -p 7445 -P `./pem2rr.sh d13.pem` -f index.html
            Running ./echcli.sh at 20230315-154900
            Assuming supplied ECH is encoded ECHConfigList or SVCB
            ./echcli.sh Summary: 
            Looks like ECH worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $
            $ 

That seems to work ok, but with very (very:-) little testing! 

## August 2023

Both HRR and early data working now. Switched to stderr based logging.

Next up is to figure out how to reload ECH keys without restarting haproxy.
TLS certificate/key reloading via socket-API/CLI is described
[here](https://docs.haproxy.org/dev/management.html#9.3). We'll want to try
figure out something similar for ECH keys, or to figure out an equivalent for
the LUA interface.

## May 2023 rebuild...

I just updated the current code (i.e. without rebasing with upstream) to
handle recent ECH API tweaks.

## March 2023 rebase...

These are the updated notes from 20230315 for haproxy with ECH.
Will test on ubuntu 20.10, with latest haproxy code.

You need my haproxy fork and to use the ``ECH-experimental``
branch from that, so...

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/haproxy.git
            $ cd haproxy
            $ git checkout ECH-experimental

To build that with a non-standard build of OpenSSL...

            $ make SSL_INC=$HOME/code/openssl/include/ \
                SSL_LIB=$HOME/code/openssl \
                TARGET=linux-glibc USE_OPENSSL=1

Testing:

            $ ./testhaproxy.sh
            ...stuff... # hit ctrl-C to exit haproxy, killall lighttpd to kill backend

            $ # split-mode test
            $ ./echcli.sh -s localhost  -H foo.example.com -p 7446 -P `./pem2rr.sh d13.pem` -f index.html
            Running ./echcli.sh at 20230315-154634
            Assuming supplied ECH is encoded ECHConfigList or SVCB
            ./echcli.sh Summary: 
            Looks like ECH worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $ # shared-mode test
            $ ./echcli.sh -s localhost  -H foo.example.com -p 7445 -P `./pem2rr.sh d13.pem` -f index.html
            Running ./echcli.sh at 20230315-154900
            Assuming supplied ECH is encoded ECHConfigList or SVCB
            ./echcli.sh Summary: 
            Looks like ECH worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $
            $ 

That seemed to work ok, but with very (very:-) little testing! 

## Sep 2021 Notes

These notes are from September 2021.

Our integration with haproxy is more experimental that e.g. those for web
servers. There are a few reasons for this:

- haproxy doesn't read from disk after initial startup, so we can't re-use
  code for periodically reloading ECH keys - what needs doing is clear (just
  replicate what's done for TLS server keys) but very specific to haproxy so
  we won't invest effort there for now.
- we do support split-mode (our mail reason for integrating with haproxy) but
  don't currently support HRR with split-mode - haproxy seems to have a
  current limitation that it can only parse the first client message, so
  decrypting the 2nd ClientHello (CH) that follows a HRR isn't possible for now.
  Addressing this would likely require the kind of major surgery that it'd
  only make sense be carried out by the upstream devs. (We have described
  the issue to them.)
- some additional changes are needed to properly handle ``early_data`` in
  split-mode - we need to inject back the inner CH without disturbing
  any other data in haproxy's buffers (right now, we overwrite the relevant
  buffer with the inner CH). This is probably fairly easily fixable so we
  may address it shortly.
- One could argue that there's a need to be able to support cover traffic from
  frontend to backend and to have that, and subsequent traffic, use an encrypted
  tunnel between frontend and backend. Otherwise a network observer who can see
  traffic between client and frontend, and also between frontend and backend,
  can easily defeat ECH as it'll simply see the result of ECH decryption. (That
  wouldn't be needed in all network setups, but in some.)
- There were (at one stage) leaks on exit - check if that's some effect of
  threads by running with vanilla OpenSSL libraries. We need to re-test for
  those.

## Clone and build

First you need my ECH-enabled OpenSSL fork:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl.git
            $ cd openssl
            $ git checkout ECH-draft-13a
            $ ./config
            ...
            $ make
            ...

Next you need my fork of the [upstream haproxy
repo](https://github.com/haproxy/haproxy) and to use the ``ECH-experimental``
branch from that, so...

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/haproxy.git
            $ cd haproxy
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

All my code code changes, are protected using ``#ifndef OPENSSL_NO_ECH``

## Shared-mode

"Shared-mode" in haproxy terms is where the frontend is a TLS terminator and
does all the ECH work.

We followed [this haprox config
guide](https://www.haproxy.com/blog/the-four-essential-sections-of-an-haproxy-configuration/)
and my test script is [here](testhaproxy.sh) with a minimal config
[here](haproxymin.conf).  That test script starts a lighttpd as needed to act
as a back-end server. (You'll need to manually kill that when done with it.)

A typical haproxy config for terminating TLS will include lines like:

            bind :7443 ssl crt cadir/foo.example.com.pem

We've simply extended that to add the ECH keypair filename to that line, e.g.:

            bind :7443 ech d13.pem ssl crt cadir/foo.example.com.pem

Code for that is in ``src/cfgparse-ssl.c`` and the new code to read in the ECH
pem file is in ``src/ssl-sock.c``; the header files I changed were
``include/haproxy/openssl-compat.h`` and ``include/haproxy/listener-t.h`` but
the changes to all those are pretty obvious and minimal for now.

So far, we've just done the minimum, if going further, we would consider at
least the following features for shared-mode (or generally):

* a "trial decryption" option, defaulting to "off"
* periodic rekeying of ECH keys

In addition, we need to consider the "scope" of the set of loaded ECH keys -
previously we've considered it fine to decrypt an ECH based on any loaded ECH
private key, (we do provide a way an application can manage that set for a
given ``SSL_CTX`` or ``SSL`` session). It's not clear if that makes sense for
haproxy where (at least in principle) different frontends might each need their
own fully independent sets of ECH keys.

## Split-mode 

The model for split-mode is that haproxy only does ECH decryption - if
decryption fails or no ECH extension is present, then haproxy will forward to a
backend that has the private key of the ``ECHConfig.public_name``. If
decryption works, then haproxy will forward the recovered plaintext, which will
be the inner CH, routing the request based on the SNI from that inner CH. 

We added an external API for haproxy to use in split-mode
(``SSL_CTX_ech_raw_decrypt``) that takes the putative outer CH, and, if that
containr an ECH, attempts decryption. That API also returns the outer and inner
SNI (if present) so that routing can happen as needed. 

In haproxy, we added a ``tcp-request ech-decrypt`` keyword to allow configuring
the PEM file with the ECH key pair.  When so configured, the existing
``smp_fetch_ssl_hello_sni`` (which handles SNI based routing) is modified to
first call ``attempt_split_ech``.  ``attempt_split_ech`` will try decrypt and
setup routing based on the inner or outer SNI values found as appropriate.
If decryption succeeds, then the inner CH is spliced into the buffer that
used hold the outer CH and processing continues as normal. 

Notes:

* ``early_data`` handling - we still need to test and likely fix how we splice
  the inner CH into the haproxy buffer so that we don't e.g. throw away any
  ``early_data``.

## haproxy ECH tests

As an aside: I have ``/etc/hosts`` entries for example.com and foo.example.com
that map those to localhost.

The [testhaproxy.sh](testhaproxy.sh) script starts servers and optionally runs
clients against those.  This starts a lighttpd listening on localhost:3480 and
other ports (see [lighttpd4haproxymin.conf](lighttpd4haproxymin.conf)) an
haproxy instance listening on localhost:7443 and other front-ends for TLS with
ECH. (If there's already a lighttpd running a new one won't be started.) The
script also pesters you if the changes needed for some haproxy logging haven't
been made to the ``/etc/rsyslog.conf`` file, in which case, it'll tell you what
changes you need to make manually.

[testhaproxy.sh](testhaproxy.sh) takes one optional command line argument (the
string "client"). If not supplied the script starts lighttpd if need, and a
haproxy instance runs in the foreground. If the "client" argument is rovided,
both servers are run in the background and various client tests (both shared-
and split-mode) are run against those.

[testhaproxy.sh](testhaproxy.sh) does pretty minimal logging in
``$HOME/code/openssl/esnistuff/haproxy/logs/haproxy.log`` but you
need to add some stanzas to ``/etc/rsyslog.conf`` to get that.
(Absent those, the test script will, for now, complain and exit.)

A ``SERVERUSED`` cookie is added by haproxy in these configurations and the
file served by lighttpd, as can be seen from the lighttpd logs. 

# Naming different frontend/backend setups

Here's some terminology we use when talking about shared- or split-mode and
haproxy configurations.  

We'll name and document them like this:

            N. setup-name: Client <--[prot]--> frontend <--[prot]--> Backend

Where "N" is a number, "setup-name" is some catchy title we use just for ease
of reference, "client" is ``curl`` or ``s_client``, "frontend" is haproxy in
all cases so we'll just note the relevant port number used by our test setup,
and as the "backend" is also always lighttpd, we'll do the same for that.
Finally, "prot" is some string describing the protocol options on that hop.

With that our first and most basic setup is:

            1. ECH-front: Client <--[TLS+ECH]--> :7443 <--[Plaintext HTTP]--> :3480

The second one just turns on TLS, via two entirely independent TLS sessions,
with no ECH to the backend:

            2. Two-TLS: Client <--[TLS+ECH]--> :7444 <--[other-TLS]--> :3481

The third has one TLS session from the client to backend, with the frontend
just using the (outer) SNI for e.g. routing, if at all, and so that the
frontend doesn't get to see the plaintext HTTP traffic. This isn't that
interesting for us (other than to understand how to set it up), but is on the
path to one we do want. (In the actual configuration we also have a backend
listener at :3483 to handle the case where an unknown (outer) SNI was seen.)

            3. One-TLS: Client <--[TLS]--> :7445 <--[same-TLS]--> :3482

The fourth is where use split-mode, with the same TLS session between client
and backend but where the frontend did decrypt the ECH and just pass on the
inner CH to the backend, but where the frontend doesn't get to see the
plaintext HTTP traffic.  (As in the previous case, we have another backend
listener at :3485 to handle the case of both an outer SNI and a failure to
decrypt an ECH.)

            4. Split-mode: Client <--[TLS+ECH]--> :7446 <--[inner-CH]--> :3484

A fifth option that we don't plan to investigate but that may be worth naming
is where we have two separate TLS sessions both of which independently use ECH.
If that did prove useful, it'd probably be fairly easy to do.

            5. Two-ECH: Client <--[TLS+ECH]--> frontend <--[other-TLS+ECH]--> backend

## Running haproxy split-mode 

The idea is to configure "routes" for both in the frontend. With the example
configuration below, assuming "foo.example.com" is the inner SNI and
"example.com" is the outer SNI (or ``ECHConfig.public_name``) then if
decryption works, we'll route to the "foo" backend on port 3484, whereas if it
fails (or no ECH is present etc.) then we'll route to the "eg" server on port
3485. 

            frontend Split-mode
                mode tcp
                option tcplog
                bind :7446 
                use_backend 3484
            backend 3484
                mode tcp
                # next 2 lines needed to get switching on (outer) SNI to
                # work, not sure why
                tcp-request inspect-delay 5s
                tcp-request content accept if { req_ssl_hello_type 1 }
                tcp-request ech-decrypt d13.pem
                use-server foo if { req.ssl_sni -i foo.example.com }
                use-server eg if { req.ssl_sni -i example.com }
                server eg 127.0.3.4:3485 
                server foo 127.0.3.4:3484 
                server default 127.0.3.4:3485

If the above configuration is in a file called ``sm.cfg`` then haproxy can be
started via a command like:

            $ LD_LIBRARY_PATH=$HOME/code/openssl ./haproxy -f sm.cfg -dV 

We can then start the non-ECH-enabled backend for foo.example.com listening on
port 3484 as follows:

            $ cd $HOME/code/openssl/esnistuff
            $ ../apps/openssl s_server -msg -trace  -tlsextdebug  \
                -key cadir/example.com.priv \
                -cert cadir/example.com.crt \
                -key2 cadir/foo.example.com.priv \
                -cert2 cadir/foo.example.com.crt  \
                -CApath cadir/  \
                -port 3484  -tls1_3  -servername foo.example.com

Equivalently, it's ok if the backend server on port 3484 is also ECH-enabled
itself and has a copy of the ECH key pair. If that's the desired setup, one of
our test scripts is also usable:

            $ cd $HOME/code/openssl/esnistuff
            $ ./echsvr.sh -p 3484

Running a server for example.com on port 3485 is done similarly.

For the client, we do the following to use ECH and send our request to port
7446 where haproxy is listening:

            $ cd $HOME/code/openssl/esnistuff
            $ ./echcli.sh -s localhost  -H foo.example.com -p 7446 \
                -P `./pem2rr.sh echconfig.pem` -f index.html -N -c something-else
            Running ./echcli.sh at 20210615-191012
            Assuming supplied ECH is RR value
            ./echcli.sh Summary: 
            Looks like it worked ok
            ECH: success: outer SNI: 'something-else', inner SNI: 'foo.example.com'



