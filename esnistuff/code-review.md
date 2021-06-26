
# Code review of OpenSSL ECH Changes

20210624

All code changes are protected via ``#ifndef OPENSSL_NO_ECH`` so 
running a find for that we get the list below. (We'll do a cross
check vs. the master branch too later.)

            $ find . -type f -exec grep -l OPENSSL_NO_ECH {} \;
            ./include/openssl/ssl.h.in
            ./include/openssl/pem.h
            ./include/openssl/ech.h
            ./include/openssl/tls1.h
            ./include/openssl/ssl.h
            ./crypto/ec/asm/ecp_nistz256-armv4.pl
            ./ssl/ssl_sess.c
            ./ssl/tls13_enc.c
            ./ssl/s3_lib.c
            ./ssl/t1_trce.c
            ./ssl/ssl_conf.c
            ./ssl/record/ssl3_record_tls13.c
            ./ssl/ech_local.h
            ./ssl/s3_enc.c
            ./ssl/ech.c
            ./ssl/ssl_txt.c
            ./ssl/statem/statem_local.h
            ./ssl/statem/extensions.c
            ./ssl/statem/extensions_srvr.c
            ./ssl/statem/extensions_clnt.c
            ./ssl/statem/statem_clnt.c
            ./ssl/statem/statem_lib.c
            ./ssl/statem/statem_srvr.c
            ./ssl/ssl_local.h
            ./ssl/ssl_lib.c
            ./esnistuff/haproxy.html
            ./esnistuff/haproxy.md
            ./esnistuff/README.md
            ./test/buildtest_ech.c
            ./apps/lib/s_cb.c
            ./apps/ech.c
            ./apps/s_client.c
            ./apps/s_server.c

The plan for now is to look at each file and make notes here.
In parallel, we'll be testing for agility etc. as described
[here](agility.md).

## ``./include/openssl/ssl.h.in``

...and off we go: there's a TODO in that:-)

This defines ECH-related flags and has prototypes for
a few functions.

Of the flags:

* ``SSL_OP_ECH_HARDFAIL`` - deleted that one - it made sense for ESNI but 
doesn't really for ECH 
* ``SSL_OP_ECH_GREASE`` - documented
* ``SSL_OP_ECH_TRIALDECRYPT`` - documented

There were also prototypes for the ECH callbacks and for 
setting outer ALPN - I moved those to ech.h for now. (All of ech.h
might end up in ssl.h eventually, but not yet.) 

## ``./include/openssl/pem.h``

Just defines ECHCONFIG as a PEM string, so that's fine.

## ``./include/openssl/ech.h``

**TODO: revisit this when more nitty ones done.**

## ``./include/openssl/tls1.h``

Just defines the extension type codes for TLS, so that's fine.
(Note that the WG process of changing these per-interop target
means this'll change as we do that, and we might have two
different values for some time-windows if we want to support
both old/new at once.)

## ``./include/openssl/ssl.h``

See ssl.h.in above, this one's generated from that.

## ``./crypto/ec/asm/ecp_nistz256-armv4.pl``

The earlier gitlab-based CI objected to code in this file
so we found a work-around. It seems that's no longer a problem
so we've reverted this to the content of the file from
the master branch.

## ``./ssl/ssl_sess.c``

Another TODO! What to send as SNI when resuming? I guess
using ``public_name`` and re-doing ECH seems to be 
what's called for, so we probably need to note that the
session used ECH, and what ``public_name`` was used 1st
time around.  (We need setter/getter methods for those 
fields here.) And we probably need to do stuff in
the client and server to handle that properly.

There are some questions here though, so I sent a
[mail](https://mailarchive.ietf.org/arch/msg/tls/uMhAL5JBJmac4b-6JFtPaiY6tPw/)
to the TLS WG list. Will come back to this when
that thread resolves.

**TODO: revisit this when list discussion done.**

## ``./ssl/tls13_enc.c``

The only ECH code here is added tracing, to help with interop
as we mess with the transcript so none of that code likely needs
to be upstreamed ever - IOW, this one's fine.

## ``./ssl/s3_lib.c``

There's ECH code here for setting to null and freeing. I don't
think that's needed, but it might I guess with some set of API
calls that I've forgotten. I've ifdef'd that code out for now
and added a comment.

## ``./ssl/t1_trce.c``

This just has a bit of tracing for the new ECH related extensions.
Seems fine.

## ``./ssl/ssl_conf.c``

Code just allows setting our two options (grease/trial decrypt) in 
a config file. Seems fine but hasn't been tested. Turned out that
figuring out how to actually test that was waaay too much effort
so I deleted (both lines of:-) the ECH code.

## ``./ssl/record/ssl3_record_tls13.c``

GOTHERE

## ``./ssl/ech_local.h``
## ``./ssl/s3_enc.c``
## ``./ssl/ech.c``
## ``./ssl/ssl_txt.c``
## ``./ssl/statem/statem_local.h``
## ``./ssl/statem/extensions.c``
## ``./ssl/statem/extensions_srvr.c``
## ``./ssl/statem/extensions_clnt.c``
## ``./ssl/statem/statem_clnt.c``
## ``./ssl/statem/statem_lib.c``
## ``./ssl/statem/statem_srvr.c``
## ``./ssl/ssl_local.h``
## ``./ssl/ssl_lib.c``
## ``./esnistuff/haproxy.html``
## ``./esnistuff/haproxy.md``
## ``./esnistuff/README.md``
## ``./test/buildtest_ech.c``
## ``./apps/lib/s_cb.c``
## ``./apps/ech.c``
## ``./apps/s_client.c``
## ``./apps/s_server.c``
