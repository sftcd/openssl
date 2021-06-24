
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
* ``SSL_OP_ECH_GREASE`` - GOTHERE
* ``SSL_OP_ECH_TRIALDECRYPT``

There are also prototypes for the ECH callbacks and for 
outer ALPN. Maybe we should generalise sone outer API
some, not sure. Or, at least move the outer SNI to an
API like that for ALPNs. (Currently outer SNI is handled
in the same way we did ESNI but that mightn't be 
sensible any more.)

## ``./include/openssl/pem.h``
## ``./include/openssl/ech.h``
## ``./include/openssl/tls1.h``

## ``./include/openssl/ssl.h``

See ssl.h.in above.


## ``./crypto/ec/asm/ecp_nistz256-armv4.pl``
## ``./ssl/ssl_sess.c``
## ``./ssl/tls13_enc.c``
## ``./ssl/s3_lib.c``
## ``./ssl/t1_trce.c``
## ``./ssl/ssl_conf.c``
## ``./ssl/record/ssl3_record_tls13.c``
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
