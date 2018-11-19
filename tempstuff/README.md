
# Place for temp files...

I'll put stuff here that'll likely disappear if this
goes (much) further. So the plan would be to delete
all this before submitting any PR and to move any
related test code etc into the proper openssl test
framework.

For now [esni.c](../ssl/esni.c) has (what I think is;-) 
good OPENSSL-style code to decode and print the 
content of a TXT RR as described by the -02 I-D
and calculates the values for the encrypted SNI
CH extension.

This seems to build and run ok on both a 64 and
32 bit ubuntus under valgrind. [testit.sh](./testit.sh)
does that.

Added stubs for the statem extension handling.

## Files still to figure out/check

- ssl/ssl_asn1.c - might be a challenge, not sure if I need to go there
	- a comment in ssl/ssl_locl.h implies I might, perhaps for state mgmt, not sure

## Files modified so far

Added stuff protected by #ifndef OPENSSL_NO_ESNI 
- include/openssl/err.h
- include/openssl/ssl.h
- include/openssl/tls1.h
- apps/s_client.c

- ssl/ssl-locl.h - TLSEXT_IDX_esni isn't #ifndef protected for some reason, maybe 'cause of enum
- ssl/statem/extensions.c - lots of new code, mainly copied from server_name handling
- ssl/statem/statem_locl.h
- ssl/statem/extensions_clnt.c
- ssl/statem/extensions_srvr.c 

Added esni.c into sources for libssl
- ssl/build.info - need to add new source files here (just esni.c for now)
- utils/libssl.num - seem to need to add exported stuff here manually?

## New header files

Apparently there's nothing to do to include these in the
generated 

- include/openssl/esni.h
- include/openssl/esnierr.h

## New C files

- ssl/esni.c

- tempstuff/esnimain.c
- tempstuff/doit.sh - calls esnimain
- tempstuff/testit.sh - calls openssl s_client (evolving!)





