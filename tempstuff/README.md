
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
The ctos encoder for esni is being called when a connection is
attempted.
ClientHello is being sent, but I'm getting back a protocol
error. 
My openssl s_client build though is failing all the time
so it might not be down to how I'm encoding the esni
extension (or it might:-). Will try with a clean build
of openssl without my code just to see.
Try that vs. https://tls13.crypto.mozilla.org/

Ah, a clean build does work with tls1.3, must be
my fault so, guess I broke something.
Perhaps not all my fault - cloudflare.net seems to
[not always](https://community.cloudflare.com/t/tls13-not-working-for-dns-over-tls/31332) have been working, but the moz site is 100%
with a clean openssl, and my modified build fails
100% even with no esni included, so that's the
place to start.

Might be near time to comment on [this](https://github.com/tlswg/draft-ietf-tls-esni/issues/118)
issue to see if I can find more help.

## Files still to figure out/check

- ssl/ssl_asn1.c - might be a challenge, not sure if I need to go there
	- a comment in ssl/ssl_locl.h implies I might, perhaps for state mgmt, not sure

## Files modified so far

Added stuff protected by #ifndef OPENSSL_NO_ESNI 
- include/openssl/err.h
- include/openssl/ssl.h
- include/openssl/sslerr.h
- include/openssl/tls1.h
- apps/s_client.c

- ssl/ssl-locl.h - TLSEXT_IDX_esni isn't #ifndef protected for some reason, maybe 'cause of enum
- ssl/ssl-lib.c
- ssl/s3_lib.c
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





