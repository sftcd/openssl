
# This is a temporary place for ESNI content ...

Stephen Farrell, stephen.farrell@cs.tcd.ie

I'll put stuff here that'll likely disappear if this matures. So the plan would
be to delete all this before submitting any PR to the openssl folks. Over time,
I'll likely move any documentation, test code etc into the proper openssl test
framework.

For now [esni.c](../ssl/esni.c) has (what I think is;-) good OPENSSL-style code
to decode and print the content of the TXT RR as described by the -02 I-D and
to calculate the values for the encrypted SNI CH extension.

This seems to build and run ok on both 64 and 32 bit Ubuntus and not leak
according to valgrind.

- [testit.sh](./testit.sh) calls tha via a modified ``openssl s_client``.. 
- There's an [esnimain.c](./esnimain.c) that can be run locally that 
  just prints out the ESNI calculation values.

In terms of integrating with openssl, I've added stubs for the statem extension 
handling.  The esni ctos (client-to-server) function is done and is called when a
connection is attempted.  The ClientHello is then sent including that value, 
but it's obviously not yet working...

# Results

(Well, not a result, more state-of-play:-)

1. With esni included:

- cloudflare.net gives "SSL alert number 70" in response to CH
- tls13.crypto.mozilla.org gives "SSL alert number 40" in response to CH
- 1.1.1.1:853 finishes the handshake, probably ignoring the esni

1. When esni omiteed but my build:

- cloudflare.net gives "SSL alert number 70" in response to CH
- tls13.crypto.mozilla.org finishes the handshake
- 1.1.1.1:853 finishes the handshake

1. A "clean" build right from [upstream](https://github.com/openssl/opennssl/):

- cloudflare.net gives "SSL alert number 70" in response to CH
- tls13.crypto.mozilla.org finishes the handshake
- 1.1.1.1:853 finishes the handshake

So cloudflare.net is doing something odd, it seems. And that's odd
as it's them who say they support this. Maybe they're just reacting
more quickly to my bad esni encoding but that doesn't explain the
last case above.

It might be near time to comment on
[this](https://github.com/tlswg/draft-ietf-tls-esni/issues/118) issue to see if
I can find more help.

# Modifications for esni support (so far)

I'll expand on this when it's actually working.
All path names are below your clone of openssl, for me that's
usually in ``$HOME/code/openssl``.

All or almost all code is protected via ``#ifndef OPESSL_NO_ESNI``
as seems to be done for other things. So search for that to find
out what I've been doing.  There are TODOs galore, of course:-)

## New files

- ssl/esni.c - main esni-specific functions
- include/openssl/esni.h - data structures are commented some
- include/openssl/esnierr.h - boring

- esnistuff/esnimain.c - a tester
- esnistuff/doit.sh - calls esnimain
- esnistuff/testit.sh - calls ``openssl s_client`` (still evolving!)

## Existing Files modified so far

- ssl/build.info - need to add new source files here (just esni.c for now)
- utils/libssl.num - seem to need to add exported stuff here manually?
- include/openssl/err.h
- include/openssl/ssl.h
- include/openssl/sslerr.h
- include/openssl/tls1.h
- apps/s_client.c
- ssl/ssl-locl.h - TLSEXT_IDX_esni isn't #ifndef protected for some reason, maybe because it's an enum?
- ssl/ssl-lib.c
- ssl/s3_lib.c
- ssl/statem/extensions.c - lots of new code, mainly copied from server_name handling
- ssl/statem/statem_locl.h
- ssl/statem/extensions_clnt.c
- ssl/statem/extensions_srvr.c 

## Files still to figure out/check

- ssl/ssl_asn1.c - might be a challenge, not sure if I need to go there
	- a comment in ssl/ssl_locl.h implies I might, perhaps for state mgmt, not
	  sure

