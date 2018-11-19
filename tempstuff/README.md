
# Place for temp files...

I'll put stuff here that'll likely disappear if this
goes (much) further. So the plan would be to delete
all this before submitting any PR and to move any
related test code etc into the proper openssl test
framework.

For now [esni.c](./esni.c) has (what I think is;-) 
good OPENSSL-style code to decode and print the 
content of a TXT RR as described by the -02 I-D
and calculates the values for the encrypted SNI
CH extension.

If/when doing this for-real, that code would be
distributed in a couple of library bits. Starting
that now.

## Files modified so far

Added stuff protected by #ifndef OPENSSL_NO_ESNI 
- include/openssl/err.h
- include/openssl/ssl.h
- include/openssl/tls1.h
- apps/s_client.c

Added esni.c into sources for libssl
- ssl/build.info 

## New header files

Apparently there's nothing to do to include these in the
generated Makefile? TODO: check via clean clone on another
box!

- include/openssl/esni.h
- include/openssl/esnierr.h

## New C files

- ssl/esni.c
- tempstuff/esnimain.c




