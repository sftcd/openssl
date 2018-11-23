
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

(Well, not a result, more state-of-play, most recent 1st:-)

- Made a bunch of changes to be more like what the instrumented
  NSS seems to do. (Incl. issue#119); getting down to where it
  may be the crypto/kdf that I need to check via some test
  vector I can run through both sets of code - first though
  wireshark is calling my CH's TLSv1 and not TLSv1.3 when I
  include the ESNI, but doesn't without or for NSS's with ESNI
  included - guess it could be that so try eliminate that 
  first.
	- reckon wireshark thing is spurious, it likely updates
	  the protocol field for the CH after seeing answers
	  (tested with different filter, and NSS also shows at
 	  just TLSv1 if I only capture outbound packets)

- Started instrumenting NSS's tls13esni.c, more as we get it...

- Got NSS built and can use it's tstclnt - plan now is to dump the
  same intermediate values 'till I get it right...
  The [nssdoint.sh](./nssdoit.sh) script calls that as needed
  and seems to get further than my code, as you'd expext.

- Using a stale old value from DNS isn't a good plan - that
  caused the NSS tsclnt to fail too - moved to using dig
  each time in scripts.

- www.cloudflare.com finished the handshake but no sign of an
  esni in the EE so far (actually getting no EE from the
  server)
	- I discovered I wasn't handling the client h/s key share at all (heh:-)
	- need to check what FF gets when working - later

- I've gotten FF nightly to work with CF, and am now sending
  the same structure. I did have 2 extra bytes in my
  encrypted_sni field and took out a length but not sure
  if that was the right one or not. There's a TODO...

- cloudflare.net gives "SSL alert number 70" in response to CH
- tls13.crypto.mozilla.org gives "SSL alert number 40" in response to CH
- 1.1.1.1:853 finishes the handshake, probably ignoring the esni

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
- ssl/t1_trce.c
- ssl/statem/extensions.c - lots of new code, mainly copied from server_name handling
- ssl/statem/statem_locl.h
- ssl/statem/extensions_clnt.c
- ssl/statem/extensions_srvr.c 

## Files still to figure out/check

- ssl/ssl_asn1.c - might be a challenge, not sure if I need to go there
	- a comment in ssl/ssl_locl.h implies I might, perhaps for state mgmt, not
	  sure

