
# This is a temporary place for ESNI content ...

Stephen Farrell, stephen.farrell@cs.tcd.ie

I'll put stuff here that'll likely disappear if this matures. So the plan would
be to delete all this before submitting any PR to the openssl folks. Over time,
I'll likely move any documentation, test code etc into the proper openssl test
framework.

For now [esni.c](../ssl/esni.c) has (what I think is;-) good(ish) OPENSSL-style code
do the [-02 Internet-draft](https://tools.ietf.org/html/draft-ietf-tls-esni-02).
The main header file is [esni.h](../include/openssl/esni.h).

This builds ok on both 64 and 32 bit Ubuntus and (nominally) doesn't leak
according to valgrind. It works e.g. when talking to www.cloudflare.com
with e.g. ietf.org as the value inside the encrypted SNI.

- [testit.sh](./testit.sh) calls that via a locally modified ``openssl s_client``.. 
- There's an [esnimain.c](./esnimain.c) that can be run locally that 
  just prints out the ESNI calculation values.
- [nssdoit.sh](./nssdoit.sh) is a script for doing the same with an NSS
  build - I made such a build and am using it help me develop my code

In terms of integrating with openssl, I've added most of the client-side
code for a basic use of ``s_client``, but nothing on the server-side yet
and haven't done any significant testing.

# Random notes

- TODO: consistent function names, e.g. esni_checknames -> SSL_ESNI_checknames etc.

- Raise this on the list or in GH: both client_random and the TLS h/s key_share
  extension value are mixed in the ESNI calculation. The latter makes the
openssl implementation a little harder as it imposes ordering constraints on
the client code (TLS h/s key_share has to be done first). The TLS h/s key_share
is also a little confusing as using that means there are 3 key_shares involved
in the overall story, and they're not quite encoded the same way, which is a
bit ickky. I guess some code might also confuse this if the TLS h/s contains >1
key share, as FF seems to do, at least in some cases. (One is 25519 one p256.)
It's not clear to me that both ways of binding the ESNI to this h/s are needed.
Maybe move to just using the client_random for binding? TODO: check if this
was already raised as a GH issue.

- Providing ``-H nonexistent`` as input to ``testit.sh`` claims success and
the h/s does end successfully. Behaviour differs if a cleartext SNI was
sent or not. TODO: ponder if we need the client to validate
the selected cert from the h/s matches the HIDDEN value? Probably should.
Might need to ask CF how they interpret such things too.

- TODO: Follow advice from an openssl maintainer: add a design document to be
shared with project folks. 

- TODO: I could have the s_client app do the ESNIKeys DNS lookup. Maybe add
that to handle cases where the RR value isn't supplied on the command line.

- From NSS code: /* If we're not sending SNI, don't send ESNI. */
  That should maybe be agreed upon, anything can work, but no harm
  to pick one behaviour I reckon.

- Things to test (later, when writing test code:-):
	- DNS: dns query/answer failure(s) - affects script not code so far...
	- API: No ESNI but Encservername (and vice versa)
	- checksum fail in ESNIKeys
	- decode fail(s) in ENSIKeys
	- unknown version, group, suite in ESNIKeys
	- bad times (but I disklike the whole inclusion of not_before/after!)
	- some (bogus) extension  
	- bad nonce returned by server
	- no nonce returned by server
	- fuzzing (need to check how that's generally done for openssl)
	- malloc fails
	- triggered internal fails

# State-of-play...

Most recent first...

- Tidied up the ``s_client`` display a bit so it says how things went,
  and added ``SSL_ESNI_get_status()`` API for that. Also tweaked the 
  testit.sh script a good bit so hidden, cover and server are handled 
  consistently (see the [script](./testit.sh) for details).

- Re-factored the data structures and got that working again. Next
  step will be to get rid of some more TODOs and try leave this in
  good shape for the student project to start.

- Started tidying up some todo's - got rid of hardcoding of key
  and iv lengths and 0x001d for curve ids. still more tbd

- Yay! finally got it right (had to take back some of my copying
  stuff NSS do - they prepend AAD with 8 0x00's but copying that
  wasn't a good plan:-) Have now added the code to check the
  returned nonce in the EE, and that seems to work. Next up
  should be a range of tidy-up stuff, then maybe ask some OpenSSL
  folks how bad they think the code is...

- Feeding same private, h/s key share and client_random and ESNIKeys
  values to both NSS and OpenSSL, I get the same public, Z and Zx
  and hashes and AAD. But I end up with different symm K and IV.
  Still... progress!

- Slow progress matching keys with NSS - finally got the NSS
  private (exported via logging - see [nssdoit.sh](./nssdoit.sh))
  to work when imported to OpenSSL. We now have the same 
  key share derived on both. (Note: CF public share changes
  often, so a new build of OpenSSL will be needed - check out
  code protected via ``#ifdef ESNI_CRYPT_INTEROP`` in ssl/esni.c for
  details 

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

