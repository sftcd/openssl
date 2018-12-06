
# This is a temporary place for ESNI content ...

Stephen Farrell, stephen.farrell@cs.tcd.ie, 20181203

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

- [testclient.sh](./testclient.sh) calls that via a locally modified ``openssl s_client``.. 
- There's an [esnimain.c](./esnimain.c) that can be run locally that 
  just prints out the ESNI calculation values.
- [nssdoit.sh](./nssdoit.sh) is a script for doing the same with an NSS
  build - I made such a build and am using it help me develop my code

In terms of integrating with openssl, we've added client-side
code for basic use of ``s_client``, but the server-side code is
just being done now 
and we haven't done any significant testing.

Here's the [design doc](./design.md).

# Random notes

- Surprisingly (for me:-) this works: 

			$ ./testclient.sh -H ietf.org -c toolongtobeadomainnamesystemlabelifikeepadding00000000000000000000000000000000000

	i.e., connecting to www.cloudflare.com with an SNI they don't serve and
 	an ESNI that they do... is fine. The SNI value doesn't have to be a real or even
    a valid DNS name (I think!). Not sure what'd be right there TBH.
	Probably wanna ask CF about that.

# State-of-play...

Most recent first...

- Re-did how I handle ciphersuites in my data structures to use the 2byte
  ciphersuite IDs off the wire and just map those to ``SSL_CIPHER`` or
  ``EVP_xx`` later. Makes memory management easier:-) Seems to show that
  the ``SSL_CIPHER`` "class" isn't really designed that much I guess.

- (Now fixed) Server crashes on 2nd TLS connection though - something up with how I'm
  calling ``SSL_ESNI_free`` I bet (and the ctx/ctx2 stuff;-) (Keep this
  @ top of list 'till fixed.) 

- Fixed encoding of ESNI response, was missing extn type and length.
  H/s working now, and nonce coming back ok, but getting name 
  mismatch on client.

- EncryptedExtensions with nonce being returned now, but no cert from
  server being process on client (looks like a cert may be sent but, 
  maybe client barfing on SH? ...)
  I guess more work is needed than just setting s->ext.hostname;-(

- ``SSL_ESNI_dec`` seems to be working, neat. Next up is to
  go back to processing the returned ESNI. 

- AEAD decryption success, next up to extract encservername

- Got (re-)calculation of Z (DH shared) the same on my server, 
  yay! Same for ESNIContent and hash thereof (with a bit of
  re-factoring of client side code to make tha easier).

- Added ``-P <esnikeysfile>`` option to ``testclient.sh`` so I 
  can test locally (which I'd forgotten, but which nicely 
  means I've now tested the client using the wrong ESNIKeys
  with my server code:-)

- Added (stub) version of ``SSL_ESNI_dec`` that should have all
  the right inputs, next up will be the checks/decrypt in the
  body of that function.

- ``tls_parse_ctos_esni``: done with parsing, no crypto yet, lots
  of code tidying needed and TODOs

- Added ``SSL_set_esni_callback_ctx`` so I can ``SSL_ESNI_print``
  from ``tls_parse_ctos_esni`` (along with a bit of copying
  from ``SSL_CTX`` down to ``SSL`` instances.

- Renamed testit.sh -> [testclient.sh](./testclient.sh) for obvious
  reasons.

- Working on ``SSL_esni_server_enable`` - partly done. The ``SSL_ESNI``
  structure for the server (i.e. with no client input) is populated
  and all seems well. (If untested;-)

- Added [testserver.sh](./testserver.sh) to use ``s_server`` for
  testing. For now that can generate server cert keys and start
  a server, but doesn't actually do any ESNI stuff.

- Added [mk_esnikeys.c](./mk_esnikeys.c), as (the start of) a command 
  line tool to make an ESNIKeys structure and private key. I guess this 
  is a start (of sorts:-) to server-side coding. Seems to generate a
  key pair and dump out files that appear well-formatted. 

- Moved error strings into libcrypto.so which required modifying a 
  few more things. Not sure this is correct but seems like what
  is done in other cases. Good enough anyway, though it seems odd
  to make libcrypto depend on esni, but whatever.

- Started to add javadoc text and doxygen-generated output. Will
  see if I can turn that into .md. Gonna start by trying [this](https://github.com/sourcey/moxygen)
  (but that had some npm issues, followed [this](https://linuxize.com/post/how-to-install-node-js-on-ubuntu-18.04/)
  process to get npm installed after apt failed due to a conflict - presumably that's
  down to my 18.10 upgrade zapping the previously installed repos).
  Ressulf of that is [here](./api.md). We'll see if it's any good.

- Added hostname validation as an option to ``SSL_esni_enable`` - if requested 
  and we don't get the
  hidden name matching the server cert then ``SSL_esni_get_status``
  returns a "bad name" error code.
  Not quite sure this is the right thing to do (TM:-) and we're 
  ignoring the covername when doing it, but it seems kinda sensible
  so we'll go for it for now. ``s_client`` hardcodes this to be
  requested for now, could be added to command line later.

- From NSS code: ``/* If we're not sending SNI, don't send ESNI. */``
  That should maybe be agreed upon, anything can work, but no harm
  to pick one (default?) behaviour I reckon. For now, I don't couple 
  things so tightly, maybe ``s_client`` is different enough from
  a browser that that's correct.

- Got rid of duplication of encservername/covername from ``SSL s.ext``
  and ``SSL_ESNI`` and from the ``SSL_ESNI_enc`` API

- I could have had the ``s_client`` app do the ESNIKeys DNS lookup. Maybe add
that to handle cases where the RR value isn't supplied on the command line.
OTOH, maybe not - would require picking a DNS library which Viktor 
seemed unkeen on. Decided to not bother with that.

- Consistency: got rid of "frontname" everywhere -> "covername" and
  use encservername everywhere (and never enchostname;-) 

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

