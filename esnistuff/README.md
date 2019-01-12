
# This is a temporary place for ESNI content ...

Stephen Farrell, stephen.farrell@cs.tcd.ie, 20190101

I'll put stuff here that'll likely disappear if this matures. So the plan would
be to delete all this before submitting any PR to the openssl folks. Over time,
I'll likely move any documentation, test code etc into the proper openssl test
framework.

This builds ok on both 64 and 32 bit Ubuntus and (nominally) doesn't leak
according to valgrind. It works e.g. when talking to www.cloudflare.com
with e.g. ietf.org as the value inside the encrypted SNI. Server-side
stuff seems to work when talking to itself, and an NSS client.

**We haven't done any significant testing. Use at your own risk.**

Here's our [design doc](./design.md) that'll hopefully explain more
about how it works and what it does.

# Random notes

- Surprisingly (for me:-) this works: 

			$ ./testclient.sh -H ietf.org -c 254systemlabelifikeepadding00000000000000000000000000000000000111111111111111111111111111111111122222222222222222222222222222222222244444444444444444444444444445666666666666666666666666666666666666666666666666666677777777777777777777777777777777777777776

	i.e., connecting to www.cloudflare.com with an SNI they don't serve and
 	an ESNI that they do... is fine. The SNI value doesn't have to be a real or even
    a valid DNS name (I think!). The one above is 254 octets long. (255 or more
	octets aren't accepted by the ``openssl s_client``) Not sure what'd be right there TBH.
	Probably wanna ask CF about that.

# State-of-play...

There's a [TODO list](#todos) at the end.

Most recent first...

- ``make test`` in the main openssl directory is reporting problems (thanks to 
  @niallor for spotting that). First fail can be reproduced with: 
            make test TESTS=test_sslmessages V=1
  and indicates that there's a problem with resuming a session. As I did mess with that
  code (I changed what's stored when ESNI is used and what's checked when a session is
  loaded for re-use), that's likely my fault. 
    - Issue seems to be my ``s_client`` additions to the ``new_session_cb``
      callback is insisting that the name (whether clear or ESNI) stored in the
session matches the peer cert in the session, which is ok if that's a "real"
cert, as in my ESNI tests, but likely isn't the case in general where we might
be dealing with a self-signed cert.
    - So I need to loosen up a bit and/or make the ``require_hidden_match``
      input to ``SSL_esni_enable`` be a command line argument that also
controls this (and hence has a slightly different semantic). Need to think a
bit about that.
    - situation:
        - We have SNI or ESNI or neither supplied on the command line 
        - If neither then we won't check any names
        - If just ESNI or both then ESNI wins over SNI and we check that name
        - If SNI then we check that
        - The server cert is/isn't checked 
    - I added an ``esni_strict`` CLA to ``s_client`` - if set then these
    name checks are done, if not, they're not and that's enough to get
    ``make test`` in the main directory to return a PASS.

- Resync'd with upstream. Must figure how to automate that.

- When testing resumption, I had to run ``testclient.sh`` without ``-d`` to get
  a session ticket - seems like we're exiting too soon or something if we omit
the ``-d`` (which seems counterintuitive).  That seems true both against CF and
against my own server on localhost. E.g., this command doesn't result in a
session ticket being stored, nor received:

            $ ./testclient.sh -H ietf.org -S sess -d

  ...whereas this one reliably does:

            $ ./testclient.sh -H ietf.org -S sess 

  ...you'd imagine that's some fault of the script, but apparently not.  see it
(yet).  Breaking that out some more:

            $ echo "get /" | LD_LIBRARY_PATH=.. /home/stephen/code/openssl/apps/openssl s_client -CApath /etc/ssl/certs/ -cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2 -connect www.cloudflare.com:443 -esni ietf.org -esnirr /wECHcZnACQAHQAgeto9z+jn2BOrX31ZhlgBoatctfP2R3MkH/5MeLV3SG4AAhMBAQQAAAAAXBoWoAAAAABcIf+gAAA= -servername www.cloudflare.com -sess_out sess -msg
            ... lots of output, no file for session (sess) created...
            $ echo "get /" | LD_LIBRARY_PATH=.. /home/stephen/code/openssl/apps/openssl s_client -CApath /etc/ssl/certs/ -cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2 -connect www.cloudflare.com:443 -esni ietf.org -esnirr /wECHcZnACQAHQAgeto9z+jn2BOrX31ZhlgBoatctfP2R3MkH/5MeLV3SG4AAhMBAQQAAAAAXBoWoAAAAABcIf+gAAA= -servername www.cloudflare.com -sess_out sess -quiet
            ... teeny bit of output, session file (sess) created...

    The only difference there is the ``-msg`` vs. ``-quiet`` command
    line argument. Odd. So it's not the script's fault. (Note: you'll
    need to use a fresh esnirr value to see the above.)
    Not providing the ``echo "get /"`` input means ``s_client`` waits
    for user input, in which case we do get the session tickets, so 
    this issue could be down to timing - if for some reason 
    ``-msg`` was that little quicker than ``-quiet`` causing 
    the client to exit before receiving back the tickets. However, 
    when I (temporarily) added a ``sleep(10)``
    before the call to ``do_ssl_shutdown()`` in ``s_client'' we still didn't
    get the session tickets, so it's not just timing.

- Forgot to free ``ext.encservername`` in ``SSL_SESSION_free`` - fixed now.
  Also fixed some issues with ``new_session_cb`` which was crashing for a
  bit because I also forgot to fix up ``SSL_SESSION_dup``.

- Fixed up client handling of ``SSL_SESSION`` to make use of
  the encservername field (via new get0/set1 APIs), and making some use of
  those in ``s_client``. 

- Android NDK build (with thanks to Michael Pöhn): Changed various loop
  counters to not assume C99 (android, sheesh!). Got build working with android
  NDK. Added ``esnistuff/Makefile.ndk`` hacked together to build the ``esni`` and
  ``mk_esnikeys`` binaries (that's not produced by the openssl ``./Configure``
  sorry, so you may need to edit to get it to work, not sure). Haven't yet tried
  to run anything, just built it so who knows if it works. Here's what I did to
  get that build: 

            $ mkdir $HOME/code/android
            $ cd $HOME/code/android
            $ mkdir NDK
            $ cd NDK
            $ wget https://dl.google.com/android/repository/android-ndk-r16b-linux-x86_64.zip
            $ unzip android-ndk-r16b-linux-x86_64.zip
            ...lots of output...
            $ cd ..
            $ git clone https://github.com/sftcd/openssl
            ...some output...
            $ cd openssl
            $ . ./esnistuff/android_envvars.sh
            $ ./Configure android-arm -D__ANDROID_API__=16
            ...a bit of output...
            $ make
            ...an awful lot of output...
            $ cd esnistuff
            $ make -f Makefile.ndk
            ...a little bit of output...

  That should leave you with the ``esni`` and ``mk_esnikeys`` binaries
  for Android/ARM. (Again, I've never run those, so who knows what'd happen.)
  If you put things in some other place, you'll need to edit 
  ``esnistuff/android_envvars.sh`` to match that.

- Changed resumption in ``s_client`` to check HIDDEN (or COVER, if
  no HIDDEN) name vs. peer cert (subj/SAN) in stored session state
  if resuming. 

- Re-sync'd with upstream on 20181218.

- Started to modify client to include HIDDEN in saved session state.
  Added a new esni field to ``SSL_SESSION`` struct and
  associated ASN1 stuff. (Ick;-) **BUT** I'm temporarily abusing the
  apparently otherwise unused ``SSL_SESSION.ext.hostname`` field
  to hold that value. FIXME: properly use the new ``SSL_SESSION.ext.esni``
  field instead of the hostname. (Needs a bunch of uninteresting
  hacking about.)

- Changed ``make-example-ca.sh`` to generate wildcard certs.

- This is failing. It shouldn't :-)

			$ ./testclient.sh -p 4000 -s localhost -n -c example.com -vd

  I was being too strict in insisting on ``s->esni`` not being NULL.
  Fixed.

- Fixed ``s_server`` server-name call back some, so I can start to test
  resumption.

- Adding ``s_server`` code to make padding more specific to h/s messages
  via callback. Callback part is done and seems to work. Added a command
  line arg.

- Added client-side padding as well. (Same 512 byte setup.) See design
  notes again:-)

- Padding now turned on (within ``SSL_esni_server_enable`` on server) in a
  fairly crude manner. See the design notes for more. 
  Wireshark shows that padding is happening. Didn't test 
  it enough though yet - ``s_server`` only supports 1 HIDDEN so 
  it's a bit hard to test lots of differeng lengths for now.

- Starting to think about padding cert, so modified ``make-example-ca.sh``
  to generate different length keys giving me ~1000bytes difference in 
  cert lengths, instead of just a few bytes based on the names.

- Did some clean-up with Makefile to help with key generation/cleaning up 
  etc. ``make; make keys`` should be a good start here **after** you've
  done the main openssl build. Note that ``make keys`` will create a new
  fake CA, server keys and ESNI keys so if you've put any of those keys
  elsewhere, you need to consider that.

- Neat: tried the NSS ``tstclnt`` to interop with my ``s_server`` - and it worked! 
  The ESNI processing all seems good, and the NSS client gets the right nonce
  back. I figured out how to make NSS like my fake CA - see the end of
  ``make-example-ca.sh`` and ``nssdoit.sh``. (Note to self - you need to
  do ``./nssdoit.sh localhost`` to talk to the local ``s_server`` on port
  4000, if you omit the ``localhost`` it'll talk to ``www.cloudflare.com``.)

- There's a leak on exit in ``s_client`` in some error cases - if the ``SSL_ESNI``
  structure is created but we exit on an error, then that isn't being freed in
  all cases. It should be freed via the ``SSL_free`` for ``s_client``'s ``con``
  variable but that doesn't seem to always happen. Just calling ``SSL_ESNI_free``
  directly (on the ``esnikeys`` variable) can result in double-free's so need's
  a bit of thought/work. FIXED.

- Added session resumption to ``testclient.sh`` (I think!) via the ``s_client``
  ``sess_out`` and ``sess_in`` command line argument. Nominal case seems
  to work ok (where 2nd time you send no ESNI, or play the ESNI game afresh
  with the same HIDDEN), **but** if you send a 
  different ESNI when resuming, the server sends the cert for the original
  ESNI (e.g. for foo.example.com), but the client thinks ESNI has succeeded for
  the new ESNI (e.g. bar.example.com), which seems broken. 
  That said, [RFC8446, section 4.2.11](https://tools.ietf.org/html/rfc8446#section-4.2.11)
  isn't easy to parse on this, and considering ESNI in general. It seems
  to be saying that SNI needs to be sent on resumption, but we of 
  course won't send the real SNI in clear, so perhaps we should always
  send ESNI (which works). Not clear that we should barf if the ESNI
  in the resumed session CH differs from the server's idea of SNI but
  that seems safer to me. (There's a related [issue](https://github.com/tlswg/draft-ietf-tls-esni/issues/121)
  in the repo for the I-D.) In-work now - see [resumption.md](resumption.md).

- Modified testserver stuff to make up a fake CA and issue required
  certs etc. End result is
  that localhost tests declare success! (Since the ``s_client``
  can verify the name.) 

- Works now for pub/priv from ``esnidir`` but a bit of leakage to
  fix. (Now fixed.)

- Now accumulating supplied ESNI publics/keys and that works still
  (to the extent it has) with first supplied public/key but not
  yet for one found in ``esnidir`` - need to check more.

- Added new ``esnidir`` command line arg to ``s_server`` - idea is
  to read the set of ESNIKeys/privates found in that dir. For now,
  the last one in is active, but will change to support >1 in 
  state shortly. Note that the code there likely needs changes to
  be portable (to Windows probably, at least). There's a TODO in
  the code I'll revisit later.

- Oops - I messed up the ``esni_server_name_fixup`` function so that
  the cleartext SNI wasn't ever being sent. That was further confusing
  me in trying to test the server side, but it should be fixed now.

- Got the server to do the right thing for the 1st time, by skipping
  a check (that I don't yet grok!) in ``ssl_servername_cb``. Plenty
  more to be done though before I could claim it works. 

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

# TODOs

I'm sure there's more but some collected so far:

- Figure out/test HRR cases. [This issue](https://github.com/tlswg/draft-ietf-tls-esni/issues/121) calls for checks to be enforced.
- Server API for managing ESNI public/private values w/o restart.
- Server-side policy: should server have a concept of "only visible via ESNI"?
  E.g. some server certs might only ever be used when asked-for via ESNI.
- Server-side policy: Various combinations of existing/non-existing SNI/ESNI
  and how to handle 'em.
- What do we want/need to do to support the split backend approach? (separate
  fronting server from hosting server)
- Integration with apache/nginx/wget/curl
- Do we (really;-) need to deal with notbefore and notafter dates? It's a
  horrible source of x.509 problems, so skipped in this code for now.
- Adding/moving tests to the OpenSSL test suites
- Continuous integration for these patches that aim to keep the patch series
  current against OpenSSL master as it evolves
- Handling this on different platforms (my ``esnikeydir`` handling in
  ``s_server`` may be a bit non-portable)
- AFAIK, nobody's tested different curves/algorithms/ciphersuites - code should
  be alg. agile but who knows.
- Once we've integrated with some real client/server test the effect of our
  crude padding scheme.
- Security review: identify which parts of the code e.g. need to be constant
  time, which need to use special OpenSSL APIs, which need support for
  crypto h/w (if any)
- Maybe move the above to issues in github.


