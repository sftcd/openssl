# This is a temporary place for ESNI content ...

Stephen Farrell, stephen.farrell@cs.tcd.ie, 20230114-ish

I'll put stuff here that'll likely disappear as this matures. The plan is
to delete all this before submitting PRs to the openssl folks.

This builds ok on both 64 and 32 bit Ubuntus and (nominally) doesn't leak
according to valgrind. It works e.g. when talking to crypto.cloudflare.com

An ``s_client`` works with the ``s_server`` but also with
[lighttpd](./lighttpd.md), [nginx](./nginx.md),
[apache](./apache2.md) and, most recently, [haproxy](haproxy.md).

**We haven't that done much testing. Use at your own risk.**

# State-of-play...

There's a [TODO list](#todos) at the end.

Most recent first...

DON'T DEPLOY ECH YET!!! It's still work-in-progress code.

- 20230428: added ``test/ech_split_mode.c`` as (the start of) a
  better test harness for ECH split-mode

- 20230425: added ``demos/echecho.c`` showing simple use of ECH and
  changed memory management for inner/outer SNI returned from 
  ``SSL_ech_get_status()`` so that it's the same as handling 
  similar outputs from ``SSL_CTX_ech_raw_decrypt()``. That's 
  probably better anyway, as we avoid returning a pointer to
  the middle of a bigger struct.

- 20230424: added nominal ECH split mode usage test

- 20230421: bit more refactoring around transcript buffer (not fully
  done)

- 20230420: added a flag on loading keys to say if the related ECHConfig
  values should be included in retry-configs

- 20230420: added wrong public key test, straight and with HRR,
  and re-factored error handling some

- 20230416: added initial (nominal) test of ``SSL_CTX_ech_raw_decrypt()``

- 20230415: refactored ``ech_calc_confirm()`` (again:-) making 
  progress on path towards better (generic) ECH transcript handling

- 20230412: added tests with borked CH/SH (in ``echcorrupttest.c``)
  which are fine but didn't yet find a way to do the same for the
  retry-config

- 20230408: added "ech-required" alert as per spec along with other
  related library error strings; investigating HRR+ECH in the face
  of errors (bit flip in HRR) or use of wrong public key - seems to
  be some work to do there

- 20230407: finally added not accepting so-called "mandatory" ECHConfig
  extensions (not a good design idea, but it's in the spec;-()

- 20230406: refactored ECH bits of ``tls_process_server_hello()``
  and started to add tests that bork server hello

- 20230404: added test with ECHConfig extensions present; refactored
  ``ECHConfigList_from_binary()`` some

- 20230403: refactored ``ech_get_sh_offsets()`` and ``ech_calc_ech_confirm()``

- 20230402: more refactoring, mostly in ``ech_early_decrypt()``

- 20230401: refactored ``ech_decode_inner()`` to only use PACKET APIs

- 20230325: pushing a commit to check if the [github.com SSH key
  rotation](https://www.bleepingcomputer.com/news/security/githubcom-rotates-its-exposed-private-ssh-key/)
affects me;-) Yep, it did, had to do a bit of manual key deletion and accepting
a new one for ``known_hosts``.

- 20230323: started adding tests that involve corrupted
  encoded inner CH values (in ``test/echcorrupttest.c``
  modelled on ``test/sslcorrupttest.c``).

- 20230321: added more alpn/sni inner/outer tests

- 20230318: refactored roundtrip tests and added a couple of
  GREASE tests, including use of retry-config

- 20230314: rebased lighttpd1.4 and updated integration code
  with recent ECH API changes, seems ok

- 20230310: refactoring of extension compression, duplication
  and whether to make a 2nd call to constuctor - seems to be working
  ok

- 20230308: changed to compress the ``key_share`` so the ECH
  extension is smaller (and to check we don't barf on any EVP
  structures when doing so). Made a few tweaks to padding to
  match that, so result is saving about 128 octets in the CH
  as a result. But - important to at some point re-test the
  setup with independent key shares in inner and outer to 
  ensure server is ok with that, including when ECH fails and
  we end up negotiating based on the outer CH and getting a
  ``retry_config``.

- 20230305: Support for custom extension handling now working with ECH.
  Such extensions for now are always compressed in inner CH. Test code
  added for that too.

- 20230301: did a bit of testing that GREASE PSKs actually
  look nicely random incl. the obfuscated ticket ages (as
  called for by the ECH spec)

- 20230228: got early data working again - problems were
  a mix of mine (more changes related to moving away from
  use of ``s_inner`` etc) and a bug in the underlying 
  master branch fixed via [PR20387](https://github.com/openssl/openssl/pull/20387).

- 20230218: added HRR tests to ``ech/ech_test.c`` (and 
  found/fixed a key-share leak in doing so!)

- 20230217: added a bunch more tests to ``test/ech_test.c``
  including for all suites, so that's starting to head to
  where it can replace the ``agiletest.sh`` script (still
  need to figure how to add tests for HRR, resumption etc
  though)

- 20230215: did a fairly big refactor of the ECHConfigList
  ingestion code, seems ok

- 20230126: added ``doc/designs/ech-api.md`` - that's just a starter
  for that doc as of now.

- 20230124: swapped storage choice for inner/outer SNI; as a hangover
  from ESNI we used store the inner SNI in a newly defined field, but that
  didn't fit so well with ECH, so ``s->ext.hostname`` will now hold the
  inner SNI value and the outer will be in ``s->ext.ech.cfgs->outer_name``
  (if being overridden) or ``s->ext.ech.outer_hostname`` (if using the
  ``ECHConfig.public_name``

- 20230119: bit more tidying up of data structures

- 20230118: rebased with master, cleaned up some doc-nits stuff

- 20230117: Fixed issue with early-data (session name vs. 
  inner SNI check needed a tweak).

- 20230112: removed the (sort of recursive) ``SSL_CONNECTION *inner_s`` 
  and ``SSL_CONNECTION *outer_s`` fields from within an ``SSL_CONNECTION``,
  i.e. flattened out the structure, hopefully improving resilliency.
  Seems to be working, at least for the ``agiletest.sh`` script.

- 20230109: added a new ``PACKET_replace()`` API to avoid abusing PACKET APIs
  when server replaces outer CH with inner and did a scan of other modified
  files to get rid of a couple of other (W)PACKET API abuses.

- 20230107: tidied up the rest of the code that's protected via ``#ifndef
  OPENSSL_NP_ECH``. Next up will be to fix my remaining abuses of the PACKET
  APIs and play with getting rid of the ``SSL_CONNECCTION *inner_s`` on the
  client.

- 20230104: tidied up ``ssl/statem/extensions_srvr.c`` and
  ``ssl/statem/statem_srvr.c`` and a couple more a good bit

- 20230103: tidied up ``ssl/statem/extensions_clnt.c`` and 
  ``ssl/statem/statem_clnt.c`` a good bit

- 20230101: fixed up ``ech_send_grease()`` some, and related code
  in ``ssl/statem/extensions_clnt.c``

- 20221230: fixed up ``ech_decode_inner`` a good bit; might re-do
  that entirely later (I should make an attempt to properly use
  or extend the PACKET/WPACKET APIs for that and elsewhere). Got
  to the ``calc_accept`` stuff.

- 20221229: back at it:-) changed the printing stuff (for ECHConfigs)
  to use ``BIO*`` instead of home-grown stuff.

- 20221224: bit more tidying, next up will be to re-check all 
  the (still untrusted) outer CH fields in ``ech_decode_inner()``
  as it could be I'm not doing enough checks on those (need to
  re-check as stated:-)

- 20221221: looked a bit at error handling in split-mode and 
  figured out yet more work is needed, e.g. if a client sends
  a GREASEd ECH the frontend ought finish the h/s which won't
  happen with my haproxy PoC - basically more work TBD. (Also
  cleaned up ``ossl_ech_make_echconfig()`` a lot.

- 20221217: re-did POD files for ECH stuff see
  ``doc/man3/SSL_ech_set1_echconfig.pod`` (same for command line tools). There
  was also a few accompanying code chnages.

- 20221215: fixed a leak in ``test/ech_test`` that causes our
  old friend double-free in echcli.sh yet again - check for
  FIXME in ``ssl/ssl_lib.c`` - still an ickky workaround that
  needs to go (probably when/if "shadow" ``SSL_CONNECTION`` on
  client is ditched).

- 20221214: renamed a bunch of APIs to be more aligned with
  project patterns, e.g. ``SSL_ech_add()`` -> ``SSL_ech_set1_echconfig()``
  Note that this breaks integrations with applications e.g. nginx etc.
  but we'll get back to fix those in a short-ish while.

- 20221213: HRR and early-data tests now back working. So back to
  tidy-up, before heading down the path of making this code more
  likely attractive to upstream devs (based on lessons learned from
  our earlier HPKE PR).

- 20221212: many changes to tidy up formatting according to OpenSSL
  project guidelines. That or related rebasing left us in a state
  where ECH server side was failing because of not getting the 
  right transcript before sending the ServerHello. Put in a fix for 
  that (into the end of ``ech_calc_ech_confirm()`` for now, but 
  needs re-working). Just pushing this now, so there's a working
  thing in the repo. (But still have to test HRR/early-data etc.)

- 20221115: finished changing external prototypes to match project prefs
  (outputs 1st etc.) Will need to get around to changing web server and
  client integrations accordingly in a while. (Maybe next, or maybe do 
  more on implementation internals first, we'll see.)

- 20221115: rebased again, HPKE-PR nearing done

- 20221106: Adding new ECH tests in OpenSSL test harness mode, e.g.
  try: ``make test TESTS=test_ech V=1``, code in ``test/ech_test.c``

- 20221105: now include latest HPKE changes based on more PR review

- 20221103: more tidying up...

- 20221029: Started to tidy up ECH code in early preparation for making
  a PR for that (now that my HPKE PR is hopefully nearing completion).

- 20221024: another record layer leak, when GREASEing from client, answer
  was to tweak the conditions for free'ing the record layer and
  ``init_buf`` depending on the ECH conditions we see, but that's pretty
  brittle and liable to break as other code changes. See the comment in
  ``ssl/ssl_lib.c`` within ``ossl_ssl_connection_free()``.
    - TODO: better automate leak-checking esp with GREASE and/or
      deliberate use of an ECHConfig that is ok other than having the 
      wrong public key

- 20221023: fixed leak below which was due to attmempting to load
  a draft-10 ECHConfig, when that was the only offered ECHConfig.
  Could well add more testing there as it's
  been a long time since that was done (to the make test target.)

- 20221022: removed all draft-10 code and updated to latest version
  of HPKE-PR code. As of now, seems clean, but:
    - server leak on exit, not sure if due to ctrl-c handling
      (forget;-), valgrind says:
                ==1638854==    by 0x48898FA: local_ech_add (ech.c:1273)
                ==1638854==    by 0x48873EB: ech_readpemfile (ech.c:464)
                ==1638854==    by 0x488B7B4: SSL_CTX_ech_server_enable (ech.c:1876)
                ==1638854==    by 0x48985ED: SSL_CTX_ech_readpemdir (ech.c:5451)
    

- 20221013: changed ECH code to use ``SSL3_RT_MAX_PLAIN_LENGTH``
  instead of ``OSSL_HPKE_MAXSIZE``, still TODO:
    - probably no point in keeping the draft-10 code about
      any longer too so that should go

- 20221012: this branch (ECH-draft-13c) now uses the newest
  HPKE APIs, and ECH works, but with leak fixes needed.

- 20220920: this branch is rebased on master from a few
  days ago, it builds and the client works, but leaks and
  crashes due to memory changes in master (mainly down to 
  the change from ``SSL *`` to ``SSL_CONNECTION *`` in 
  many APIs); I'll likely use this to figure out fixes for
  those but it's probably a short-term thing and I'll
  move to yet another branch to re-do a bunch of this more
  properly in a bit

- 20220530: re-merged with upstream; it looks like the way to
squash my merge commits when the time comes (i.e. when it's
time to submit a PR for ECH) will be something like the
recipe below, but I'm not sure if there's a way to preserve
the commit comments:

            $ git checkout my-branch
            $ git branch -m my-branch-old
            $ git checkout master
            $ git checkout -b my-branch
            $ git merge --squash my-branch-old
            $ git commit

- 20220310: got interop with FF nightly back! (was my fault - I
  wasn't allowing for enough referencing of outer extensions in
  the inner CH;-). Also a few tweaks to test scripts used to
  track that down.

- 20220225: noted HPKE is now RFC9180 and re-merged with upstream

- 20220216: starting to test with FF again, see [ff13a.md](ff13a.md)

- 20211108: remerged with upstream

- 20211106: Added real use of ECH to ``sslapitest.c:execute_test_session()``
  which is called a bunch of times in various ways. That turned up a couple
  more issues that've been fixed now. Usage here is only nominal ECH, no
  ECH-specific errors are tested as yet.

- 20211102: started to add in ECH specifics to the ``make test`` target
  (based on stuff figured out by @niallor [here](https://github.com/niallor/openssl/tree/ECH-TEST-API-WIP)
  Found/fixed some bugs as a result.

- 20211101: 3rd pass of code review completed

- 20211003: ``early_data`` working now between openssl and
  boringssl.

- 20210921: adding early data options to echcli.sh and echsrv.sh but not
  yet working (or I don't know how to properly ask:-) - could be that
  the stored session isn't quite right for early data, checking...
  ... to run a test:

            $ ./echsvr.sh -dev
            ...stuff...
            $ ./echcli.sh -s localhost -H foo.example.com -p 8443 -P d13.pem -f index.html -dv -S foo.sess
            ...stuff...
            $ ./echcli.sh -s localhost -H foo.example.com -p 8443 -P d13.pem -f index.html -dv -S foo.sess -e
            ...stuff...

- 20210919: haproxy split-mode plus HRR doesn't work as haproxy
  doesn't provide a way (that I can see) to decrypt the 2nd CH,
  asked haproxy devs for advice, but will park that for now.

- 20210914: git haproxy split mode working again for draft-13

- 20210914: deployed a bunch of services on [defo.ie](https://defo.ie/) -
  see the web page there for details

- 20210910: deployed an HRR-forcing server (P-384 only)
  on port 8414 of draft-13.esni.defo.ie. Normal server
  is on port 8413 of same host.

- 20210909: Got HRR working between boringssl and OpenSSL
  clients/servers in both directions, but with mega-hack
  code in places - will tidy that after we have broader
  interop with others.

- 20210904: have basic interop with boringssl working ok
  in both directions, now working on HRR interop... (do
  we hate HRR? yes we do! ;-)

- 20210817: added notes on [HRR testing](hrrtest.md)

- 20210816: moved agiletest.sh up to draft-13 keys

- 20210816: added the recommended ECH padding length calc
  from draft-13 (even though I now think the SNI part of
  that's not really useful now)

- 20210816: added an initial version of draft-13 accept
  confirmation calculation - usually I need to see someone
  else's code to get that right but that's ok - it works
  for ``s_client<->s_server`` in the meantime

- 20210816: ``-no-cmp`` seems no longer needed to
  get tracing to work which is nice, so new recipe
  to build with tracing is:

            $ cd $HOME/code/openssl
            $ ./config enable-ssl-trace enable-trace --debug
            ...
            $ make clean; make
            $ cd esnistuff
            $ ./echsrv.sh -dvT
            ...etc...

- 20210816: added ``hpke_expansion()`` to
  [happykey](https://github.com/sftcd/happykey) for
  draft-13. Also tidied up hpke.[ch] files some.

- 20210813: draft-13 ECH extension formatting, padding
  and AAD calculation seemingly ok (but not really doing
  draft-13 yet); there are some new TODOs introduced that
  are to be adddressed.

- 20210812: pre-draft-13: got GREASE working for either
  draft-10 or draft-13 extension types. Will probably
  try keep both -10 and -13 working in parallel for the
  moment both for interop and because the differences
  are modest.

- 20210811: Added back "support" for generating draft-09
  ECHConfigs so we can easily generate values to test we
  properly ignore "unsupported" versions in other code.

- 20210811: started to code up pre-draft-13 - first steps
  are to just define the extension (using the same handling
  functions as draft-10 for now) and ensure that draft-10
  still works. That'll be a few steps... before anyting
  really different happens;-)

- 20210810: made a [boringssl test script](bssl-oss-test.sh)
  to automate doing various bssl  thing - also got my ``s_client``
  working with their ``s_server``.

- 20210810: updated boringSSL, re-built and verified that
  ``bssl s_client`` works with cloudflare and (with a bit
  of welcome bug fixing) against my ``openssl s_server``.

- 20210810: added ``-ech_ignore_cid`` option to ``s_client``
  to allow client to send random ``ECH.config_id`` instead
  of server's chosen value. (Requires server to accept
  trial decryption.)

- 20210809: Moved the development branch to "ECH-draft-13"
  First addition there is the key generation stuff but to
  also play with cat picture extensions (even small cat pics
  are big enough to exercise code not otherwise tested:-)
  Part of that is a script [makecatexts.sh](makecatexts.sh)
  to prepare a file containing encoded extensions to provide
  to ``openssl ech``. The file [cat.ext](cat.ext) is a case
  in point and contains two cat pictures (with a dog:-) as
  an example.

- 20210808: ``make test`` now works for ``-no-ech`` build.
  ALso had to tweak ech.h so that libssl.num is ok with a
  ``make update`` when ECH is part of the build - that
  required putting the ``OPENSSL_NO_ECH`` ifndef inside
  the ``OPENSSL_ECH_H`` ifndef to keep the ``mknum.pl``
  script happy. (Well, that's just a theory from experimenting
  and copying srtp.h;-)

- 20210807: checking build/test with ``-no-ech`` and aligning code
  with upstream that git merge gets wrong. (A few non-ECH bits of
  code that'd been deleted from upstream - we added a [script](scanem.sh)
  to help with that). As of now, the no-ech build
  seems fine, but the no-ech ``make test`` isn't, so we probably have
  some ECH code that's not properly protected via the #ifndef.

- 20210801: resync'd with upstream

- 20210624: Started an internal [code review](code-review.md) of
  all the ECH changes, that'll be ongoing for a bit. Finished
  two passes of that in late July having tested a bunch of stuff
  (incl. >1 ECHConfig/ECHConfigs), fixed a small pile of things
  and made a lot of cosmetic/code-style changes.

- 20210624: Our ``make-example-ca.sh`` script was barfing when
  openssl is built in debug mode but working fine otherwise.
  Changing from "-newkey rsa:4096" to just "-newkey rsa" fixed
  that and is enough for us, as that's not en ECH thing.
  (I removed a workaround for this from agiletest.sh too.)

- 20210623: added [agiletest.sh](agiletest.sh) that has a pile of
  tests related to algorithm agility and other parameter handling. See
  [agility.md](agility.md) for some more details.

- 20210622: haproxy/split-mode still needs work on key rotation but otherwise
  not that bad, though there's some unexpected behaviour when nonsense
  inner SNI values are used. (Had a call with haproxy devs on 20210623
  so won't try fix that just yet - some other changes to do first to
  more properly handle inner/outer CH's in a more generic manner.)

- 20210615: got split-mode ``s_client`` to ``s_server`` via haproxy working

- 20210608: rebmerged with upstream

- 20210607: might just have the entire CI build stuff working now

- 20210602: haproxy sorta working a bit - [notes](haproxy.md)

- 20210525: More work done on padding - [padding_notes.md](padding_notes.md).
  Probably ok to park that for a bit and discuss on the list or in GH.

- 20210524: fixed ALPN handling on server when we have two contexts
  (which we do for ECH). That's not really an ECH-specific fix though
  but needs doing anyway.

- 20210522: turned on padding for inner CH when real, and made GREASEy
  ECH extension match that length; padding is as-was for library (i.e.
  same alg as when padding option set)

- 20210520: remerged with upstream - there's some new issue in
  reading ECH private keys - just put in a workaround for x25519
  for now, but needs checking.

- 20210521: fixed the private key loading - latest library lets
  us go back to only using the PEM function, which is better
  than having to delve down to the HPKE one

- 20210520: a bunch of improvements wrt the CI actions done on
  pushing - many now working (coupla windows changes still needed,
  some docs and a few others, but mostly done).

- 20210514: finally got the ``make test`` target fixed after a lot
  of painful mucking about (the fault was mine but wasn't helped by
  the oddball test setup). Also brought GREASE up to draft-10 spec
  and improved greasiness via ``hpke_good4grease`` API that knows the
  internal lengths etc.

- 20210429: made myself a [checklist](checklist.md) for things to check
  whenever non-trivial changes made (one just done and there's more upcoming).
  All the localhost/dev-machine parts of that are now done. Will push
  and move on to the defo.ie deployment parts...

- 20210426: this build removes ESNI code but still builds and seems to
  run at least a basic ECH client test ok; most likely this'll need to
  be done more than once to get it all right

- 20210425: created an ESNI-and-ECH branch to mark state of play before
  the start of cleaning up.

- 20210420: deployed an nginx at https://draft-10.esni.defo.ie:10410 that seems to
  work.

- 20210417: deployed a lighttpd on defo.ie at draft-10.esni.defo.ie:9410 which works, but
  still some oddity related to the "ECH only" virtual host (draft-10-echonly.esni.defo.ie:9410)
  on the same server - seems to relate to ALPN somehow, investigating...

- Niall's curl build + our draft-10 library now works against
  https://draft-10.esni.defo.ie:8410 which is only an s_server
  instance (so not a real server, hence: please be kind:-).
  Reminder to self, for invoking that:

            $ cd $HOME/code/curl
            $ export LD_LIBRARY_PATH="/home/stephen/code/curl/lib/.libs:/home/stephen/code/openssl"
            $ src/curl https://draft-10.esni.defo.ie:8410/stats --echconfig "AEL+CgA+zgAgACDpySLJgFRnOze6x/6Dt4AqAkecRlgvFuopBQ6xCqN2aAAEAAEAAQAAAA1jb3Zlci5kZWZvLmllAAA=" -v

  Niall has a wrapper script that retrieves the ECHConfig from
  DNS but I've yet to test that.

- 20210323: made changes that might provide draft-10 interop
  (seems to work locally at least)

- 20210323: created a draft-09 branch to preserve that before
  we move onto the breaking changes for draft-10.

- 20210319: resolved leaks when wrong ECHConfig used by
  client - probably more to be done there, in terms of
  exploring all failure modes, but as the accept confirmation
  signal is still likely to change, probably ok for now

- 20210315: nominal localhost operation with draft-09 and when
  a draft-10 ECHConfig loaded (no other draft-10 changes made
  yet). Next is to fix a bunch of purely draft-09 error cases to tidy
  up where valgrind isn't happy (e.g. when wrong key used by
  client).

- 20210313: added reading of draft-10 ECHConfig to library

- 20210312: started to code up draft-10, first  by adding more
options for the ``openssl ech`` command line tool so we can do more tests
as we go.

- 20210310: updated HPKE/happykey code to match latest upstream OpenSSL
(but HPKE/draft-07 is still the default build here for now)

- 20210305: rebased with upstream (many, many changes so testing needed!).
Some new warnings about deprecation, not yet fixed. Loading our PEM file
was broken so added a new HPKE API to handle that better.

- 20210301: fixed the use of ``hpke_enc_evp`` variant, and got
rid of the ``hpke_enc_raw`` variant code (which exposes the
sender's ephemeral private key bits to the application
unnecessarily)

- 20210301: re-added outer ALPN handling, seems ok at protocol
level, still need to check if any callback changes needed

- 20210238: cleaned up leaks at least in nominal operation

- 20210227: (later:-) Now have NSS tstclnt working against
my ``openssl s_server`` and my ``openssl s_client`` working
vs. the Cloudflare test deployment for draft-09 (which will
not be the last draft).

- 20210227: s_client works vs. CF with ciphersuite 0x1301 so
I guess I have a bug in handling 0x1302's hash output length
in the ECH confirmation magic bit calculation. And still
loads of leaks and code re-factoring needed, but can now
claim -09 interop for at least some credible setups.

- 20210227: NSS tstclnt and s_client now both working against
s_server, but s_client failing vs. CF deployment (looks like
the CF server decrypts ok, but I get a different SH.random
magic still)

- 20210226: Got NSS with ECH mostly working with s_server, to
the point NSS client figures the server has accepted the ECH,
but it then fails decrypting tickets so some key derivation is
likely wrong; CH server similarly seems to be accepting my
ECH from s_client, but I'm not seeing the right SH.random
magic bits

- 20210217: Started to play with NSS again as a comparison. Some
changes since I last did that. I created a ``nssdoech.sh`` script
for that. First off, it was saying that ECH/HPKE was disabled in
the build, so for the NSS build I tried:

            $ ./build.sh -Denable_draft_hpke=1

   and that seems to move things along a bit...

- 20210217: Moar testing against CF deployment. Various fixes
  being fixed... config_id and AAD for -09 sorta done but not
  succeeding so far. Next step is to build NSS and compare.

- 20210212: Added basic GREASE'ing to client and server.

- 20210211: Handshake with ECH is working, still need to do GREASE
and also proper calculation of server-random magic lower bits, but
otherwise ok. Integrating with apps (only s_client/s_server done
so far) with ECH differs a bit from ESNI in how and when information about
the inner/outer is made available to the application, but we managed
to hide that by moving the call to the application's server name callback.

- 20210210: We're using the following fields in the SSL.ext data structure:

    - client:
        - ech_attempted: ECH extension will be present in outer CH
        - ech_grease: We'll include a grease value as ECH extension
        - ech_done: saw magic server_random value (so decryption
            worked out)
        - ech_success: session based on inner CH established ok
    - server:
        - ech_attempted: ECH extension present in outer CH
        - ech_grease: Couldn't decrypt ECH so treating as GREASE
        - ech_done: Decryption of ECH succeeded
        - ech_success: session based on inner CH established ok

- 20210102: server side decrypt/decode of inner now sorta there, next
  up is to get the client to react correctly to the session (inner or
  outer-based) that gets established. (Note: there's some really ickky
  stuff still on the server side that'd be v. brittle if >1 extension
  ever interacts and one of those but not the other is "compressed."
  All that compression is just muck really;-)

- 20201228: got the call to ``hpke_dec`` succeeding now, next up to
  try put inner CH back together (when compressed) and use it

- 20201222: upgraded to HPKE-07 and did a bunch of valgrinding - next up
  is to get HPKE decrypt to work

- 20201203: Coded up as far as the ``hpke_enc`` call on the client - not
  really according to the draft but along same lines (waiting for an
  "interop" draft before I get too worried about precision)

- 20201027: Did a quick check of draft-02 suff - still seems ok with defo.ie,
  but ``./testclient.sh -H ietf.org`` doesn't work now, however that seems more
  like some cloudflare ops change as ``./testclient.sh -H rte.ie -c NONE`` does
  work. Probably no need to delve into full detail but IIRC the ``-c NONE``
  didn't used be needed so maybe Clouflare are now just more picky about
  the draft-02 cover SNI sent to 'em for some reason.

- 20201027: Tidied up hpke.c implementation so get rid of openssl build warnings
  and updated HPKE to draft-06, though still defaulting to draft-05
  (with the X-coordinate DH fix) in this build for now due to ESNI-08 spec
  brokenly calling for that.

- 20200928: back at it now that the github discussion-storm seems to have
  died down on the pre-08 changes

- Starting to do local ECH testing (ECH isn't actually happening yet,
  but soon:-), to do that, after you have a local ESNI stup working,
  then kick that off with:

            $ cd $HOME/code/openssl/esnistuff
            $ ./echsvr.sh -d
            ... in another window or whatever
            ... and assuming your ECHConfig is is ``echconfig.pem``
            $ ./echcli.sh -d -p 8443 -s localhost -H foo.example.com -P `./pem2rr.sh -p echconfig.pem`
            ... and see how it goes
            ... for now, it works but does no ECH at all

- Added [echsrv.sh](echsvr.sh), to run a local test server with ECH inputs.
  (That's obviously derived from [testserver.sh](testserver.sh).) Made
  corresponding additions (just to start, they're non-functional for now) to
  ``s_server.c``.

- More work on adding svcb - also noted that ietf.org no longer
  appears to be a good ESNI target via CF for some reason but
  others (e.g. rte.ie) are. I guess that must be down to a CF
  backend change of some sort.

- Added new APIs (``SSL_svcb_add`` and ``SSL_CTX_svcb_add``)
  for ingestion of SVCB/HTTPS RR values since we can't reliably
  distinguish those from ECHConfigs with the various possible
  encodings. That also means a new command line arg for the
  command line tools in general. Bit boring but needs to be done
  I guess. Also lead to some renaming as passing an ECHConfigs
  in doesn't involve any DNS RR any more. Now have the code
  for the 1st testable version of ``SSL_scvb_add()``.

- Simplified testclient.sh a bit to become echcli.sh - does more or
  less the same but losing some options that are no longer needed I
  hope. (testclient.sh will stay there for use with earlier/ESNI
  draft versions for now, just in case.)
    - That's not working yet because I need to do the DNS RRTYPE
      decoding stuff, but will fix soon.

- Next is to check production of a valid ECHConfig, seems sorta ok for
  now, I'm sure more'll turn up later.

- After a hiatus (20200619) due to other work, back at it now.
  First up is ECHO -> ECH renaming bikeshed compliance, which
  is done.

- Starting to create test setups for ECHO. Again, doing that a bit in
  parallel to what I did with ESNI so the eventual contribution to
  upstream can be better/smaller. ``esnistuff/doecho.sh`` is the
  start of that.
    - currently decodes a draft-06 format public key from command line

- Adding an "echo" (sub)command to the openssl command line tool to allow
  for generating private keys/ECHOConfig. Added an ``apps/echo.c`` file
  and associated changes to ``apps/build.info``, ``apps/progs.h`` and
  ``apps/progs.c``.
    - Added ``hpke.c`` to ``libcrypto`` via ``crypto/build.info``
      and ``util/libcrypto.num``

- The overall plan for ECHO: Since we need to change the APIs a bit, both
  because of ECHO and because of changes to OpenSSL upstream, I've taken the
opportunity to hide more internals of the ESNI/ECHO data structures. That
needed to be done at some stage anyway, so may as well do it now. The overall
plan will be to add new code for ECHO, so we'll see code fragments protected by
both ``OPENSSL_NO_ESNI`` and ``OPENSSL_NO_ECHO`` and some bits of code and data
structures that are repetitive. The hope is that we can remove the
``OPENSSL_NO_ESNI`` code before we're done. If support for draft-02 (as
deployed by CF today) continues to be needed longer term we can figure out how
best to handle that later. (The ``SSL_ESNI`` main data structure would be
changing a lot anyway to ditch unneeded fields that were just useful in early
interop, so this approach isn't as wasteful of time/LOC as it might seem.)
We'll also add an option in the openssl command line for generation of
ECHO public key values. Well - all that's the plan, we'll see how well
it survives meeting with reality:-)

- Remerged with upstream (20200331) - comment below still applies

- Remerged with upstream - started on 20200320 but didn't get done 'till 20200331 as
there were a bunch of internal changes to figure out due to upstream changes and some
distractions as well;-) Will likely re-do this again and then start on 1) a few
API changes to better match upstream (and that are just better:-) and 2) including the
ESNI->ECHO work in this branch of the fork. Some changes may be needed to get this to
work with apache etc. - those havne't been done to the forks of those servers yet.

- Remerged with upstream (20191219)

- Remerged with upstream (20191218)

- Attempted to fix msft windows build issues identified via gitlab. (Might
  take an iteration or two, as I don't have a windows build/test setup
  locally at the moment.)

- Fix a build issue with MacOS for issue#3 reported by patrickkh7788
  with suggested fix. (Thanks!)

- Made the ESNI callback more generic, so it suits what I needed
  for apache better, and various bits of apache tidying up - see [apache2.md](apache2,md)
  for more.

- Made a few tweaks to [make-esnikeys.sh](make-esnikeys.sh) and
  [nginx.md](nginx.md) to make it easier for others to replicate.

- Started to do some work on [apache2](apache2.md). Seems to work
in a localhost setup, and is now deployed at [https://defo.ie:9443/](https://defo.ie:9443/)

- TODO: revisit overriding the ``ESNIKeys.public_name`` value. When I specify
  "-c NONE" with testclient.sh script at the moment, we still get the public
name from the drat-04 ESNI RR. Could be I need a way to flag NONE as special to
``s_client`` from the command line. (I forget where that's at tbh;-) Right now,
"-c NONE" gets translated to "-noservername" but looks like I may need a
"-noservername-REALLY" or or a "-noservername-BUT-public-name-is-ok" or
something:-)

- 20191111: Seeing some valgrind issues with default/non-debug build that
disappear with a debug build, but that don't seem to affect functionality or (so
far) cause a crash. Not fully clear what's up yet.
    - Manually editing the Makefile to use "-g -O3" allows me to see where that
      (or I guess some related error) happens
    - Seems like the issue is related to extracting the GCM tag
      when calling
            EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG, taglen, tag)
      (See comments around ssl/esni.c:1893)
    - Looks like the problem may be in some SHA256 assembler
    - Building with ``./config no-asm`` seems to work ok and is good enough for
      us for now, at least for whenever I want to check things with valgrind.
    - Sent a
      [mail](https://mta.openssl.org/pipermail/openssl-users/2019-November/011503.html)
      to the openssl-users list

- Had to do some fix-up of ordinals in util/libssl.num and util/libcrypto.num to
  avoid a fail from ``make test``

- Similar thing for lighttpd and ``SSL_CTX_load_verify_locations``

- On 20191109 I re-merged my nginx fork with upstream, and then built against the
latest OpenSSL.  I had to fix up a couple of calls to now-deprecated OpenSSL
functions. I think I found non-deprecated alternatives for both. Those were:
    - ``SSL_CTX_load_verify_locations``
    - ``ERR_peek_error_line_data``

- Doing interop testing with https://tls13.1d.pw/ - it worked
  unless the server sent an HRR, (which it was doing about 50%
  of the time) in which case my side failed, so time to fix that;-)
    - That server also changes group with the HRR, so another
      code path exercised!
    - HRR handling seems to be as per draft-02, so haven't yet
      tested the HRR iv/aad label switching really - it's coded
      up but that path hasn't been run so far.
    - TODO: Check how/if nginz/lighttpd handle HRR

- Added an ``esni_trace_cb`` to ``s_client`` - basically the
  same as for the server side, but was useful when debugging
  HRR stuff (above).

- Added a bit more error checking to ``SSL_ESNI_dec`` - looks like some
  [people are playing](https://github.com/sftcd/openssl/issues/7) with
  that in some other context that hasn't been initialised in the same
  ways the ones I've tried. Apparently that was it as they closed the issue.

- Re-merged with upstream on 20191105
    - Got a compile error in CMP code when tracing on. Reported that
      to openssl-users. (No response so far.)

- Started to make changes due to internal review of man pages. Some of
  those changes are just man page text, others change function names to
  be more consistent, so I'll do commits one at a time.
    - change ``SSL_set_esnicallback_ctx`` to the more
      proper ``SSL_CTX_set_esni_callback``.
    - change ``SSL_esni_reduce`` to ``SSL_ESNI_reduce``
    - typo: "comman seperated" -> "comma separated"
    - various editorial changes to man pages
    - the various ESNI callback things are really just for print/debug;
      are only currently used by ``s_client`` and ``s_server`` and
      probably aren't needed by real web servers or client, so I've
      renamed them to make that clear. That means:
        - SSL_esni_client_cb_func -> SSL_esni_print_cb_func (typedef)
        - esni_cb -> esni_print_cb (within SSL/SSL_CTX)
        - SSL_set_esni_callback -> SSL_set_esni_print_callback
        - SSL_CTX_set_esni_callback -> SSL_CTX_set_esni_print_callback,
    - "covername" (or derivitives) could be counter-productive in terms of
      acceptance and adoption, maybe better to rename that, so we'll go with
      public_name_override for a value that is client-chosen to go in cleartext SNI
      (vs. public_name from ESNIKeys) and clear_sni on the server side for the value
      received as cleartext SNI - that's a bit of a change as I was using covername
      for both concepts, so I might bugger up teasing apart code changes from
      covername to one of those two, we'll see...
        - There are some man page and test script changes that also get
          rid of the word "cover"

- The original 2018 [design doc](./design.md) is by now outmoded, so you should
  probably ignore that. I'll keep it about for a while in case I
  want to re-use some text from there.

- Added an option to cause client to produce borked ciphertext so I
could test my server's tracing in that scenario. To get the client
to do that you first need to have tracing compiled in (see below)
and set an environment variable called ``OPENSSL_BREAK_ESNI``
to some value. If you do that, then the client will overwrite the
first 16 octets of the ESNI ciphertext with 0xaa values. That
also allowed me to fix some server-side tracing I couldn't otherwise
easily exercise.

- Added output of key pair file from ``mk_esnikeys`` for nginx-friendlier
  config. Use ``-k`` command line arg to pick name, default is "esnikeys.key"

- I wanted some more tracing to try help someone do interop against my server
so spent (too much!) time figuring out how to get additional tracing via the
OpenSSL trace API. Basically:

            $ cd $HOME/code/openssl
            $ ./config enable-ssl-trace enable-trace --debug -no-cmp
            ...
            $ make clean; make
            $ cd esnistuff
            $ ./testserver.sh -d
            ...lots and lots of output when a connection happens...

I added an ``esni_trace_cb`` callback function to ``s_server`` that
prints client IP, time, and lots of TLS details related to server processing
of a received ESNI extension. I also added tracing calls at all the exit points
of ``tls_parse_ctos_esni``. (Added even more of that, now inside ssl/esni.c,
to see how far we're (not) getting.)

- I modified ``SSL_CTX_esni_server_enable()`` so that you can also provide only
  one input file that contains both the ESNI private key in PEM format and a
PEM-encoded ESNIKeys. This is so I could configure such files in my
[nginx](./nginx.md) fork, in a way that seems more acceptable to upstream.
There are some corresponding changes to ``s_server`` as well to allow this to
be used - basically some changes to the command line arguments (apologies if
someone was depending on those not changing, but that'd have been a bad plan
anyway:-). We still need to test that with nginx and lighttpd but it seems to
work for my [testserver.sh](./testserver.sh).  In such a file, the private key
must be first, and that should look something like this:

            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VuBCIEIEDyEDpfvLoFYQi4rNjAxAz7F/Dqydv5IFmcPpIyGNd8
            -----END PRIVATE KEY-----
            -----BEGIN ESNIKEY-----
            /wG+49mkACQAHQAgB8SUB952QOphcyUR1sAvnRhY9NSSETVDuon9/CvoDVYAAhMBAQQAAAAAXYZC
            TwAAAABdlBoPAAA=
            -----END ESNIKEY-----

I started a thread on the [TLS list](https://mailarchive.ietf.org/arch/msg/tls/hMOQpQ12IIzHfOHhQjSmjphKJ1g)
about that.

- I now have an apparently working ESNI-enabled nginx: see the [notes](./nginx.md).
That is deployed on [defo.ie on port 5443](https://defo.ie:5443).

- I was advised to change a couple of function names from ``SSL_esni_*``
to ``SSL_CTX_esni_*`` which seems right, so I've done that. No functional
changes afaik.

- Added an ``SSL_esni_server_key_status`` API so a server can check how many
  keys are currently loaded. Server can then decide whether it can continue if
e.g. it flushed all keys except those loaded in the last hour and then the
server tried to load more keys but those all failed. In that case, if there are
still ESNI keys loaded the server may want to continue, but if the server is
configured to support ESNI and now has no keys is may be better to exit. (Well,
that's what I've done for lightttpd for now.)

- I made ``SSL_esni_server_enable`` safer even if given crap. Beforehand it
  crapped on the key table before exiting on (some) errors. The
``testserver.sh`` script now takes a ``-B`` input to cause that to happen on
startup by giving it a files for a bogus key pair.

- As part of the key loading work below, I added an ``age`` parameter (in
  seconds) to ``SSL_esni_server_flush_keys`` to allow keeping keys younger than
that.  And now when ``SSL_esni_server_enable`` is called, it checks if the
filenames were already loaded, and if so, whether the files modification time
is newer than when the contents were previously loaded. Between the two,
servers can, every N seconds, flush keys older than N seconds ad then (re-)load
their set of key files (e.g.  from a directory) without having to care about
internals of file content.  (I made the corresponding change in ligtthpd too.)

- Improving server key pair loading. We now store the private and public key
file names provided to ``SSL_esni_server_enable`` and the time at which those
were loaded. If a subsequent call to the same function has the same file
names, then we'll ignore the call if the files have not been modified since
we last loaded the key pair, but if the files have been modified since then,
we'll overwrite the already loaded key. If either file name is new, we'll
add a new key to the store.

- Added "ESNI only" setup to lighttpd build. Just to see if it's worth it.
It was a good bit more work than I thought to get it working as
it happened as I was trying to provide some "nice" fallback for that case.
In the end, I just fail the TLS connection and that works more easily.
That's deployed on [defo.ie](https://defo.ie) now.

- Deployed lighttpd on defo.ie. Seems to work nicely, so we're out of
the chewing gum and glue phase maybe:-)

- When adding code to the lighttpd server to reload ESNI keys periodically,
I realised I needed a way to ensure we don't just keep growing
the internal table of ESNI keys. Could likely be done better, but
for now, I've just defined a new function ``SSL_esni_server_flush_keys()``
that can be called before calling ``SSL_esni_server_enable()``.
The latter function gets called once for each currently valid
key.

- I made a fork of [lighttpd](https://github.com/sftcd/lighttpd1.4) and
have integrated ESNI with that. The main reason
is that it'll likely be simpler/quicker to get something working with
that than apache or nginx and we'll likely learn better how to tackle
the more popular web servers by first tackling a simpler one.
There's notes about that in [lighttpd.md](./lighttpd.md).

- Belatedly noting the existence of the instructions for
  [HOWTO build openssl and curl](./building-curl-openssl-with-ech.md).
  (Was reminded to do this because I had to modify the [curl-esni](curl-esni)
  shell script.)

- Added draft-04 (ESNIKeys.version==0xff03) keys to [defo.ie](https://defo.ie/) deployment
  and [test-examples](./test-examples.md) for local use. Had to tweak server side greasing
  code (was greasing even if not asked:-) - seems ok now, but more testing of the various
  combinations would be good. Had to modify [testclient.sh](./testclient.sh) to handle
  multi-valued RRs as drafts -03 and -04 use the same experimental RRTYPE.

- ``make test`` was unhappy
    - `` make test TESTS=test_provider V=1`` gives details
    - fixed via re-syncing with upstream again and a ``make update``

- Currently have an "Invalid read" of 8 bytes that's annoying but apparently doesn't
  cause a crash. Somewhere in ``ssl/esni.c:esni_hkdf_extract`` - looks like there's
  been some internal change that causes my inputs to functions around ``EVP_PKEY_derive``
  no longer be appropriate. That's not a shocker though as I don't claim to be
  familiar with all the details there - I've mostly copied such code from other
  bits of TLS1.3 stuff;-) Maybe this'll force me to try understand it better.
    - re-merged with upstream on 20190912 and this problem seems to have disappeared.
    I may still need to change code in ``ssl/esni.c`` around line 1650 to
    handle the lengths better, but it seems to be back working cleanly now
    (according to valgrind).

- Re-merged with upstream again (20190911)

- Added some thoughts as to how one might [configure a web server](web-server-config.md) for ESNI,
  for discussion before we start coding stuff up.

- Next up will be to really do the re-try stuff if a client gets back a real ESNIKeys in-band.
  But, I need to check out HRR a bit first I guess so see how that's handled as it has some
  similarities.

- Trying to address the CI armv4/android build error that's been happening for a while.
  I made the change below to ``crypto/ec/asm/ecp_nistz256-armv4.pl`` as I was getting
  the error described below. Note that this is untested and I have no clue as to its
  potential effect so it'll need to be checked out sometime.

            # OPENSSL_NO_ESNI
            # I (sftcd) made this change so my CI builds for armv4 don't fail
            # but I currently have no way to test that this works or not, it
            # just builds with this change.
            # without this change I get an error about .rodata
            # that says:
            # crypto/ec/ecp_nistz256-armv4.S:9: Error: unknown pseudo-op: `.rodata'
            # See https://gitlab.com/sftcd/openssl/-/jobs/266946709/raw for an example
            # OLD:
            #
            # $code.=<<___;
            # .rodata
            # .globl    ecp_nistz256_precomputed
            # .type ecp_nistz256_precomputed,%object
            # .align    12
            # ecp_nistz256_precomputed:
            # ___
            #
            # NEW:
            ########################################################################
            $code.=<<___;
            .globl  ecp_nistz256_precomputed
            .type   ecp_nistz256_precomputed,%object
            .align  12
            ecp_nistz256_precomputed:
            ___
            # OPENSSL_NO_ESNI

- Added a placeholder ``doc/man3/SSL_esni_enable.pod`` to keep the ``make doc-nits`` target
  happy (the CI build was complaining about it). There's no actual content in that file yet,
  so it's just one big TODO for the moment;-)

- Added code to handle changes in ESNI from server to client (``esni_retry_requested`` and
related). Mostly in ``ssl/statem/extensions_server.c``
and ``ssl/statem/extensions_clnt.c`` that currently includes:
    - Move to -03/-04 ``esni_accept`` containing struct in EncryptedExtensions
    - If greased or failed and ESNIKeys loaded, return an ESNIKeys value that should work
    - Server-side trial decryption option, if so configured
        - testserver.sh new ``-T`` option, ``SSL_OP_ESNI_TRIALDECRYPT`` added along with ``s_server`` command line option
        - added a ``#ifdef BREAK_RECORD_DIGEST`` compile time option to ``ssl/statem/extensions_clnt.c``
          so I could test trial decryption - that really ought be part of the openssl ``make test`` setup and
          I've left a TODO in the code to that effect
    - If there're no ESNIKeys loaded, yet we receive an ESNI extension, then the
      server randomly returns a random value that's randomly chosen as either a nonce length (16) or
      roughly the length of an ESNIKeys. That code is in ``tls_construct_stoc_esni``.
        - had to add an ``esni_attempted`` field to SSL struct to control this and so
          that the ``make test`` target passes
        - Note: This is not in the I-D, and is added by me so
          it might disappear if/when the I-D addresses this topic.)

- Added some code to make GREASE more accurate, can now produce either
ciphersuite 0x1301 (80% of the time), or 0x1303 with (I think) more
accurate lengths and real public share values.

- Fixed GREASE error handling so that ``make update`` target works.

- Finally switched around so that locally supplied covername wins over
  ``ESNIKeys.public_name``. The opposite never really made sense but I
  do do that sometimes;-)
    - Latterly, fixed up ``SSL_get_esni_status`` to also reflect that

- GREASE: close to done here, I hope...
    - As an aside, I already have GREASE extensions in ``mk_esnikeys``:-)
    - Added a version value of ``ESNI_GREASE_VERSION`` (0xffff) for use in
      the ``SSL_ESNI`` structure.
    - Added a function ``SSL_ESNI_grease_me`` to create the phoney value.
      For the moment, that just hard codes x25519 and otherwise sets non-bogus
      looking (but actually bogus) random crap.
    - Call out to the above on the client from ``tls_construct_ctos_esni``
    - Added an ``SSL_OP_ESNI_GREASE`` for the client (taking a reserved
      bit in a field, need to check if that's ok), and added a new CLA
      to ``s_client``: ``--esni_grease`` if you want to do greasing (so
      client is off by default). Need to figure out how that can be
      done via config file.
    - Added an ``SSL_OP_ESNI_HARDFAIL`` server config (taking another
      reserved bit in a field) that defaults to off. So we'll fall back
      to the cleartext SNI by default and only hardfail on ESNI if
      this is set. That enables GREASE. Need to figure out how that
      can be done via config file.

- Started coding up [draft-04](https://tools.ietf.org/html/draft-ietf-tls-esni-04).
None of this should affect processing of earlier versions for now.  The list of
fairly minor changes is:
    - Did the ``mk_esnikeys.c`` changes first to produce a sample
    - Added the RR value decoding into an ``SSL_ESNI`` changes (not really tested yet)
    - Fixed up structure changes in ``SSL_ESNI_print`` and ``SSL_ESNI_dup``
    - Tidied up death of ``not_before``/``not_after``
    - Changed input bytes for ``record_digest``
    - Switched from ServerNameList to opaque for input to ``esni_pad``

- Re-merged with upstream again (20190717) since the last took a few days.
    - Some more oddities there too, suspect my work-arounds will need to
      be tweaked next time.

- Re-merged with upstream (20190714) prior to starting in on -04 code
    - Well, that took a while. I had to move esnierr.c within crypto/build.info
      as with the latest Configure script it was somehow being added into a FIPS
      target and hence not building. The wonders of perl mean that I dunno why
      that was happening;-)

- draft-04 has been published (20190708), some good, some more-iffy, changes
    - initial [notes](./03-04.md) on the changes therein

- Fixed what looks like a case where ``s_server`` just hangs
  when started with ``-www`` and where renegotiation is
  not supported and where the URL's pathname starts with "/reneg"
  Also made the ``-WWW`` mode (where it acts as a teeny
  web server for files) a little better.
  None of these are really ESNI-related changes but could
  be suggested as indepndent improvements/fixes. Not sure
  if anyone cares enough, but maybe when/if I make a PR for
  ``cert_chain2`` I'll include these too.

- Added zone file fragment production for draft-02 TXT RRs to
  ``mk_esnikeys`` and a JSON format output option
  from which e.g. a ZSK holder can build the DNS
  zone file stanza(s) - we'll be using that internally
  as a format to use when communicating between the
  cover/hidden web server and the DNS zone-file factory,
  which aren't co-located, at least in our test deployment.

- Minor oops, fixed misleading comments as to the name of ``SSL_get_esni_status``

- Changed ``mk_esnikeys.c`` so that DNS TTL is duration/2 and
actual key lifetime is 1.5 times specified "main" duration.

- Added a ``-V`` input to ``testclient.sh`` so caller can pick to try
different draft versions.

- Fixed issue with ``SSL_ESNI_get_status`` where it (yet again) wasn't
picking the right array element to report on. Did that by just checking
that there's exactly one array element with a nonce set (only happens
after successful decrypt or encrypt). There's TODO's in the code - I
need to go back and change all this so the array handling is better.
(Maybe change so only one ``SSL_ESNI`` structure is passed from the
``SSL_CTX`` factory to the ``SSL`` session-specific structure?)

- Tidied up ``SSL_ESNI_print`` API documentation.

- Seems like FF nightly may have an issue if I publish >1 TXT RR with
an ESNIKeys value. Behaviour seems to be that ESNI isn't attempted.
Need to check the code but guess (TBC) is that it doesn't like the two
RR values. Likely I'll need to change to publish just one RR for the
draft-02 key at a time, instead of two. That appears to have worked,
so just one TXT RR at a time so;-)

- My test client was failing sometimes - it thought the returned nonce
length wasn't right, even though it seems to be correct from dumped values.
Issue was having >1 ESNI RR value in client and not picking the right
array element against which to compare. Seems fixed now.

- There was an, I guess,
  thread-related issue in ``esni_cb`` in ``s_server`` causing eventual (but
fairly speedy) crashes of ``s_server`` when dumping out the ``SSL_ESNI``
content. I changed the callback prototype so that the output string to print is
returned from the library to the application via the callback rather than
having the application access a pointer to the ``SSL_ESNI`` structure with the
``SSL`` structure for the session. The problem with the latter was that the
``SSL_ESNI`` will be modified by each new connection.  (Recall we're storing
and printing out much more now than we eventually will, so were this to remain
a problem we'd have a few ways to handle it.) After various tests, seems
to be ok now, but more testing may show up problems still.

- Tweaked ``testclient.sh`` to also take ESNI RR value from command
line (as well as filename for that).

- Now that I've gotten FF nightly interop done, have tweaked the output
from ``s-server -www`` a bit. Also changed how the ``SSL_SESSION.ext.hostname``
is set when we do get an ESNI. Not sure yet if I've got that right. Left a
TODO in ``ssl/statem/extensions_srvr.c`` in the ctos handler. For now,
that results in a correct-looking display in FF nightly, but need to
figure out how it might play with use of SessionTickets/resumption
and early data. (Probably gotta go back to the spec to see what it
says on that.)

- Trying FF nightly vs. my test server and getting an ESNI decrypt error.
  After a bit of messing with NSS's ``tstclnt`` the standalone tester works ok
again now. (I had to add a ``-b`` command line argument in ``nssdoit.sh``.)
``tstclnt`` btw adds a ``dummy.invalid`` cover name in the h/s which routes
correctly for me to ``s_server`` as I default my server to trying ESNI and
ignoring the SNI (it's recorded and displayed as covername but not used for
keying.) ``tstclnt`` only sends one key share value in the h/s key share
extension, whereas FF nightly sends two. OpenSSL TLS1.3 code currently ignores
key shares that it doesn't need for the h/s and I've just been taking the value
selected for use in the h/s and encoding that as the AAD for ESNI en/decrypt.
Looks like I ought be taking the encoded set of all key shares from the CH as
the AAD instead, based on the text in the Internet draft.  Looking at the NSS
code, (``lib/ssl/tls13esni.c:876``,) it seems like that's also what they're
doing.  I'll need to muck about a bit to store the encoded key shares in the
SSL session I guess as it's not previously been kept, and I can't put it into
the ``SSL_ESNI`` structure because (on the server anyway) I don't yet know
which ESNI key pair will be in play, nor even if ESNI is being tried (when I'm
processing the h/s key share extension). That'll change the ``SSL_ESNI_dec``
API a bit (though not the prototype, mostly the calling code and a bit of the
implementation) so, a bit of work to do before I can make another useful FF
nightly test...
    - Yay! That worked, got FF nightly interop

- While doing the above, I found a leak on the server side (about 2k/session).
I've fixed that now but need to go back an re-visit how I handle the
array of ``SSL_ESNI`` stuff in general - there are two levels of it,
which is one too many:-) There's a FIXME in ssl/esni.c in the comment
before ``SSL_esni_enable``.

- I fixed ``SSL_SESSION_print`` to handle ESNI better by adding covername
  to ``SSL_SESSION.ext`` IIRC ext.hostname and ext.encservername are handled
  differently on client and server at the moment. Simplest fix is probably to add
  all the name fields and then have the print function figure out what to print based
  on which of those are non-null. Maybe a better fix would be to try get rid of
  that discrepency between client and server code. (Cause for which IIRC was that
  I didn't really understand ``SSL_CTX`` vs. ``SSL_SESSION`` at first;-)
  Not quite done with this yet. Also notices a leak on the server that I need
  to track down.

- Fixed a crash if some bad ESNI RR values supplied  - decoding bug due to
  signed error value treated as ``size_t``

- Made some changes to testclient.sh in preparation for setting up my
  own test server (should be soonish;-). Part of that involved running
  ``s_server`` with real certs instead of my locally generated fake
  CA. As a result I needed the server to send the intermediate CA cert
  to the client, but in my testserver I'm using the ``s_server`` key2/cert2
  command line arguments and it turns out that ``apps/s_server.c`` doesn't
  actually associate the ``cert_chain`` command line argument's cert
  bundle with key2/cert2/ctx2. I'll check it with the maintainers but
  for the moment I just added the ``s_chain`` variable as an input
  to the relevant call to ``set_cert_key_stuff`` instead of a NULL.
  Left a FIXME there. It's on line 2354 of my current version of
  ``s_server.c`` and on line 2029 on the same file in upstream.

- Re-merged with upstream (20190505)

- Updated ``make-esnikeys.sh`` script to use version 0xff02 (draft-03).
  All seems fine.

- Changed ``SSL_ESNI_enc`` to do the "pick longest lived" RR value
  scheme described below. Similar change to check the returned
  nonce vs. all RR value structures in EncryptedExtensions (a
  change in the ``ssl/statem/extensions_clnt.c`` file).

- Added ``not_before`` and ``not_after`` fields to ``SSL_ESNI_ext``
  structure. Might be that gives me a nice out that let's me avoid
  adding an X.509-like notAfter bug to the library! Logic is that
  library code can pick the pubblic key that'll be valid longest
  (latest ``not_after``) as a default but that anything more (incl.
  comparing to wall-clock time!) is up to the application. Next
  up will be to add selection of one from many RR values in the
  encryption process.

- Fixed ``make update`` target and added proper error string
  handling to new APIs.

- Added new APIs for allowing application to access some (new) internals of
  ESNIKeys RR. Not yet documented in design.md, and still need to add the
  proper OpenSSL error string handling, but those are:

    - ``SSL_esni_query`` to extract more easily understood bits
    of ESNIKeys RR (public_name and addresses)
    - ``SSL_ESNI_reduce`` to allow application to downselect
    to the stuff from one RR based on output of the above
    - ``SSL_ESNI_ext_free`` to allow application to free the
    "nicer" format info from ``SSL_esni_query``
    - ``SSL_ESNI_ext_print`` to whack that to stdout etc.

  See the next point down for why...

- Added parsing of AddressSet extension into ``BIO_ADDR`` structure, with
  a view to providing a new API that allows the application to see which
  ``public_name`` and IP address combinations exist and to then allow the
  appliction to select amongst those. (Those two new APIs aren't defined
  yet but are reasonably obvious.) A reason for this design (that we really
  ought note in the design document is that it avoids the library doing
  anything like happy eyeballs or similar which a library cannot do.)

- Added a greasy option to ``mk_esnikeys`` (``-g`` funnily enough:-) to add
  some greasy/nonsense extension values to the ESNIKeys RR value. It adds
  one random length extension before and one after the AddressSet extension.
  If either of those random lengths are even numbers, then it also adds an
  extension with no value as well. So we can get a max of 5 extensions for
  the moment.

- Adding initial code for parsing of AddressSet extension for ESNIKeys version
  0xff02 (draft-03). Seem to be creating and parsing that ok now. Not acting
  on it yet, nor handling >1 extension.

- Re-merged with upstream. (20190402)

- Ditched the idea of parsing dig output within library - 'twas a silly idea:-)

- Better multi-valued RR support now, seems to be working okish. Some changes to
  API for that, that are not yet reflected in the [design](design.md) document.
  TODO: update design document when the -03 draft is more done.

- Added reading of new (in -03) ``public_name`` ESNIKeys field. When present, that
  currently takes precedence over a locally supplied covername for including in the
  cleartext SNI extension. TODO: Re-consider that, maybe move to the opposite if
  covername is locally supplied, not sure which'd be better. If we do switch that,
  then should take out use of covername as a default in test scripts.

- Added support for multi-valued RR inputs. For b64, that's comma-separated. For binary,
  or ascii-hex just a catentation is enough. (That's down to b64 padding being harder
  to find in the middle of a catenated input;-)
  This has only been tested via the [``doit2.sh``](doit2.sh) script.

- Added a ``ekfmt`` input to ``SSL_ESNI_new_from_buffer()`` with possible values as below:

                #define ESNI_RRFMT_GUESS     0  ///< try guess which it is
                #define ESNI_RRFMT_BIN       1  ///< binary encoded
                #define ESNI_RRFMT_ASCIIHEX  2  ///< draft-03 ascii hex value(s catenated)
                #define ESNI_RRFMT_B64TXT    3  ///< draft-02 (legacy) base64 encoded TXT

    The dig output variant isn't yet done, and more testing is needed.

- Modified [testclient.sh](./testclient.sh) script to first check the draft-03 RRTYPE
  before checking the draft-02 TXT RR. That needed a bit of mucking about within the
  script to provide one command line arg that's just ascii-hex to ``s_client``. (Other
  things could be possible, I chose that:-). Seems to work with multi-valued cases
  now too.

- Generalised a bit from base64 encoded ESNIKeys inputs (not tested ascii-hex nor binary
  input options yet but will as we go)

- Starting to work on coding up [draft-03](https://tools.ietf.org/html/draft-ietf-tls-esni-03)
  from now,  will try keep [draft-02](https://tools.ietf.org/html/draft-ietf-tls-esni-02) working
  as the default for now, but we'll see how that goes, and will switch defaults later, depending
    - Played with DNS a bit as -03 has a new ESNI RRTYPE (value 0xffdf == 65439) instead of TXT
        - to query for such a thing, published at example.com, who turn out to have two ESNIKeys RRs:

                $ dig +short -t TYPE65439 example.com
                \# 81 FF027CE3FD9C000B6578616D706C652E6E65740024001D00208C48CF 4B00BAAF1191C8B882CFA43DC7F45796C7A0ADC9EB6329BE25B94642 35000213010104000000005C9588C7000000005C9EC3470000
                \# 81 FF02FF93090D000B6578616D706C652E636F6D0024001D00202857EF 701013510D270E531232C40A09226A83391919F4ED3F6B3D08547A7F 68000213010104000000005C93BA56000000005C9CF4D60000

        - to publish such a thing in example.com's zone file it'd look like:

                ;;; ESNIKeys stuff,
                example.com. IN TYPE65439 \# 81 (
                             ff02 ff93 090d 000b 6578 616d 706c 652e
                             636f 6d00 2400 1d00 2028 57ef 7010 1351
                             0d27 0e53 1232 c40a 0922 6a83 3919 19f4
                             ed3f 6b3d 0854 7a7f 6800 0213 0101 0400
                             0000 005c 93ba 5600 0000 005c 9cf4 d600
                             00 )
                example.com. IN TYPE65439 \# 81 (
                             ff02 7ce3 fd9c 000b 6578 616d 706c 652e
                             6e65 7400 2400 1d00 208c 48cf 4b00 baaf
                             1191 c8b8 82cf a43d c7f4 5796 c7a0 adc9
                             eb63 29be 25b9 4642 3500 0213 0101 0400
                             0000 005c 9588 c700 0000 005c 9ec3 4700
                             00 )

        - strangely enough, that all seems to just work when we tried it with
          dummy values in a zone-we-own:-)

- First coding step is to kick off with the modest changes needed to [mk_esnikeys.c](./mk_esnikeys.c).
        - added ``-V``,``-P`` and ``-A`` command lines arguments, it produces
        some output that could possibly be the the right encoding (but isn't
        likely to be yet, as I've not tested that:-)

- Re-merged with upstream. (20190313)

- Started to look at ESNI-enabling curl. Paused that for
  a bit, now that draft-03 has landed (and someone else may be doing
  work on that I can re-use later). (Later: @20190923 I deleted
  those curl notes as they're superseded.)

- I took a look a building [wget](wget.md) with this but it seems like
  wget is a tad too far behind openssl upstream to make that easy and
  so would be more work that warranted right now, esp as integrating
  openssl with wget2 for TLS seems to be in-work at the moment.
  (Will likely revisit this later.)

- Caught up with upstream, had to tweak a few bits'n'pieces for build
  and ``testclient.sh`` but nothing that should affect a consumer of
  the library who can re-build. (Changes to ordinals I expect would
  need that at least on some OSes, not sure.)

- CI folks told me ``make update`` was failing, which it was. Seems there're
  parts of the build I'd not played with before and where I previously
  did manual edits but should've been configuring tool stuff.
  Got the ``make ordinals`` sub-target to work,
  which updates ``util/lib[ssl|crypto].num`` more or less (but not quite) the same as I'd
  previously done manually. The ``make errors`` bit took more work.
  ``crypto/err/README`` turns out to have some advice when I stumbled
  over that:-) So I had to make all the ``ESNIerr`` macro calls use a
  first parameter/string derived from the actual function name, which
  I guess is both good and a bit anal. After that with a whack load of messing
  about (due to unwinding then re-winding previously manually done
  changes), stuff eventually worked out. I don't rule out the possibility that
  this still isn't quite right, and I do bet there'll be more work
  to do when porting to e.g. windows, but hopefully these changes
  will make that easier. (I am confident that if I have to figure out
  those changes from scratch again, it'll be near as much a PITA;-()

- Added a call to ``SSL_esni_get_status`` to ``s_server.c`` callback for tracing
  and cleaned up a bit of the over-verbosity of ``s_server`` generally.

- Added a `-L` command line option to ``testclient.sh`` to turn off ``esni_strict``
  if desired (with ``esni_strict`` being on by default for the script but off by
  default for ``s_client``).

- Surprisingly (for me:-) this works:

            $ ./testclient.sh -H ietf.org -c 254systemlabelifikeepadding00000000000000000000000000000000000111111111111111111111111111111111122222222222222222222222222222222222244444444444444444444444444445666666666666666666666666666666666666666666666666666677777777777777777777777777777777777777776

    i.e., connecting to www.cloudflare.com with an SNI they don't serve and an
ESNI that they do... is fine. The SNI value doesn't have to be a real or even a
valid DNS name (I think!). The one above is 254 octets long. (255 or more
octets aren't accepted by the ``openssl s_client``) Not sure what'd be right
there TBH.  Probably wanna ask CF about that. I did. They just ignore SNI if a
good ESNI is present, which is reasonable, if a small surprise.

- rebased my code as advised by @eighthave to make CI stuff easier/better (not
  that I fully understand the mechanics here;-). That involved doing this:

            $ git remote add upstream https://github.com/openssl/openssl.git
            $ git fetch upstream
            $ git merge upstream/master
            ...some mucking with merge fails...
            $ git push -f origin master

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
  hidden name matching the server cert then ``SSL_get_esni_status``
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
  and added ``SSL_get_esni_status()`` API for that. Also tweaked the
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
  server) - I discovered I wasn't handling the client h/s key share at all (heh:-)
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

- Integration with wget
- Adding/moving tests to the OpenSSL test suites
- Once we've integrated with some real client/server test the effect of our
  crude padding scheme.
- Security review: identify which parts of the code e.g. need to be constant
  time, which need to use special OpenSSL APIs, which need support for
  crypto h/w (if any)

