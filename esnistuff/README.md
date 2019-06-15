
# This is a temporary place for ESNI content ...

Stephen Farrell, stephen.farrell@cs.tcd.ie, 20190403-ish

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
about how it works and what it does. (That's not yet updated for
draft-03 stuff really.)

# State-of-play...

There's a [TODO list](#todos) at the end.

Most recent first...

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
    - ``SSL_esni_reduce`` to allow application to downselect
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

- Started to look at ESNI-enabling [curl](curl.md) Paused that for
  a bit, now that draft-03 has landed (and someone else may be doing
  work on that I can re-use later).

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


- If we do end up with >1 ESNIKeys version that needs to be supported, 
  consider some kind of local "any" version value that a 
  server can use to force use of a public share regardless of the
  the ESNIKeys.version used by the client. That more easily allows
  multiple $hidden sites to hide behind one key pair belonging to
  some operator.
- Had a look at how [lightttpd](https://github.com/lighttpd/lighttpd1.4/blob/master/src/mod_openssl.c) 
  integrates OpenSSL and that might be a nicely viable build into which to
  integrate our ESNI without too much effort. (Seems like latest OpenSSL and TLS1.3
  have been integrated/working since 1.4.51-1 from Oct 2018 when someone 
  fixed a [bug](https://bugs.archlinux.org/task/60294) caused by TLS1.3.)
- Code up support for [draft-03](https://tools.ietf.org/html/draft-ietf-tls-esni-03#section-8.3)
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


