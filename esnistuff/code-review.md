
# Code review of OpenSSL ECH Changes

[Pass-1](#Pass-1) started, 20210624, ended 20210705.
[Pass-2](#Pass-2) started, 20210706, ended 20210803.

All code changes are protected via ``#ifndef OPENSSL_NO_ECH`` so 
running a find for that we get the list below. (We'll do a cross
check vs. the master branch too later.)

A similar exercise will be needed for our [HPKE code](https://github.com/sftcd/happykey).

## Pass-2

[Pass-1](#Pass-1) generated a bunch of TODOs and I also left
a few of the core files to consider after I'd sorted out a
pile of the more trivial changes. We'll see how many of those
I fix properly in this pass. (There will be a few that need
to wait until the IETF standardisation process is done.)

            $ find . -type f -exec grep -l OPENSSL_NO_ECH {} \;
            ./include/openssl/ssl.h.in
            ./include/openssl/pem.h
            ./include/openssl/ech.h
            ./include/openssl/tls1.h
            ./include/openssl/ssl.h
            ./ssl/ssl_sess.c
            ./ssl/tls13_enc.c
            ./ssl/t1_trce.c
            ./ssl/record/ssl3_record_tls13.c
            ./ssl/ech_local.h
            ./ssl/s3_enc.c
            ./ssl/ech.c
            ./ssl/ssl_txt.c
            ./ssl/statem/statem_local.h
            ./ssl/statem/extensions.c
            ./ssl/statem/extensions_srvr.c
            ./ssl/statem/extensions_clnt.c
            ./ssl/statem/statem_clnt.c
            ./ssl/statem/statem_lib.c
            ./ssl/statem/statem_srvr.c
            ./ssl/ssl_local.h
            ./ssl/ssl_lib.c
            ./esnistuff/haproxy.html
            ./esnistuff/haproxy.md
            ./esnistuff/README.md
            ./esnistuff/code-review.md
            ./test/buildtest_ech.c
            ./apps/lib/s_cb.c
            ./apps/ech.c
            ./apps/s_client.c
            ./apps/s_server.c

### ``./include/openssl/ssl.h.in``

Clean (enough). We could add an option related to padding
I guess but given there are APIs for that already that's
fine to leave for now.

### ``./include/openssl/pem.h``

Clean.

### ``./include/openssl/ech.h``

* **TODO**: ``ech_pbuf`` and ``ech_ptranscript`` are sometimes
  inside, and sometimes outside ``#ifndef OPENSSL_NO_SSL_TRACE``
  protection. Fix that by moving them all inside. Better to do
  that after draft-13 interop success, so one for later.

* Explained ``HPKE_MAXSIZE`` usage
* Found some better OpenSSL constants where I'd #define'd new ones.
* Moved strings used in ECH key derivation to ``ssl/ech_local.h``
* Re-tested the ``-svcb`` command line with ascii-hex and base64
* Re-tested the ``-echconfigs`` input formats (ascii-hex, b64)
* Fleshed out ``SSL_ech_query`` and associated.
* Added new ``SSL_ech_get_status`` codes to indicate that an
  ECH was returned (after GREASE or a failed attempt).
* Added new external API ``SSL_ech_get_returned`` to allow
  application access to that ECHConfig, e.g. so it could
  be used in a subsequent attempt.
* Removed ``SSL_ECH_STATUS_TOOMANY`` as it wasn't really used.
  (Was an ESNI hangover really.)

Otherwise seems ok.

### ``./include/openssl/tls1.h``

Good. No real change in pass#2.

### ``./include/openssl/ssl.h``

Good. No change in pass#2.

### ``./ssl/ssl_sess.c``

Had a placeholder comment there but seems like we don't really
need ECH specific changes there (for now at least).

### ``./ssl/tls13_enc.c``

No change since pass#1 the only ECH code here is added tracing.

### ``./ssl/t1_trce.c``

No change since pass#1.

### ``./ssl/record/ssl3_record_tls13.c``

No change since pass#1. Only ECH code here sets the ``s->ext.ech_success``
for the client once some decryption has happened well.

### ``./ssl/ech_local.h``

* Turned off ``ECH_SUPERVEBOSE`` for now. (And then back on:-)
* Removed ``config_id_len`` field and fixed ``config_id`` as one octet
* Removed ``dns_alpns`` and ``dns_no_def_alpn`` from ``SSL_ECH`` as those 
  are better handled outside the library.
* Removed some no longer needed prototypes and tidied up others.
* Added ``s->ext.ech_returned`` and length.

### ``./ssl/s3_enc.c``

Only tracing. All good.

### ``./ssl/ech.c``

* **TODO** We currently use a truly ephemeral ECH key pair but will
  have to store that for HRR purposes when we get to that.

* Removed ``dns_alpns`` and ``dns_no_def_alpn`` from ``SSL_ECH`` as those 
  are better handled outside the library.
* Added new return value to handle case where server tries to (re)load
  a key pair but the file isn't readable - could happen if the server
  periodically calls ``SSL_CTX_ech_server_enable`` which is expected
  behaviour
* Added a buffer input equivalent of ``SSL_CTX_ech_server_enable``
  (oddly called ``SSL_CTX_ech_server_enable_buffer``:-) so that haproxy 
  doesn't have to read disk after startup. (Also added test code for 
  that to ``apps/s_server.c``.)
* Fixed semantics of ``public_name`` override in 
  ``SSL_ech_server_name`` and related functions.
* Output more information from ``SSL_ech_print`` and added
  call to ``s_client``.
* Fixed semantics of ``SSL_CTX_svcb_add`` and ``SSL_svcb_add`` to be 
  additive if multiple calls made.
* Moved outer compression tables to top of file and tidied 'em up.
* Fixed an issue with non-contiguous to-be-ECH-compressed exts
  in encoded inner CH.
* Noted that ``init_ech`` is also called after SH rx'd so fixed
  that to not reset ``ech_done``.
* Fixed a crash in ``SSL_SESSION_free`` for the inner
  SSL struct, if ECH is was attempted but failed due to
  wrong ECH public key. (Fixed a client leak when wrong 
  public key used as a after that fix.)
* Moved call to ECH callback from accept confirm (which'll change)
  to better place in ``ech_swaperoo``.
* Reverted changes to how ``final_server_name`` is called as 
  those are no longer needed now we're doing the early ECH
  decryption attempt on the server. (That's nice as it means
  we no longer need to special case SNI for this part of
  extension processing.)
* Tidied up ``hpke_decrypt_encch``, ``ech_earcy_decrypt`` and a few 
  other server-side utility functions.
* Fixed a few issues with handling ECHConfigs that have 
  more than one ECHConfig.
* Found and fixed (return error) an error state where client 
  could send both GREASE and real ECH if application asked 
  for both. (Server handled it correctly.)
* Various minor fixes for handling >1 ECHConfig in ECHConfigs.
  A number of cases where we previously just initialised the
  first ``SSL_ECH`` in the array and needed to do them all.
* Added many more bounds checks to ``ech_decode_inner`` to
  void invalid memory accesses if we get random or bad 
  plaintext after decryption.

### ``./ssl/ssl_txt.c``

Nothing here yet but HRR will force something.

### ``./ssl/statem/statem_local.h``

* Removed no longer needed ``tls_construct_client_hello_with_ech``
  prototype. Otherwise seems ok.

### ``./ssl/statem/extensions.c``

* Replaced the hacky way I'd been correcting the overall 3-octet
  length of the CH when calculating binders by setting that
  based on ``s->ext.innerch_len`` (that's in ``tls_do_psk_binder``)
  which seems much more easily understood and even correct:-)

### ``./ssl/statem/extensions_srvr.c``

* Cosmetic tidying.

### ``./ssl/statem/extensions_clnt.c``

* Cosmetic tidying.

### ``./ssl/statem/statem_clnt.c``

* Cosmetic tidying.

### ``./ssl/statem/statem_lib.c``

* Cosmetic tidying.

### ``./ssl/statem/statem_srvr.c``

* Cosmetic tidying.

### ``./ssl/ssl_local.h``

* Cosmetic tidying.

### ``./ssl/ssl_lib.c``

* **TODO**: re-examine the ECH parts of ``SSL_free`` - some
  of the cases where we do/don't deep-copy ECH fields is too 
  ad-hoc - the worry being that give rise to leaks in error
  cases.
* Cosmetic tidying.

### ``./esnistuff/haproxy.html``

N/A.

### ``./esnistuff/haproxy.md``

N/A.

### ``./esnistuff/README.md``

N/A.

### ``./esnistuff/code-review.md``

N/A.

### ``./test/buildtest_ech.c``

N/A.

### ``./apps/lib/s_cb.c``

No change needed.

### ``./apps/ech.c``

* Added a new option for printing ECHConfig files:

            $ openssl ech -pemin foo.pem 
            ...prints contents...

  The file ``foo.pem`` can contain a private key and ECHConfig or just an
  ECHConfig.
  In order to test multi-valued inputs, we created a new shell script
  [mergepems.sh](mergepems.sh) that allows us to merge ECHConfigs into one PEM
  file that we can load. 
* Fixed an ECHConfig generation bug when ``public_name`` is empty
* Got the multiple ECHConfig in ECHConfigs stuff tested.
* Added down selection to pick one for printing with ``-pemin`` when dealing
  with multi-valued ECHConfigs. (Use the script above to marge multiple PEM
  files.)

            $ openssl ech -pemin foo.pem [-select 2] 
            ...prints contents...

### ``./apps/s_client.c``

* Added a down selection ``s_client`` command line input 
  (``-select``) as per ``-pemin`` above.
* Made other cosmetic changes.

### ``./apps/s_server.c``

* Cosmetic clean-ups.

## Pass-1

            $ find . -type f -exec grep -l OPENSSL_NO_ECH {} \;
            ./include/openssl/ssl.h.in
            ./include/openssl/pem.h
            ./include/openssl/ech.h
            ./include/openssl/tls1.h
            ./include/openssl/ssl.h
            ./crypto/ec/asm/ecp_nistz256-armv4.pl
            ./ssl/ssl_sess.c
            ./ssl/tls13_enc.c
            ./ssl/s3_lib.c
            ./ssl/t1_trce.c
            ./ssl/ssl_conf.c
            ./ssl/record/ssl3_record_tls13.c
            ./ssl/ech_local.h
            ./ssl/s3_enc.c
            ./ssl/ech.c
            ./ssl/ssl_txt.c
            ./ssl/statem/statem_local.h
            ./ssl/statem/extensions.c
            ./ssl/statem/extensions_srvr.c
            ./ssl/statem/extensions_clnt.c
            ./ssl/statem/statem_clnt.c
            ./ssl/statem/statem_lib.c
            ./ssl/statem/statem_srvr.c
            ./ssl/ssl_local.h
            ./ssl/ssl_lib.c
            ./esnistuff/haproxy.html
            ./esnistuff/haproxy.md
            ./esnistuff/README.md
            ./test/buildtest_ech.c
            ./apps/lib/s_cb.c
            ./apps/ech.c
            ./apps/s_client.c
            ./apps/s_server.c

The plan for now is to look at each file and make notes here.
In parallel, we'll be testing for agility etc. as described
[here](agility.md).

### ``./include/openssl/ssl.h.in``

...and off we go: there was a **TODO** in that:-)

This defines ECH-related flags and has prototypes for
a few functions.

Of the flags:

* ``SSL_OP_ECH_HARDFAIL`` - deleted that one - it made sense for ESNI but 
doesn't really for ECH 
* ``SSL_OP_ECH_GREASE`` - documented
* ``SSL_OP_ECH_TRIALDECRYPT`` - documented

There were also prototypes for the ECH callbacks and for 
setting outer ALPN - I moved those to ech.h for now. (All of ech.h
might end up in ssl.h eventually, but not yet.) 

### ``./include/openssl/pem.h``

Just defines ECHCONFIG as a PEM string, so that's fine.

### ``./include/openssl/ech.h``

**TODO** revisit this when more nitty ones done.

I added ``ECH_PUBLIC_NAME_OVERRIDE_NULL`` here as a const
external variable. Not sure how that ought be reflected in
``util/libssl.num`` so that's another **TODO**.

### ``./include/openssl/tls1.h``

Just defines the extension type codes for TLS, so that's fine.
(Note that the WG process of changing these per-interop target
means this'll change as we do that, and we might have two
different values for some time-windows if we want to support
both old/new at once.)

### ``./include/openssl/ssl.h``

See ssl.h.in above, this one's generated from that.

### ``./crypto/ec/asm/ecp_nistz256-armv4.pl``

The earlier gitlab-based CI objected to code in this file
so we found a work-around. It seems that's no longer a problem
so we've reverted this to the content of the file from
the master branch.

### ``./ssl/ssl_sess.c``

Another **TODO**! What to send as SNI when resuming? I guess
using ``public_name`` and re-doing ECH seems to be 
what's called for, so we probably need to note that the
session used ECH, and what ``public_name`` was used 1st
time around.  (We need setter/getter methods for those 
fields here.) And we probably need to do stuff in
the client and server to handle that properly.

There are some questions here though, so I sent a
[mail](https://mailarchive.ietf.org/arch/msg/tls/uMhAL5JBJmac4b-6JFtPaiY6tPw/)
to the TLS WG list. Will come back to this when
that thread resolves.

**TODO** revisit this when resumption list discussion done.

### ``./ssl/tls13_enc.c``

The only ECH code here is added tracing, to help with interop
as we mess with the transcript so none of that code likely needs
to be upstreamed ever - IOW, this one's fine.

### ``./ssl/s3_lib.c``

There's ECH code here for setting to null and freeing. I don't
think that's needed, but it might I guess with some set of API
calls that I've forgotten. I've ifdef'd that code out for now
and added a comment in case it turns up later but expectation
is that code can stay out.

### ``./ssl/t1_trce.c``

This just has a bit of tracing for the new ECH related extensions.
Seems fine.

### ``./ssl/ssl_conf.c``

Code just allows setting our two options (grease/trial decrypt) in 
a config file. Seems fine but hasn't been tested. Turned out that
figuring out how to actually test that was waaay too much effort
so I deleted (both lines of:-) the ECH code.

### ``./ssl/record/ssl3_record_tls13.c``

This just sets ``s->ext.ech_success`` to 1 for clients if we 
managed to decrypt something.

**TODO** revisit use of ``s->ext.inner_s`` and ``s->ext.outer_s`` there,
  those mightn't be needed any more with the ``ECH_UPFRONT_DEC`` branch.

### ``./ssl/ech_local.h``

**TODO** revisit this when more nitty ones done.

### ``./ssl/s3_enc.c``

This just has some additional tracing that can be dropped
later.

### ``./ssl/ech.c``

**TODO** revisit this when more nitty ones done.

### ``./ssl/ssl_txt.c``

Code here is a placeholder for printing ECH related information
for/from a stored session. The answer here will be obvious but
will depend on what we store in the session.

**TODO** revisit this when resumption list discussion done.

### ``./ssl/statem/statem_local.h``

Just a bunch of prototypes, but a reminder tha we don't
really need the ``*_ech_outer_exts()`` functions as that's
handled in earlier. So removed those from here and the
other ``ssl/statem/extensions*.c`` files.

### ``./ssl/statem/extensions.c``

draft-10 imposed a requirment that the ECH handlers be after the 
``key_share`` handles in the extensions table (so that we can 
correctly calculate the ECH accept signal). That's removed in
draft-11, so left a **TODO** in for that. 

For ECH, we need a special check when we get one back in 
an encrypted extension if we really tried ECH but used the
wrong key - because of the outer extensions stuff we don't
set the usual "we sent that extension" flag when we send
ECH, so we need a special check (around line 670). Tried
a couple of other ways to handle that, but ended up keeping
the check and just adding an explanatory comment.
That, plus some new test cases with real ECH attempts with
the wrong key, lead to a bunch of changes and clean-ups.

Was also seemingly superflously setting the ``ech_attempted``
flag when it'd be set already so removed that code. 

``final_server_name`` prototype moved to ``statem_local.h``

**TODO**: added a new hacky bit of code to fix up the
transcript when calculating binders - shows up the need
for some kind of more generic transcript API probably
(as we had to fix the overall CH 3-octet length which
isn't really writable for that code) 

### ``./ssl/statem/extensions_srvr.c``

The few bits of code there seem sensible. ("Few bits" because
we attempt ECH decryption before so most of the actul code's 
in ech.c:-)

### ``./ssl/statem/extensions_clnt.c``

**TODO** Looks like there's a missing thing - what to do when we get an
ECHConfig back having GREASE'd (or if our attempt was considered GREASE).
Probably needs a new API and a new error code and a new element in the SSL
struct.

**TODO** check out early data handling - that's yet to be tested.
The ``IOSAME`` macro call within ``tls_construct_ctos_early_data`` in
particular.

I took out a setting of ``ech_attempted`` from ``ctos_ech`` when GREASEing -
that might break something I've forgotten but shouldn't be needed.

### ``./ssl/statem/statem_clnt.c``

``ssl_cipher_list_to_bytes`` prototype moved to ``statem_local.h``

Added a good few more comments to clarify how we're re-using code
and what's new for ECH. Surprisingly (for me:-) the code itself
was fairly clean.

### ``./ssl/statem/statem_lib.c``

Took out a change within ``ssl_version_supported`` that seemed 
no longer needed, at least as far as current tests indicaete.

Otherwise just one change here, to avoid a double-free on the
transscipt (``init_buf``).

**TODO** consider if there's a generally better way to handle
the transcript than messing with ``init_buf`` - do that while
coding up HRR specifics as those will likely involve most 
transcript munging. 

### ``./ssl/statem/statem_srvr.c``

This has a couple of TODOs that should be attended to,
likely when draft-12 is implemented. (The particularly
hacky write of the accept signal into the packet 
probably should be a new ``WPACKET_foo`` API.

**TODO**: Replace ``SSL_ech_print`` with something
more lasting.

### ``./ssl/ssl_local.h``

* Removed a couple of no-longer used fields: ``ech_dropped_from_ch``
(and it's length).
* **TODO**: move "More ECH details" fields into within ext
  substructure same as others, e.g. ``s->ech --> s->ext.ech``
  same for ``s->nechs`` and ``s->ech_cb`` - only reason to 
  not do it yet is pressed for time right now and it affects
  9 c files.
* **TODO**: consider moving ``alpn_outer`` into ECHConfig, but
first check ALPN stuff in SVCB speec.

### ``./ssl/ssl_lib.c``

* **TODO**: At the expense of making the diff vs. upstream worse, we could
collect together the various ECH specific tests in ``SSL_free`` (e.g.
``INOUTFREE`` and friends).  That might make upstream merges harder though to
leave it for later.
* Moved ``SSL_CTX_set_ech_alpn_protos`` and ``SSL_set_ech_alpn_protos``
from here to ``ssl/ech.c`` where they belong better (for now), and
also re-named 'em to ``SSL_CTX_ech_set_outer_alpn_protos`` and
``SSL_ech_set_outer_alpn_protos`` for better consistency and clarity.
(Did a similar naming improvement with ``SSL_ech_set_callback`` 
becomming ``SSL_ech_set_callback`` and same for ``SSL_CTX``
version.)
* Some tidy-up of copies within ``SSL_dup()`` and similar for
``alpn_outer`` and ``ech_grease_suite``.

### ``./esnistuff/haproxy.md``

N/A

### ``./esnistuff/README.md``

N/A

### ``./test/buildtest_ech.c``

N/A

### ``./apps/lib/s_cb.c``

Only new code here added strings for the new extension types, so
all's good.

### ``./apps/ech.c``

**TODO** will come back to this @ end.

### ``./apps/s_client.c``

* tweaked ``new_session_cb`` - that needs testing (it's been a while
since I tried out session storage/resumption)
* made a few changes for session storage/resumption (leading to
a new added temporary hack to ``ssl/statem/extensions.c``)

### ``./apps/s_server.c``

* **TODO**: do some confirmatory testing on padding - added code
to pad ``ctx2`` as needed.
* **TODO**: not really ECH specific, but if ``ctx2`` is set then 
it ought also be possible to set a second ``schain`` file that
has a different set of CA certs for ``ctx2`` 
* Bits of tidy-up around ``SSL_ech_get_status`` handling.
