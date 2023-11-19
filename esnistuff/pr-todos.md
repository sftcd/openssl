# Things to do for an ECH PR

Our current branch (ECH-draft-13c) isn't quite right for using to make a
PR for ECH.

## Reasons

- The ``esnistuff`` directory content needs to be moved elsewhere
- ``include/openssl/ech.h`` should be integrated into ``ssl.h.in``, which
  means minor changes to application integrations
- The ``ech_ext_handling`` tables in ``ssl/ech.c`` should in the end be
  integrated with the ``ext_defs`` table in ``ssl/statem/extensions.c``
- Code behind ``ifdef SUPERVERBOSE`` should probably stay until nearly the last
  minute, then be dropped

Aside from those issues, it'd be great to figure a way to break this all down
into more than one PR, but can't see a way to do that.

## Plan

- Create a new ``ech-utils`` repo that gets all the ``esnistuff`` scripts
  we may want to keep, but that shouldn't be in the PR
- "Promote" the current ECH code-points to being the "official" ones as soon
  as the early IANA code-point registration thing is done.
- Everything else to happen in a new branch for the PR.
- Integrate ``ech.h`` into ``ssl.h.in`` (we'll later have to re-do all the
  integrations that included ``ech.h``, but that's only a timing tweak)
- (Maybe) integrate the new function pointers into the ``ext_defs`` table
  in ``extensions.c``? (Might be better done later, not sure - could be
  better to get review of compile-time handling of which extensions to
  ECH-modify/copy/compress, and that may be easier with the new table in
  ``ech.h`` rather than merging into ``ext_defs`` first.)
- (Somehow?) Squash all the dev commits, and then do some rebasing so
  that the PR ends up with a small number of separate commits to help
  reviewers have more easily consumed chunks for examination. The set
  of commits in the initially-submitted PR might then end up as:
    - docs: the ECH API design doc + pod files
    - CLI: command line additions
    - modified internals: existing files where we add some ECH internal API calls
    - new internals: ``ech.c`` and co
    - tests: new test code
- That'll get messy as review comments are handled, but probably anything
  will, so maybe that's ok?

The above will probably take a couple of attempts before we're at the point
where we want to actually open the PR, so trying it out will be a thing.

## Recipe

Possible recipe to do the above, just after rebasing, if our PR branch were to
be ``prb``:

            $ git checkout ECH-draft-13c # dev branch
            $ git checkout -b prb # new branch
            $ git reset --soft master # "uncommit" changes (leaving files as-is)
            $ git restore --staged . # make changes ready for add/commit
            # delete stuff not needed, git add stuff wanted, when checkpoint reached
            $ git commit -m "commit message"
            # repeat above 'till all done, then
            $ git push -u origin prb

The order in which to do commits needs a bit of work.  I still need to figure
the way to distribute the added/modified file changes between commits sensibly.
Last time I did this (pre-pre2 branch) the set of commits looked like:

            git add INSTALL.md doc/build.info doc/man1/build.info doc/man1/openssl-s_client.pod.in doc/man1/openssl-s_server.pod.in doc/man1/openssl.pod doc/man3/SSL_CTX_set_options.pod doc/designs/ech-api.md doc/man1/openssl-ech.pod.in doc/man3/SSL_ech_set1_echconfig.pod
            git commit -m "ECH: docs and similar"
            git add apps/build.info apps/lib/s_cb.c apps/s_client.c apps/s_server.c apps/ech.c
            git commit -m "ECH: command line changes"
            git add Configurations/unix-Makefile.tmpl Configure crypto/err/openssl.txt include/internal/packet.h include/openssl/pem.h include/openssl/ssl.h.in include/openssl/sslerr.h include/openssl/tls1.h ssl/build.info ssl/s3_enc.c ssl/ssl_err.c ssl/ssl_lib.c ssl/ssl_local.h ssl/ssl_stat.c ssl/ssl_txt.c ssl/statem/extensions.c ssl/statem/extensions_clnt.c ssl/statem/extensions_cust.c ssl/statem/extensions_srvr.c ssl/statem/statem_clnt.c ssl/statem/statem_local.h ssl/statem/statem_srvr.c ssl/t1_enc.c ssl/t1_trce.c ssl/tls13_enc.c util/libcrypto.num util/libssl.num util/perl/TLSProxy/Message.pm include/internal/ech_helpers.h include/openssl/ech.h ssl/ech.c ssl/ech_helpers.c ssl/ech_local.h
            git commit -m "ECH: internals"
            git add demos/sslecho/Makefile demos/sslecho/README.md demos/sslecho/echecho.c test/build.info test/evp_extra_test.c test/ext_internal_test.c test/recipes/75-test_quicapi_data/ssltraceref-zlib.txt test/recipes/75-test_quicapi_data/ssltraceref.txt test/sslapitest.c test/certs/echconfig.pem test/certs/echserver.csr test/certs/echserver.key test/certs/echserver.pem test/certs/echwithexts.pem test/certs/echwithmand.pem test/certs/fe_cert.pem test/certs/fe_key.pem test/certs/newechconfig.pem test/ech_split_mode.c test/ech_test.c test/echcorrupttest.c test/recipes/30-test_ech.t test/recipes/30-test_ech_split_mode.t test/recipes/80-test_echcorrupt.t
            git commit -m "ECH: test code and related"

Nex time around I'll break up the "internals" commit above into chunks like
this as it had 9k (of the overall 17k) LOC by itself:

			git add Configurations/unix-Makefile.tmpl Configure util/libcrypto.num util/libssl.num util/perl/TLSProxy/Message.pm crypto/err/openssl.txt ssl/build.info
			git commit -m "ECH: internals - build artefacts"
			git add include/internal/packet.h include/openssl/pem.h include/openssl/ssl.h.in include/openssl/sslerr.h include/openssl/tls1.h ssl/s3_enc.c ssl/ssl_err.c ssl/ssl_lib.c ssl/ssl_local.h ssl/ssl_stat.c ssl/ssl_txt.c ssl/t1_enc.c ssl/t1_trce.c ssl/tls13_enc.c
			git commit -m "ECH: internals - library tweaks"
			git add ssl/statem/extensions.c ssl/statem/extensions_clnt.c ssl/statem/extensions_cust.c ssl/statem/extensions_srvr.c ssl/statem/statem_clnt.c ssl/statem/statem_local.h ssl/statem/statem_srvr.c
			git commit -m "ECH: extensions/state machine changes"
			git add include/internal/ech_helpers.h include/openssl/ech.h ssl/ech.c ssl/ech_helpers.c ssl/ech_local.h
			git commit -m "ECH: new ECH internals"
