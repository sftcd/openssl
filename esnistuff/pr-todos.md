
# Notes after PR posted

This is just a place for notes after the
[ECH PR](https://github.com/openssl/openssl/pull/22938) was posted on
2023-12-04.

- DONE 2023-12-11: Fuzzer (in ~/code/openssl-fuzz) finds crash caused
  [here](https://github.com/sftcd/openssl/blob/ECH-draft-13c/ssl/ech.c#L2675)
  as pointer ``c`` isn't checked for NULL before de-reference on next line.
  Moar fuzzing to follow!

- DONE 2023-12-06: [review
  comment](https://github.com/openssl/openssl/pull/22938#pullrequestreview-1767215068):
  "The libcrypto.num and libssl.num changes looks just wrong. Please reset the
  libcrypto.num and libssl.num files to pristine from the master branch and run
  make update." Did that.

- 2023-12-05: with haproxy split-mode+HRR we end up calling
  ``SSL_CTX_ech_raw_decrypt()`` too many times (a flaw in our haproxy
  integration rather than here - we're calling this also for the CH sent from FE
  to BE after initial decryption - but that's a haproxy issue). The issue for
  OpenSSL is that before really trying decrypting, we check there's no
  outstanding OpenSSL errors first and fail if there were.  (Done in
  ``ssl/ech.c:2220`` via a call to ``ERR_peek_erro()``.) Could be that we could
  do better inside the library, e.g. by checking for new errors or something
  rather than having to clear all of 'em in haproxy before attempting decryption.

- DONE 2023-12-04: ``test/ech_split_mode`` renamed e.g. to
  ``test/ech_split_test`` to match the ``test/*test`` line in ``.gitignore``.

# Preparation: Things to do for an ECH PR

Text below was written in preparation for the ECH PR which has now been
posted.

Our current branch (ECH-draft-13c) isn't quite right for using to make a
PR for ECH.

## Reasons

- The ``esnistuff`` directory content needs to be moved elsewhere
- ``include/openssl/ech.h`` should be integrated into ``ssl.h.in``, which
  means minor changes to application integrations
- The ``ech_ext_handling`` tables in ``ssl/ech.c`` should maybe be
  integrated with the ``ext_defs`` table in ``ssl/statem/extensions.c``
- Code behind ``ifdef SUPERVERBOSE`` should probably stay until nearly the last
  minute, then be dropped

## Plan

- (TODO) Create a new ``ech-dev-utils`` repo that gets all the ``esnistuff``
  scripts we want to keep
- Everything else to happen in a new branch for the PR.
- (DONE) "Promote" the current ECH code-points to being the "official" ones as
  soon as the early IANA code-point registration thing is done.
- (DONE) Integrate ``ech.h`` into ``ssl.h.in`` (we'll later have to re-do all
  the integrations that included ``ech.h``, but that's only a timing tweak)
- (NOT DONE) integrate the new function pointers in ``ext_ech_handling`` into
  the ``ext_defs`` table in ``extensions.c``? (Current thinking: better done
  later, first get review of compile-time handling of which extensions to
  ECH-modify/copy/compress, and that may be easier with the new table in
``ech.c`` rather than merging into ``ext_defs`` first.)
- (DONE) Squash all the dev commits so that the PR ends up with a small number
  of separate, less gigantic, commits to help reviewers have more easily
  consumed chunks for examination. The set of commits in the initially-submitted
  PR will end up as shown in the ``git`` commands below.

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

There're a couple of files to reset:

            git checkout README.md .gitignore

The files/commit and order in which to do commits is as below:

            git add INSTALL.md doc/build.info doc/man1/build.info doc/man1/openssl-s_client.pod.in doc/man1/openssl-s_server.pod.in doc/man1/openssl.pod doc/man3/SSL_CTX_set_options.pod doc/designs/ech-api.md doc/man1/openssl-ech.pod.in doc/man3/SSL_ech_set1_echconfig.pod
            git commit -m "ECH: docs and similar"
            git add apps/build.info apps/lib/s_cb.c apps/s_client.c apps/s_server.c apps/ech.c
            git commit -m "ECH: command line changes"

			git add Configurations/unix-Makefile.tmpl Configure util/libcrypto.num util/libssl.num util/perl/TLSProxy/Message.pm crypto/err/openssl.txt ssl/build.info util/platform_symbols/unix-symbols.txt util/platform_symbols/windows-symbols.txt
			git commit -m "ECH: internals - build artefacts"
			git add include/internal/packet.h include/openssl/pem.h include/openssl/ssl.h.in include/openssl/sslerr.h include/openssl/tls1.h ssl/s3_enc.c ssl/ssl_err.c ssl/ssl_lib.c ssl/ssl_local.h ssl/ssl_stat.c ssl/ssl_txt.c ssl/t1_enc.c ssl/t1_trce.c ssl/tls13_enc.c
			git commit -m "ECH: internals - library tweaks"
			git add ssl/statem/extensions.c ssl/statem/extensions_clnt.c ssl/statem/extensions_cust.c ssl/statem/extensions_srvr.c ssl/statem/statem_clnt.c ssl/statem/statem_local.h ssl/statem/statem_srvr.c
			git commit -m "ECH: extensions/state machine changes"
			git add include/internal/ech_helpers.h include/openssl/ech.h ssl/ech.c ssl/ech_helpers.c ssl/ech_local.h
			git commit -m "ECH: new ECH internals"
            git add demos/sslecho/Makefile demos/sslecho/README.md demos/sslecho/echecho.c test/build.info test/evp_extra_test.c test/ext_internal_test.c test/recipes/75-test_quicapi_data/ssltraceref-zlib.txt test/recipes/75-test_quicapi_data/ssltraceref.txt test/sslapitest.c test/certs/echconfig.pem test/certs/echserver.csr test/certs/echserver.key test/certs/echserver.pem test/certs/echwithexts.pem test/certs/echwithmand.pem test/certs/fe_cert.pem test/certs/fe_key.pem test/certs/newechconfig.pem test/ech_split_mode.c test/ech_test.c test/echcorrupttest.c test/recipes/30-test_ech.t test/recipes/30-test_ech_split_mode.t test/recipes/80-test_echcorrupt.t
            git commit -m "ECH: test code and related"

