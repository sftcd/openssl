#!/bin/bash

# This is the script I used to make the ECH-PR from the ECH-draft-13c
# branch. It's main purpose is to squash all the 550+ dev commits into
# 7 that are functionally grouped.

WHERE=`/bin/pwd`

if [[ "$WHERE" == "/home/stephen/code/openssl/" ]]
then
    echo "Not doing that here."
    exit 1
fi

git checkout ECH-draft-13c # dev branch
rm -rf esnistuff
git checkout -b ECH-PR # new branch
git reset --soft master # "uncommit" changes (leaving files as-is)
git restore --staged . # make changes ready for add/commit
git checkout README.md .gitignore
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
