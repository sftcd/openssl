#!/bin/bash

set -ex

# Run this to update the ECH-PR branch from the ECH-draft-13c branch
# while squashing the commits into something more manageable

# Using this, the workflow for handling comments on the ECH PR is to
# do edits to ECH-draft-13c, then re-run this when happy, and it'll
# do a force-push of the ECH-PR branch, with those changes

# To allow for testing, we have an option set the destination branch
# to be a throw-away test one (prb) instead of the actual PR branch
# (which is ECH-PR).

# Master branch, expected to be up to date (i.e. rebased)
MBRANCH="master"
# ECH branch, expected to be up to date (i.e. rebased) and
# with all ECH changes we want to get into the PR
SBRANCH="ECH-draft-13c"
# Destination branch, the one that's used for the PR
# DBRANCH="ECH-PR"
# newb is a test branch I pushed to github to test this before
DBRANCH="newb"
# Temporary branch
TBRANCH="temp-ECH-PR"
# Where our OpenSSL code lives
REPO="git@github.com:sftcd/openssl.git"

TDIR=$(mktemp -d)

echo "Running $0 in $TDIR"

cd $TDIR
# get the code
git clone $REPO
cd openssl
# start from our ECH enabled branch
git checkout $SBRANCH
# make a new temporary branch
git checkout -b $TBRANCH
# "uncommit" changes (leaving files as-is)
git reset --soft $MBRANCH
# make changes ready for add/commit
git restore --staged .

# remove things we don't want to push to the PR
rm -rf esnistuff debian .github/workflows/packages.yaml

# restore some things to what master has
git checkout README.md .gitignore

# now add our ECH modified files

git add INSTALL.md doc/build.info doc/man1/build.info doc/man1/openssl-s_client.pod.in doc/man1/openssl-s_server.pod.in doc/man1/openssl.pod doc/man3/SSL_CTX_set_options.pod doc/designs/ech-api.md doc/man1/openssl-ech.pod.in doc/man3/SSL_ech_set1_echconfig.pod
git commit -m "ECH: docs and similar"
git add apps/build.info apps/lib/s_cb.c apps/s_client.c apps/s_server.c apps/ech.c apps/list.c
git commit -m "ECH: command line changes"

git add Configurations/unix-Makefile.tmpl Configure util/libcrypto.num util/libssl.num util/perl/TLSProxy/Message.pm crypto/err/openssl.txt ssl/build.info util/platform_symbols/unix-symbols.txt util/platform_symbols/windows-symbols.txt
git commit -m "ECH: internals - build artefacts"
git add include/internal/packet.h include/openssl/pem.h include/openssl/ssl.h.in include/openssl/sslerr.h include/openssl/tls1.h ssl/s3_enc.c ssl/ssl_err.c ssl/ssl_lib.c ssl/ssl_local.h ssl/ssl_stat.c ssl/ssl_txt.c ssl/t1_enc.c ssl/t1_trce.c ssl/tls13_enc.c
git commit -m "ECH: internals - library tweaks"
git add ssl/statem/extensions.c ssl/statem/extensions_clnt.c ssl/statem/extensions_cust.c ssl/statem/extensions_srvr.c ssl/statem/statem_clnt.c ssl/statem/statem_local.h ssl/statem/statem_srvr.c
git commit -m "ECH: extensions/state machine changes"
git add include/internal/ech_helpers.h include/openssl/ech.h ssl/ech.c ssl/ech_helpers.c ssl/ech_local.h
git commit -m "ECH: new ECH internals"
git add demos/sslecho/Makefile demos/sslecho/README.md demos/sslecho/echecho.c test/build.info test/evp_extra_test.c test/ext_internal_test.c test/recipes/75-test_quicapi_data/ssltraceref-zlib.txt test/recipes/75-test_quicapi_data/ssltraceref.txt test/sslapitest.c test/certs/echconfig.pem test/certs/echserver.csr test/certs/echserver.key test/certs/echserver.pem test/certs/echwithexts.pem test/certs/echwithmand.pem test/certs/fe_cert.pem test/certs/fe_key.pem test/certs/newechconfig.pem test/ech_split_test.c test/ech_test.c test/echcorrupttest.c test/recipes/30-test_ech.t test/recipes/30-test_ech_split.t test/recipes/80-test_echcorrupt.t fuzz/echclient.c fuzz/echserver.c fuzz/echsplit.c test/recipes/95-test_external_ech_bssl.t test/recipes/95-test_external_ech_bssl_data/ test/recipes/95-test_external_ech_nss.t test/recipes/95-test_external_ech_nss_data/ test/recipes/99-test_fuzz_echclient.t test/recipes/99-test_fuzz_echserver.t test/recipes/99-test_fuzz_echsplit.t fuzz/build.info fuzz/client.c fuzz/helper.py test/README-external.md
git commit -m "ECH: test code and related"

# Now push the result to the ECH-PR (or pretend version)
git push -f origin $TBRANCH:$DBRANCH

# clean up
rm -rf $TDIR
