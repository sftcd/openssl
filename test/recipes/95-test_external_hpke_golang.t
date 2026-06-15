#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Run an interop test between the OpenSSL HPKE implementation and
# that from golang. The test code for both languages can generate
# an HPKE key pair, and attempt to encrypt/decrypt a file. So we
# do that in both directions.
#
# We need golang 1.26 or better for this to work.

use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT data_file bldtop_dir srctop_dir cmdstr/;

setup("test_external_hpke_golang");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");
plan skip_all => "External HPKE tests not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32)$/;
    #plan skip_all => "External ECH tests only available in a shared build"
    #if disabled("shared");
plan skip_all => "External HPKE tests not supported in out of tree builds"
    if bldtop_dir() ne srctop_dir();
plan tests => 1;

ok(run(cmd(["sh", data_file("hpke_golang_external.sh")])),
   "running HPKE external golang tests");

