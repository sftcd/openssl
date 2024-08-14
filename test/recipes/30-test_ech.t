#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2022, Oracle and/or its affiliates.  All rights reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
#use OpenSSL::Test;              # get 'plan'
#use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_dir bldtop_file/;

setup("test_ech");

plan skip_all => "This test is unsupported in a no-ec build"
    if disabled("ec") || disabled("ech");

plan skip_all => "No TLS/SSL protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));

plan tests => 1;

ok(run(test(["ech_test", srctop_dir("test", "certs")])))

    # simple_test("test_ech", "ech_test ../test/certs");

