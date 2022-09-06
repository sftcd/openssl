#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2022, Oracle and/or its affiliates.  All rights reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

<<<<<<< HEAD
use strict;
use OpenSSL::Test;              # get 'plan'
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_hpke");

plan skip_all => "This test is unsupported in a no-ec build"
    if disabled("ec");
=======

use OpenSSL::Test::Simple;
>>>>>>> 2067773a13 (new HPKE API (not yet used her) and moved test code to it's own test case)

simple_test("test_hpke", "hpke_test");
