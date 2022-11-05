/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ech.h>
#include <openssl/hpke.h>
#include "testutil.h"

//static OSSL_LIB_CTX *testctx = NULL;
//static char *testpropq = NULL;

static int basic_echconfig_gen(void)
{
    int res = 1;
    unsigned char echconfig[400];
    size_t echconfig_len = sizeof(echconfig);
    unsigned char priv[200];
    size_t privlen = sizeof(priv);
    uint16_t ech_version = OSSL_ECH_DRAFT_13_VERSION;
    uint16_t max_name_length = 0;
    char *public_name = "example.com";
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char *extvals = NULL;
    size_t extlen = 0;

    res=ossl_ech_make_echconfig(echconfig, &echconfig_len, priv, &privlen,
                                     ech_version, max_name_length, public_name,
                                     hpke_suite, extvals, extlen);
    if (!TEST_int_eq(res,1))
        return 0;

    return res;
}

int setup_tests(void)
{
    ADD_TEST(basic_echconfig_gen);
    return 1;
}
