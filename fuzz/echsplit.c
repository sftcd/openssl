/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/* Shamelessly copied from BoringSSL and converted to C. */

/* Test ECH split mode */

#include <time.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include "fuzzer.h"

/* unused, to avoid warning. */
static int idx;

#define FUZZTIME 1485898104

#define TIME_IMPL(t) { if (t != NULL) *t = FUZZTIME; return FUZZTIME; }

/*
 * This might not work in all cases (and definitely not on Windows
 * because of the way linkers are) and callees can still get the
 * current time instead of the fixed time. This will just result
 * in things not being fully reproducible and have a slightly
 * different coverage.
 */
#if !defined(_WIN32)
time_t time(time_t *t) TIME_IMPL(t)
#endif

#ifndef OPENSSL_NO_ECH
unsigned char s_echconfig[400];
size_t s_echconfiglen = sizeof(s_echconfig);
unsigned char priv[200];
size_t privlen = sizeof(priv);
uint16_t ech_version = OSSL_ECH_RFCXXXX_VERSION;
uint16_t max_name_length = 0;
char *public_name = "example.com";
OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
unsigned char *extvals = NULL;
size_t extlen = 0;
char echkeybuf[1000];
size_t echkeybuflen = sizeof(echkeybuf);
#endif

int FuzzerInitialize(int *argc, char ***argv)
{
    STACK_OF(SSL_COMP) *comp_methods;

    FuzzerSetRand();
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ASYNC, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    comp_methods = SSL_COMP_get_compression_methods();
    if (comp_methods != NULL)
        sk_SSL_COMP_sort(comp_methods);

#ifndef OPENSSL_NO_ECH
    if (ossl_ech_make_echconfig(s_echconfig, &s_echconfiglen,
                                priv, &privlen,
                                ech_version, max_name_length,
                                public_name, hpke_suite,
                                extvals, extlen) != 1)
        return 0;
    snprintf(echkeybuf, echkeybuflen,
             "%s-----BEGIN ECHCONFIG-----\n%s\n-----END ECHCONFIG-----\n",
             priv, (char *)s_echconfig);
    echkeybuflen = strlen(echkeybuf);
#endif

    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    SSL_CTX *ctx;
    int ret;
#ifndef OPENSSL_NO_ECH
    unsigned char *inner = NULL;
    size_t innerlen = 0;
    char *inner_sni = NULL, *outer_sni = NULL;
    int dec_ok = 0;
#endif

    if (len < 2)
        return 0;

    /* This only fuzzes the initial flow from the client so far. */
    ctx = SSL_CTX_new(SSLv23_method());

    ret = SSL_CTX_set_min_proto_version(ctx, 0);
    OPENSSL_assert(ret == 1);
    ret = SSL_CTX_set_cipher_list(ctx, "ALL:eNULL:@SECLEVEL=0");
    OPENSSL_assert(ret == 1);

#ifndef OPENSSL_NO_ECH
    ret = SSL_CTX_ech_server_enable_buffer(ctx, (unsigned char *)echkeybuf,
                                           echkeybuflen, SSL_ECH_USE_FOR_RETRY);
    OPENSSL_assert(ret == 1);
    /* outer has to be longer than inner, so this is safe */
    innerlen = len;
    inner = OPENSSL_malloc(innerlen);
    OPENSSL_assert(inner != NULL);
    memset(inner, 0xAA, innerlen);
    /* so far, dec_ok will never happen, fix that in a bit */
    SSL_CTX_ech_raw_decrypt(ctx, &dec_ok, &inner_sni, &outer_sni,
                            (unsigned char *)buf, len,
                            inner, &innerlen, NULL, NULL);
    OPENSSL_free(inner);
#endif

    ERR_clear_error();
    SSL_CTX_free(ctx);

    return 0;
}

void FuzzerCleanup(void)
{
    FuzzerClearRand();
}
