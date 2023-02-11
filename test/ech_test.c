/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include <openssl/hpke.h>
#include "testutil.h"
#include "helpers/ssltestlib.h"

#ifndef OPENSSL_NO_ECH

# define OSSL_ECH_MAX_LINELEN 1000 /* for a sanity check */

/*
 * The command line argument one can provide is the location
 * of test certificates etc, which would be in $TOPDIR/test/certs
 * so if one runs "test/ech_test" from $TOPDIR, then we don't
 * need the command line argument at all.
 */
# define DEF_CERTS_DIR "test/certs"

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_LIB_CTX *testctx = NULL;
static char *testpropq = NULL;
static BIO *bio_stdout = NULL;
static BIO *bio_null = NULL;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static int verbose = 0;

/*
 * return the bas64 encoded ECHConfigList from an ECH PEM file
 *
 * note - this isn't really needed as an offical API because
 * real clients will use DNS or scripting clients who need
 * this can do it easier with shell commands
 *
 * the caller should free the returned string
 */
static char *echconfiglist_from_PEM(const char *echkeyfile)
{
    BIO *in = NULL;
    char *ecl_string = NULL;
    char lnbuf[OSSL_ECH_MAX_LINELEN];
    int readbytes = 0;

    if (!TEST_ptr(in = BIO_new(BIO_s_file()))
        || !TEST_int_ge(BIO_read_filename(in, echkeyfile), 0))
        goto out;
    /* read 4 lines before the one we want */
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    ecl_string = OPENSSL_malloc(readbytes + 1);
    if (ecl_string == NULL)
        goto out;
    memcpy(ecl_string, lnbuf, readbytes);
    /* zap any '\n' or '\r' at the end if present */
    while (readbytes >= 0
           && (ecl_string[readbytes - 1] == '\n'
               || ecl_string[readbytes - 1] == '\r')) {
        ecl_string[readbytes - 1] = '\0';
        readbytes--;
    }
    if (readbytes == 0)
        goto out;
    BIO_free_all(in);
    return ecl_string;
out:
    BIO_free_all(in);
    return NULL;
}

/* various echconfig handling calls */
static int basic_echconfig(void)
{
    int res = 1;
    unsigned char echconfig[400];
    size_t echconfiglen = sizeof(echconfig);
    unsigned char priv[200];
    size_t privlen = sizeof(priv);
    uint16_t ech_version = OSSL_ECH_DRAFT_13_VERSION;
    uint16_t max_name_length = 0;
    char *public_name = "example.com";
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char *extvals = NULL;
    unsigned char badexts[8000];
    size_t extlen = 0;
    SSL_CTX *ctx  = NULL;
    SSL *ssl = NULL;
    OSSL_ECH_INFO *details = NULL;
    int num_dets = 0;

    /* test verious dodgy key gens */
    if (!TEST_false(ossl_ech_make_echconfig(NULL, NULL,
                                            NULL, NULL,
                                            ech_version, max_name_length,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    echconfiglen = 80; /* too short */
    privlen = sizeof(priv);
    if (!TEST_false(ossl_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            ech_version, max_name_length,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    echconfiglen = sizeof(echconfig);
    privlen = 10; /* to short */
    if (!TEST_false(ossl_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            ech_version, max_name_length,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    echconfiglen = sizeof(echconfig);
    privlen = sizeof(priv);
    /* dodgy KEM */
    hpke_suite.kem_id = 0xbad;
    if (!TEST_false(ossl_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            ech_version, max_name_length,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    echconfiglen = sizeof(echconfig);
    privlen = sizeof(priv);
    hpke_suite.kem_id = OSSL_HPKE_KEM_ID_X25519;
    /* bad version */
    if (!TEST_false(ossl_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            0xbad, max_name_length,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    /* bad max name length */
    if (!TEST_false(ossl_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            ech_version, 1024,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    /* bad extensions */
    memset(badexts, 0xAA, sizeof(badexts));
    if (!TEST_false(ossl_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            ech_version, 1024,
                                            public_name, hpke_suite,
                                            badexts, sizeof(badexts))))
        goto err;
    echconfiglen = sizeof(echconfig);
    privlen = sizeof(priv);

    /* now a good key gen */
    if (!TEST_true(ossl_ech_make_echconfig(echconfig, &echconfiglen,
                                           priv, &privlen,
                                           ech_version, max_name_length,
                                           public_name, hpke_suite,
                                           extvals, extlen)))
        goto err;
    if (!TEST_ptr(ctx = SSL_CTX_new_ex(testctx, testpropq,
                                       TLS_server_method())))
        goto err;
    /* add that to ctx to start */
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(ctx, echconfig, echconfiglen)))
        goto err;
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;
    /* repeat add that to ssl to make 2 */
    if (!TEST_true(SSL_ech_set1_echconfig(ssl, echconfig, echconfiglen)))
        goto err;
    /* add a 2nd time for fun, works even if silly */
    if (!TEST_true(SSL_ech_set1_echconfig(ssl, echconfig, echconfiglen)))
        goto err;
    if (!TEST_true(SSL_ech_get_info(ssl, &details, &num_dets)))
        goto err;
    if (!TEST_int_eq(num_dets, 3))
        goto err;
    /* we should have 3 sets of details */
    if (verbose) {
        if (!TEST_true(OSSL_ECH_INFO_print(bio_stdout, details, num_dets)))
            goto err;
    } else {
        if (!TEST_true(OSSL_ECH_INFO_print(bio_null, details, num_dets)))
            goto err;
    }
    /* reduce to one */
    if (!TEST_true(SSL_ech_reduce(ssl, 1)))
        goto err;
    OSSL_ECH_INFO_free(details, num_dets);
    details = NULL;
    if (!TEST_true(SSL_ech_get_info(ssl, &details, &num_dets)))
        goto err;
    /* we should only have 1 sets of details left */
    if (!TEST_int_eq(num_dets, 1))
        goto err;
    res = 1;
err:
    OSSL_ECH_INFO_free(details, num_dets);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return res;
}

/* Test a basic roundtrip with ECH */
static int ech_roundtrip_test(void)
{
    int res = 0;
    char *echkeyfile = NULL;
    char *echconfig = NULL;
    size_t echconfiglen = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int num_echs = 0;
    int clientstatus, serverstatus;
    char *cinner, *couter, *sinner, *souter;

    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "echconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto end;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto end;
    echconfiglen = strlen(echconfig);
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen))) {
        TEST_info("Failed SSL_CTX_ech_set1_echconfig adding %s (len = %d)"
                  " to SSL_CTX: %p, wanted result in : %p\n", echconfig,
                  (int)echconfiglen, (void *)cctx, (void *)&num_echs);
        goto end;
    }
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("ech_roundtrip_test: server status %d, %s, %s",
                  serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("ech_roundtrip_test: client status %d, %s, %s",
                  clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* all good */
    res = 1;
end:
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/* Test that ECH doesn't work with a TLS1.2 connection */
static int tls_version_test(void)
{
    int res = 0;
    unsigned char echconfig[400];
    size_t echconfiglen = sizeof(echconfig);
    unsigned char priv[200];
    size_t privlen = sizeof(priv);
    uint16_t ech_version = OSSL_ECH_DRAFT_13_VERSION;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(ossl_ech_make_echconfig(echconfig, &echconfiglen,
                                           priv, &privlen,
                                           ech_version, 0, "example.com",
                                           hpke_suite, NULL, 0)))
        goto end;
    /* setup contexts, initially for tlsv1.3 */
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    /* set client to max tls v1.2 and check setting ech config barfs */
    if (!TEST_true(SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, echconfig,
                                              echconfiglen)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    /* Now see a handshake fail */
    if (!TEST_false(create_ssl_connection(serverssl, clientssl,
                                          SSL_ERROR_NONE)))
        goto end;

    /* all good */
    if (verbose)
        TEST_info("tls_version_test: success\n");
    res = 1;
end:
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/*
 * This ECHConfigList has 6 entries with different versions,
 * [13,10,9,13,10,13] - since our runtime no longer supports
 * version 9 or 10, we should see 3 configs loaded.
 */
static unsigned char echconfig_b64_6_to_3[] =
    "AXn+DQA6xQAgACBm54KSIPXu+pQq2oY183wt3ybx7CKbBYX0ogPq5u6FegAEAAE"
    "AAQALZXhhbXBsZS5jb20AAP4KADzSACAAIIP+0Qt0WGBF3H5fz8HuhVRTCEMuHS"
    "4Khu6ibR/6qER4AAQAAQABAAAAC2V4YW1wbGUuY29tAAD+CQA7AAtleGFtcGxlL"
    "mNvbQAgoyQr+cP8mh42znOp1bjPxpLCBi4A0ftttr8MPXRJPBcAIAAEAAEAAQAA"
    "AAD+DQA6QwAgACB3xsNUtSgipiYpUkW6OSrrg03I4zIENMFa0JR2+Mm1WwAEAAE"
    "AAQALZXhhbXBsZS5jb20AAP4KADwDACAAIH0BoAdiJCX88gv8nYpGVX5BpGBa9y"
    "T0Pac3Kwx6i8URAAQAAQABAAAAC2V4YW1wbGUuY29tAAD+DQA6QwAgACDcZIAx7"
    "OcOiQuk90VV7/DO4lFQr5I3Zw9tVbK8MGw1dgAEAAEAAQALZXhhbXBsZS5jb20A"
    "AA==";

/* same as above but binary encoded */
static unsigned char echconfig_bin_6_to_3[] = {
    0x01, 0x79, 0xfe, 0x0d, 0x00, 0x3a, 0xc5, 0x00,
    0x20, 0x00, 0x20, 0x66, 0xe7, 0x82, 0x92, 0x20,
    0xf5, 0xee, 0xfa, 0x94, 0x2a, 0xda, 0x86, 0x35,
    0xf3, 0x7c, 0x2d, 0xdf, 0x26, 0xf1, 0xec, 0x22,
    0x9b, 0x05, 0x85, 0xf4, 0xa2, 0x03, 0xea, 0xe6,
    0xee, 0x85, 0x7a, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0xfe, 0x0a, 0x00, 0x3c, 0xd2, 0x00, 0x20, 0x00,
    0x20, 0x83, 0xfe, 0xd1, 0x0b, 0x74, 0x58, 0x60,
    0x45, 0xdc, 0x7e, 0x5f, 0xcf, 0xc1, 0xee, 0x85,
    0x54, 0x53, 0x08, 0x43, 0x2e, 0x1d, 0x2e, 0x0a,
    0x86, 0xee, 0xa2, 0x6d, 0x1f, 0xfa, 0xa8, 0x44,
    0x78, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0xfe, 0x09, 0x00, 0x3b, 0x00, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
    0x6d, 0x00, 0x20, 0xa3, 0x24, 0x2b, 0xf9, 0xc3,
    0xfc, 0x9a, 0x1e, 0x36, 0xce, 0x73, 0xa9, 0xd5,
    0xb8, 0xcf, 0xc6, 0x92, 0xc2, 0x06, 0x2e, 0x00,
    0xd1, 0xfb, 0x6d, 0xb6, 0xbf, 0x0c, 0x3d, 0x74,
    0x49, 0x3c, 0x17, 0x00, 0x20, 0x00, 0x04, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe,
    0x0d, 0x00, 0x3a, 0x43, 0x00, 0x20, 0x00, 0x20,
    0x77, 0xc6, 0xc3, 0x54, 0xb5, 0x28, 0x22, 0xa6,
    0x26, 0x29, 0x52, 0x45, 0xba, 0x39, 0x2a, 0xeb,
    0x83, 0x4d, 0xc8, 0xe3, 0x32, 0x04, 0x34, 0xc1,
    0x5a, 0xd0, 0x94, 0x76, 0xf8, 0xc9, 0xb5, 0x5b,
    0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0b,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0xfe, 0x0a, 0x00,
    0x3c, 0x03, 0x00, 0x20, 0x00, 0x20, 0x7d, 0x01,
    0xa0, 0x07, 0x62, 0x24, 0x25, 0xfc, 0xf2, 0x0b,
    0xfc, 0x9d, 0x8a, 0x46, 0x55, 0x7e, 0x41, 0xa4,
    0x60, 0x5a, 0xf7, 0x24, 0xf4, 0x3d, 0xa7, 0x37,
    0x2b, 0x0c, 0x7a, 0x8b, 0xc5, 0x11, 0x00, 0x04,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0xfe, 0x0d, 0x00,
    0x3a, 0x43, 0x00, 0x20, 0x00, 0x20, 0xdc, 0x64,
    0x80, 0x31, 0xec, 0xe7, 0x0e, 0x89, 0x0b, 0xa4,
    0xf7, 0x45, 0x55, 0xef, 0xf0, 0xce, 0xe2, 0x51,
    0x50, 0xaf, 0x92, 0x37, 0x67, 0x0f, 0x6d, 0x55,
    0xb2, 0xbc, 0x30, 0x6c, 0x35, 0x76, 0x00, 0x04,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
    0x6d, 0x00, 0x00
};

/* output from ``dig +short https defo.ie`` */
static char *echconfig_dig_defo =
    "1 . ech=AID+DQA88wAgACDhaXQ8S0pHHQ+bwApOPPDjai"
    "YofLs24QPmmOLP8wHtKwAEAAEAAQANY292ZXIuZGVmby5p"
    "ZQAA/g0APNsAIAAgcTC7pC/ZyxhymoL1p1oAdxfvVEgRji"
    "68mhDE4vDZOzUABAABAAEADWNvdmVyLmRlZm8uaWUAAA==";

/* output from ``dig +short https crypto.cloudflare.com`` */
static char *echconfig_dig_cf = 
    "1 . alpn=\"http/1.1,h2\" ipv4hint=162.159.137.85"
    ",162.159.138.85 ech=AEX+DQBBCAAgACBsFeUbsAWR7x"
    "WL1aB6P28ppSsj+joHhNUtj2qtwYh+NAAEAAEAAQASY2xv"
    "dWRmbGFyZS1lY2guY29tAAA= ipv6hint=2606:4700:7:"
    ":a29f:8955,2606:4700:7::a29f:8a55";


/* Shuffle to preferred order */
enum OSSLTEST_ECH_FIND_runOrder
    {
     OSSLTEST_ECH_FIND_B64,
     OSSLTEST_ECH_FIND_BIN,
     OSSLTEST_ECH_FIND_DIG_DEFO,
     OSSLTEST_ECH_FIND_DIG_CF,

     OSSLTEST_ECH_FIND_NTESTS        /* Keep NTESTS last */
    };

static int test_ech_find(int idx)
{
    int i, nechs = 0, echtarg = 0;
    SSL_CTX *con = NULL;
    unsigned char *enc_cfgs = NULL;
    size_t enc_cfgs_len = 0;
    unsigned char **cfgs = NULL;
    size_t *cfglens = NULL;

    if (!TEST_ptr(con = SSL_CTX_new_ex(testctx, testpropq,
                                       TLS_server_method())))
        return 0;

    switch (idx) {
    case OSSLTEST_ECH_FIND_B64:
       enc_cfgs = echconfig_b64_6_to_3;
       enc_cfgs_len = strlen((char *)enc_cfgs);
       echtarg = 3;
       break;
    case OSSLTEST_ECH_FIND_BIN:
       enc_cfgs = echconfig_bin_6_to_3;
       enc_cfgs_len = sizeof(echconfig_bin_6_to_3);
       echtarg = 3;
       break;
    case OSSLTEST_ECH_FIND_DIG_DEFO:
       enc_cfgs = (unsigned char *)echconfig_dig_defo;
       enc_cfgs_len = strlen(echconfig_dig_defo);
       echtarg = 2;
       break;
    case OSSLTEST_ECH_FIND_DIG_CF:
       enc_cfgs = (unsigned char *)echconfig_dig_cf;
       enc_cfgs_len = strlen(echconfig_dig_cf);
       echtarg = 1;
       break;
    default:
        TEST_info("unknown option %d.",idx);
        return 0;
    }

    if (ossl_ech_find_echconfigs(&nechs, &cfgs, &cfglens,
                                 enc_cfgs, enc_cfgs_len) != 1) {
        TEST_info("ossl_ech_find_echconfigs call %d failed.",idx);
        return 0;
    }
    if (nechs != echtarg) {
        TEST_info("ossl_ech_find_echconfigs call %d failed to return ECHs",idx);
        return 0;
    }
    for (i = 0; i!= nechs; i++) {
        if (SSL_CTX_ech_set1_echconfig(con, cfgs[i], cfglens[i]) != 1) {
            TEST_info("SSL_ech_set1_echconifg call %d failed.",idx);
            return 0;
        }
        OPENSSL_free(cfgs[i]);
    }
    OPENSSL_free(cfglens);
    OPENSSL_free(cfgs);
    SSL_CTX_free(con);
    if (verbose)
        TEST_info("test_ech_find: success\n");
    return 1;
}

/* Shuffle to preferred order */
enum OSSLTEST_ECH_ADD_runOrder
    {
     OSSLTEST_ECH_B64_GUESS,
     OSSLTEST_ECH_B64_BASE64,
     OSSLTEST_ECH_B64_GUESS_XS_COUNT,
     OSSLTEST_ECH_B64_GUESS_LO_COUNT,
     OSSLTEST_ECH_B64_JUNK_GUESS,

     OSSLTEST_ECH_NTESTS        /* Keep NTESTS last */
    };

static int test_ech_add(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL, *sctx2 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;        /* assume failure */
    int echcount = 0;
    int returned;
    /*
     * This ECHConfigList has 6 entries with different versions,
     * [13,10,9,13,10,13] - since our runtime no longer supports
     * version 9 or 10, we should see 3 configs loaded.
     */
    size_t echconfiglen;
    unsigned char echconfig[] =
        "AXn+DQA6xQAgACBm54KSIPXu+pQq2oY183wt3ybx7CKbBYX0ogPq5u6FegAEAAE"
        "AAQALZXhhbXBsZS5jb20AAP4KADzSACAAIIP+0Qt0WGBF3H5fz8HuhVRTCEMuHS"
        "4Khu6ibR/6qER4AAQAAQABAAAAC2V4YW1wbGUuY29tAAD+CQA7AAtleGFtcGxlL"
        "mNvbQAgoyQr+cP8mh42znOp1bjPxpLCBi4A0ftttr8MPXRJPBcAIAAEAAEAAQAA"
        "AAD+DQA6QwAgACB3xsNUtSgipiYpUkW6OSrrg03I4zIENMFa0JR2+Mm1WwAEAAE"
        "AAQALZXhhbXBsZS5jb20AAP4KADwDACAAIH0BoAdiJCX88gv8nYpGVX5BpGBa9y"
        "T0Pac3Kwx6i8URAAQAAQABAAAAC2V4YW1wbGUuY29tAAD+DQA6QwAgACDcZIAx7"
        "OcOiQuk90VV7/DO4lFQr5I3Zw9tVbK8MGw1dgAEAAEAAQALZXhhbXBsZS5jb20A"
        "AA==";
    OSSL_ECH_INFO *details = NULL;
    int num_dets = 0;

    echconfiglen = strlen((char *)echconfig);

    /* Generate fresh context pair for each test with TLSv1.3 as a minimum */
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, 0,
                                       &sctx2, &cctx, cert, privkey))) {
        TEST_info("test_ech_add: context creation failed for iteration %d",
                  idx);
        goto end;
    }
    if (!TEST_ptr(clientssl = SSL_new(cctx))) {
        TEST_info("test_ech_add: clientssl createion failed");
        goto end;
    }
    switch (idx) {
    case OSSLTEST_ECH_B64_GUESS:
        /* Valid echconfig */
        returned = SSL_ech_set1_echconfig(clientssl, echconfig, echconfiglen);
        if (!TEST_int_eq(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS: failure for valid echconfig "
                      " and length\n");
            goto end;
        }
        if (!TEST_true(SSL_ech_get_info(clientssl, &details, &num_dets)))
            goto end;
        if (!TEST_int_eq(num_dets, 3)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS: incorrect ECH count\n");
            goto end;
        }
        OSSL_ECH_INFO_free(details, num_dets);
        details = NULL;
        break;

    case OSSLTEST_ECH_B64_BASE64:
        /* Valid echconfig */
        returned = SSL_ech_set1_echconfig(clientssl, echconfig, echconfiglen);
        if (!TEST_int_eq(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_BASE64: failure for valid echconfig\n");
            goto end;
        }
        if (!TEST_true(SSL_ech_get_info(clientssl, &details, &num_dets)))
            goto end;
        if (!TEST_int_eq(num_dets, 3)) {
            TEST_info("OSSLTEST_ECH_B64_BASE64: incorrect ECH count\n");
            goto end;
        }
        OSSL_ECH_INFO_free(details, num_dets);
        details = NULL;
        break;

    case OSSLTEST_ECH_B64_GUESS_XS_COUNT:
        /*
         * Valid echconfig, excess length but just by one octet
         * which will be ok since strings have that added NUL
         * octet. If the excess was >1 then the caller is the
         * one making the error.
         */
        returned = SSL_ech_set1_echconfig(clientssl, echconfig,
                                          echconfiglen + 1);
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_XS_COUNT: success despite excess "
                      "length (%d/%d)\n",
                      (int)echconfiglen + 1, (int)echconfiglen);
            goto end;
        }
        if (!TEST_true(SSL_ech_get_info(clientssl, &details, &num_dets)))
            goto end;
        if (!TEST_int_eq(num_dets, 0)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_XS_COUNT: ECH count (%d) should "
                      "be zero\n", echcount);
            goto end;
        }
        break;

    case OSSLTEST_ECH_B64_GUESS_LO_COUNT:
        /* Valid echconfig, short length */
        returned = SSL_ech_set1_echconfig(clientssl, echconfig,
                                          echconfiglen / 2);
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_LO_COUNT: success despite short "
                      "length (%d/%d)\n",
                      (int)echconfiglen / 2, (int)echconfiglen);
            goto end;
        }
        break;

    case OSSLTEST_ECH_B64_JUNK_GUESS:
        /* Junk echconfig */
        returned = SSL_ech_set1_echconfig(clientssl,
                                          (unsigned char *)"DUMMDUMM;DUMMYDUMM",
                                          18);
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_JUNK_GUESS: junk config success\n");
            goto end;
        }
        break;

    default:
        TEST_error("Bad test index\n");
        goto end;
    }

    if (verbose)
        TEST_info("test_ech_add: success\n");
    testresult = 1;        /* explicit success */

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run ECH tests\n" },
        { NULL }
    };
    return test_options;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    certsdir = test_get_argument(0);
    if (certsdir == NULL)
        certsdir = DEF_CERTS_DIR;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;

    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    bio_null = BIO_new(BIO_s_mem());
    ADD_TEST(basic_echconfig);
    ADD_ALL_TESTS(test_ech_add, OSSLTEST_ECH_NTESTS);
    ADD_ALL_TESTS(test_ech_find, OSSLTEST_ECH_FIND_NTESTS);
    ADD_TEST(ech_roundtrip_test);
    ADD_TEST(tls_version_test);
    return 1;
err:
    return 0;
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    BIO_free(bio_null);
    BIO_free(bio_stdout);
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
#endif
}
