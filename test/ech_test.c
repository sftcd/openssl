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

#define OSSL_ECH_MAX_LINELEN 1000 /**< for a sanity check */

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_LIB_CTX *testctx = NULL;
static char *testpropq = NULL;
static BIO *bio_stdout = NULL;
static BIO *bio_null = NULL;

static char *cert = NULL;
static char *privkey = NULL;
static int verbose = 0;

#if 0
/* may need this later */
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
    /* zap the '\n' if present */
    if (ecl_string[readbytes - 1] == '\n')
        ecl_string[readbytes - 1] = '\0';
    BIO_free_all(in);
    return(ecl_string);
out:
    if (in) BIO_free_all(in);
    return(NULL);
}
#endif

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
    SSL_CTX *ctx  = NULL;
    SSL *ssl = NULL;
    int num_echs = 0;
    OSSL_ECH_INFO *details = NULL;
    int num_dets = 0;

    res=ossl_ech_make_echconfig(echconfig, &echconfig_len, priv, &privlen,
                                     ech_version, max_name_length, public_name,
                                     hpke_suite, extvals, extlen);
    if (!TEST_int_eq(res,1))
        return 0;
    if (!TEST_ptr(ctx = SSL_CTX_new_ex(testctx, testpropq,
                                       TLS_server_method())))
        return 0;
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        return 0;
    res = SSL_ech_set1_echconfig(ssl, &num_echs, OSSL_ECH_FMT_GUESS,
                                 (char *)echconfig, echconfig_len);
    if (!TEST_int_eq(res,1))
        return 0;
    /* add same one a 2nd time for fun, should work even if silly */
    res = SSL_ech_set1_echconfig(ssl, &num_echs, OSSL_ECH_FMT_GUESS,
                                 (char *)echconfig, echconfig_len);
    if (!TEST_int_eq(res,1))
        return 0;
    res = SSL_ech_get_info(ssl, &details, &num_dets);
    if (!TEST_int_eq(res,1))
        return 0;
    /* we should have two sets of details */
    if (!TEST_int_eq(num_dets,2))
        return 0;
    if (verbose) {
        res = OSSL_ECH_INFO_print(bio_stdout, details, num_dets);
        if (!TEST_int_eq(res,1))
            return 0;
    } else {
        res = OSSL_ECH_INFO_print(bio_null, details, num_dets);
        if (!TEST_int_eq(res,1))
            return 0;
    }
    OSSL_ECH_INFO_free(details, num_dets);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
}

/* 
 * while adding text to the documentation I thought of some more
 * tests to add, so just noting those here for now and will code
 * 'em up later
 */
static int tls_version_test(void)
{
    /*
     * TODO: check that TLSv1.2 is still ok if the client
     * had set an ECHConfig
     */
    return 1;
}

static int sni_alpn_control_test(void)
{
    /*
     * TODO: add tests calling SSL_ech_set_server_names() etc
     * and validate that those work 
     */
    return 1;
}

static int ech_info_test(void)
{
    /*
     * TODO: add tests calling OSSL_ECH_INFO_print() etc
     */
    return 1;
}

static int ech_file_test(void)
{
    /*
     * TODO: add tests calling SSL_CTX_ech_server_enable_file() etc
     */
    return 1;
}

static int ech_raw_test(void)
{
    /*
     * TODO: add tests calling SSL_CTX_ech_raw_decrypt() etc
     */
    return 1;
}

enum OSSLTEST_ECH_runOrder {    /* Shuffle to preferred order */
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

#if 0
    /*
     * This ECHConfigList has only one entry.
     */
    char echconfig[] =
      "ADX+CgAxLwAgACAPM+mZOcezv6GuQIQ8ZVHT+Hube8VZq+pAbXphNU3nSwAEAAE"\
      "AAQAAAAAAAA==";
#endif

    /* 
     * This ECHConfigList has 6 entries with different versions,
     * [13,10,9,13,10,13] - since our runtime no longer supports
     * version 9 or 10, we should see 3 configs loaded.
     */
    char echconfig[]=
        "AXn+DQA6xQAgACBm54KSIPXu+pQq2oY183wt3ybx7CKbBYX0ogPq5u6FegAEAAE"\
        "AAQALZXhhbXBsZS5jb20AAP4KADzSACAAIIP+0Qt0WGBF3H5fz8HuhVRTCEMuHS"\
        "4Khu6ibR/6qER4AAQAAQABAAAAC2V4YW1wbGUuY29tAAD+CQA7AAtleGFtcGxlL"\
        "mNvbQAgoyQr+cP8mh42znOp1bjPxpLCBi4A0ftttr8MPXRJPBcAIAAEAAEAAQAA"\
        "AAD+DQA6QwAgACB3xsNUtSgipiYpUkW6OSrrg03I4zIENMFa0JR2+Mm1WwAEAAE"\
        "AAQALZXhhbXBsZS5jb20AAP4KADwDACAAIH0BoAdiJCX88gv8nYpGVX5BpGBa9y"\
        "T0Pac3Kwx6i8URAAQAAQABAAAAC2V4YW1wbGUuY29tAAD+DQA6QwAgACDcZIAx7"\
        "OcOiQuk90VV7/DO4lFQr5I3Zw9tVbK8MGw1dgAEAAEAAQALZXhhbXBsZS5jb20A"\
        "AA==";
    size_t echconfig_len=strlen(echconfig);

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
        returned = SSL_ech_set1_echconfig(clientssl, &echcount,
                                          OSSL_ECH_FMT_GUESS,
                                          echconfig, echconfig_len);
        if (!TEST_int_eq(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS: failure for valid echconfig "
                      " and length\n");
            goto end;
        }
        if (!TEST_int_eq(echcount, 3)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS: incorrect ECH count\n");
            goto end;
        }
        break;

    case OSSLTEST_ECH_B64_BASE64:
        /* Valid echconfig */
        returned = SSL_ech_set1_echconfig(clientssl, &echcount,
                                          OSSL_ECH_FMT_B64TXT,
                                          echconfig, echconfig_len);
        if (!TEST_int_eq(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_BASE64: failure for valid echconfig\n");
            goto end;
        }
        if (!TEST_int_eq(echcount, 3)) {
            TEST_info("OSSLTEST_ECH_B64_BASE64: incorrect ECH count\n");
            goto end;
        }
      break;

    case OSSLTEST_ECH_B64_GUESS_XS_COUNT:
        /* 
         * Valid echconfig, excess length but just by one octet
         * which will be ok since strings have that added NUL
         * octet. If the excess was >1 then the caller is the
         * one making the error.
         */
        returned = SSL_ech_set1_echconfig(clientssl, &echcount,
                                          OSSL_ECH_FMT_GUESS,
                                          echconfig, echconfig_len+1);
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_XS_COUNT: success despite excess "
                      "length (%d/%d)\n",
                      (int)echconfig_len+1, (int)echconfig_len);
            goto end;
        }
        if (!TEST_int_eq(echcount, 0)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_XS_COUNT: ECH count (%d) should "
                      "be zero\n", echcount);
            goto end;
        }
      break;

    case OSSLTEST_ECH_B64_GUESS_LO_COUNT:
        /* Valid echconfig, short length */
        returned = SSL_ech_set1_echconfig(clientssl, &echcount, 
                                          OSSL_ECH_FMT_GUESS,
                                          echconfig, echconfig_len/2);
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_LO_COUNT: success despite short "
                      "length (%d/%d)\n",
                       (int)echconfig_len/2, (int)echconfig_len);
            goto end;
          }
      break;

    case OSSLTEST_ECH_B64_JUNK_GUESS:
        /* Junk echconfig */
        returned = SSL_ech_set1_echconfig(clientssl, &echcount, 
                                          OSSL_ECH_FMT_GUESS,
                                          "DUMMDUMM;DUMMYDUMM", 18);
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
    SSL_CTX_free(cctx);        /* TBD: ensure that this frees any echconfig storage */
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
            verbose = 1; /* Print progress dots */
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    bio_null = BIO_new(BIO_s_mem());
    ADD_TEST(basic_echconfig_gen);
    ADD_ALL_TESTS(test_ech_add, 5);
    ADD_TEST(tls_version_test);
    ADD_TEST(sni_alpn_control_test);
    ADD_TEST(ech_info_test);
    ADD_TEST(ech_file_test);
    ADD_TEST(ech_raw_test);
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    BIO_free(bio_null);
    BIO_free(bio_stdout);
#endif
}
