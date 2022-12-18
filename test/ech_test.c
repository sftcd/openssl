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
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static int verbose = 0;

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

static int basic_echconfig_gen(void)
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
    size_t extlen = 0;
    SSL_CTX *ctx  = NULL;
    SSL *ssl = NULL;
    int num_echs = 0;
    OSSL_ECH_INFO *details = NULL;
    int num_dets = 0;

    res=ossl_ech_make_echconfig(echconfig, &echconfiglen, priv, &privlen,
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
                                 (char *)echconfig, echconfiglen);
    if (!TEST_int_eq(res,1))
        return 0;
    /* add same one a 2nd time for fun, should work even if silly */
    res = SSL_ech_set1_echconfig(ssl, &num_echs, OSSL_ECH_FMT_GUESS,
                                 (char *)echconfig, echconfiglen);
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
 * Test a basic roundtrip with ECH
 */
static int ech_roundtrip_test(void)
{
    int res = 0;
    char *echconfig = NULL;
    size_t echconfiglen = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int num_echs = 0;
    int clientstatus;
    char *cinner, *couter;
    int serverstatus;
    char *sinner, *souter;
    char *echkeyfile=NULL;

    /* read pre-cooked ECH private/ECHConfigList */
    echkeyfile = test_mk_file_path(certsdir, "echconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto end;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto end;
    echconfiglen=strlen(echconfig);
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, &num_echs,
                                              OSSL_ECH_FMT_GUESS,
                                              (char *)echconfig,
                                              echconfiglen)))
        goto end;
    if (!TEST_int_eq(num_echs, 1))
        goto end;
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
    if (verbose) {
        TEST_info("ech_roundtrip_test: server status %d, %s, %s",
                   serverstatus, sinner, souter);
    }
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS)) {
        goto end;
    }
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose) {
        TEST_info("ech_roundtrip_test: client status %d, %s, %s",
                   clientstatus, cinner, couter);
    }
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS)) {
        goto end;
    }

    /* all good */
    if (verbose)  {
        TEST_info("ech_roundtrip_test: success\n");
        TEST_info("ech_roundtrip_test: client %d, %s, %s\n",
                  clientstatus, cinner, couter);
        TEST_info("ech_roundtrip_test: server %d, %s, %s\n",
                  serverstatus, sinner, souter);
    }
    res = 1;
end:
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/* 
 * Test that setting an echconfig doesn't disturb a TLS1.2 connection
 */
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
    int num_echs = 0;

    if (!TEST_true(ossl_ech_make_echconfig(echconfig, &echconfiglen,
                                           priv, &privlen,
                                           ech_version, 0, "example.com",
                                           hpke_suite, NULL, 0)))
        goto end;
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_2_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
       goto end;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, &num_echs,
                                              OSSL_ECH_FMT_GUESS,
                                              (char *)echconfig,
                                              echconfiglen)))
        goto end;
    /* Now do a handshake */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
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
    size_t echconfiglen=strlen(echconfig);

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
                                          echconfig, echconfiglen);
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
                                          echconfig, echconfiglen);
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
                                          echconfig, echconfiglen+1);
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_XS_COUNT: success despite excess "
                      "length (%d/%d)\n",
                      (int)echconfiglen+1, (int)echconfiglen);
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
                                          echconfig, echconfiglen/2);
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_LO_COUNT: success despite short "
                      "length (%d/%d)\n",
                       (int)echconfiglen/2, (int)echconfiglen);
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

    if (!TEST_ptr(certsdir = test_get_argument(0)))
        return 0;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;

    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    bio_null = BIO_new(BIO_s_mem());
    ADD_TEST(basic_echconfig_gen);
    ADD_ALL_TESTS(test_ech_add, 5);
    ADD_TEST(ech_roundtrip_test);
    ADD_TEST(tls_version_test);
    ADD_TEST(sni_alpn_control_test);
    ADD_TEST(ech_info_test);
    ADD_TEST(ech_file_test);
    ADD_TEST(ech_raw_test);
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
