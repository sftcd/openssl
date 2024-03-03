/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/hpke.h>
#include "../include/internal/sech_helpers.h"
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
// static OSSL_LIB_CTX *testctx = NULL;
static BIO *bio_stdout = NULL;
static BIO *bio_null = NULL;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *rootcert = NULL;
static int verbose = 0;

/*
 * A struct to tie the above together for tests. Note that
 * the encoded_len should be "sizeof(x) - 1" if the encoding
 * is a string encoding, but just "sizeof(x)" if we're dealing
 * with a binary encoding.
 */
typedef struct {
    const unsigned char *encoded; /* encoded ECHConfigList */
    size_t encoded_len; /* the size of the above */
    int num_expected; /* number of ECHConfig values we expect to decode */
    int rv_expected; /* expected return value from call */
} TEST_ECHCONFIG;

/*
 * The define/vars below and the 3 callback functions are modified
 * from test/sslapitest.c
 */
# define TEST_EXT_TYPE1  0xffab /* custom ext type 1: has 1 octet payload */
# define TEST_EXT_TYPE2  0xffcd /* custom ext type 2: no payload */

static int test_SSL_CTX_sech_symmetric_key(void)
{
    int res = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    // SSL *clientssl = NULL, *serverssl = NULL;

    /* setup contexts, initially for tlsv1.3 */
    char key[5];
    strcpy(key, "abab");
    SSL_CTX_sech_symmetric_key(cctx, (char *)(&key));
    if (!TEST_ptr(cctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method())))
        goto end;
    SSL_CTX_sech_symmetric_key(cctx, (char *)(&key));

    /* all good */
    if (verbose)
        TEST_info("test_SSL_CTX_sech_symmetric_key: success\n");
    res = 1;
end:
    // SSL_free(clientssl);
    // SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

static int encrypt_symmetric_test(void) {
    int res = 0;
    encrypt_symmetric(NULL,NULL,NULL);
    res = 1;
end:
    return res;
}

/* values that can be used in helper below */
# define OSSL_ECH_TEST_BASIC    0
# define OSSL_ECH_TEST_HRR      1
# define OSSL_ECH_TEST_EARLY    2
# define OSSL_ECH_TEST_CUSTOM   3

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
    // int suite_combos;

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
    cert = test_mk_file_path(certsdir, "echserver.pem");
    if (cert == NULL)
        goto err;
    privkey = test_mk_file_path(certsdir, "echserver.key");
    if (privkey == NULL)
        goto err;
    rootcert = test_mk_file_path(certsdir, "rootcert.pem");
    if (rootcert == NULL)
        goto err;
    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    bio_null = BIO_new(BIO_s_mem());
    ADD_TEST(test_SSL_CTX_sech_symmetric_key);
    ADD_TEST(encrypt_symmetric_test);
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
    OPENSSL_free(rootcert);
#endif
}
