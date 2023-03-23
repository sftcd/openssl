/*
 * Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include <openssl/ech.h>
#include <internal/ech_helpers.h>

#define OSSL_ECH_MAX_LINELEN 1000 /* for a sanity check */
#define DEF_CERTS_DIR "test/certs"

static int verbose = 0;
static int testcase = 0;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *echkeyfile = NULL;
static char *echconfig = NULL; static size_t echconfiglen = 0;
static unsigned char *bin_echconfig; size_t bin_echconfiglen = 0;

/* we'll create HPKE vars at setup and re-use for >1 test */
static OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
static OSSL_HPKE_CTX *hctx = NULL;
static unsigned char *hpke_info = NULL; static size_t hpke_infolen = 0;
static unsigned char *mypub = NULL; static size_t mypublen = 0;

/* 
 * We use a set of test vectors for each test:
 *  - encoded inner CH prefix
 *  - encoded inner CH corrupted-or-not
 *  - encoded inner CH postfix
 *  - expected result (1 for good, 0 for bad)
 *  - expected error in the case of bad
 *
 * For each test, we'll try replace the ECH ciphertext with
 * a value that's basically the HPKE seal/enc of an inner-CH
 * made up of the relevant three parts and then see if we
 * get the correct result and/or error.
 *
 * The inner CH is split in 3 so we can re-use the pre and
 * post values, making it easier to understand/manipulate the 
 * corrupted-or-not value.
 */
typedef struct {
    const unsigned char *pre; size_t prelen;
    const unsigned char *forbork; size_t fblen;
    const unsigned char *post; size_t postlen;
    int rv_expected; /* expected result */
    int err_expected; /* expected error */
} TEST_ECHINNER;

const unsigned char fake[] = { 0x01 };

/* an example of a full encoded inner */
const unsigned char entire_encoded_inner[] = {
    0x03, 0x03, 0xec, 0x2f, 0xc7, 0x7b, 0xb5, 0x10,
    0xf6, 0x87, 0x82, 0x52, 0x64, 0x28, 0xdf, 0xb9,
    0xf2, 0xe4, 0x54, 0x5c, 0x15, 0x21, 0xfb, 0xac,
    0x8a, 0xb4, 0x48, 0x85, 0xbf, 0x67, 0xbf, 0xd1,
    0x49, 0xa3, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x56, 0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
    0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00, 0x00,
    0x15, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e,
    0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61,
    0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x10,
    0x00, 0x18, 0x00, 0x16, 0x05, 0x69, 0x6e, 0x6e,
    0x65, 0x72, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65,
    0x74, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
    0x2e, 0x31, 0xfe, 0x0d, 0x00, 0x01, 0x01
};

static TEST_ECHINNER test_inners[] = {
    { NULL, 0, NULL, 0, NULL, 0, 1, 0}, /* basic case - just copy */
    { NULL, 0, fake, sizeof(fake), NULL, 0, 1, 0}, /* basic case - just copy */
};

/*
 * Do a HPKE seal of the encoded inner
 */
static int seal_encoded_inner(char **out, int *outlen,
                              unsigned char *ei, size_t eilen,
                              const char *ch, int chlen,
                              size_t echoffset, size_t echlen)
{
    int res = 0;
    unsigned char *ct = NULL; size_t ctlen = 0;
    unsigned char *aad = NULL; size_t aadlen = 0;

    /* form up aad which is entire outer CH: zero's instead of ECH ciphertext */
    ctlen = OSSL_HPKE_get_ciphertext_size(hpke_suite, eilen);
    if (!TEST_ptr(aad = OPENSSL_memdup(ch, chlen)))
        goto err;
    memcpy(aad + echoffset + 4, mypub, mypublen);
    ct = aad + echoffset + 4 + mypublen + 2;
    memset(ct, 0, ctlen);
    if (ct == NULL)
        goto err;
    if (!TEST_true(OSSL_HPKE_seal(hctx, ct, &ctlen, aad, aadlen, ei, eilen)))
        goto err;
    *out = (char *)aad;
    *outlen = chlen;

    /* for now just return the ch, as-is */
    if (!TEST_ptr(*out = OPENSSL_memdup(ch, chlen)))
        goto err;
    *outlen = chlen;
    res = 1;
err:
    return res;

}

/*
 * We'll either corrupt or copy the CH based on the test index
 */
static int corrupt_or_copy(const char *ch, const int chlen,
                           char **chout, int *choutlen)
{
    TEST_ECHINNER *ti = NULL;
    int is_ch = 0;
    unsigned char *encoded_inner = NULL;
    size_t prelen, fblen, postlen;
    size_t encoded_innerlen = 0;
    size_t sessid, exts, extlens, echoffset, echlen, snioffset, snilen;
    uint16_t echtype;
    int inner;

    if (testcase >= OSSL_NELEM(test_inners))
        return 0;
    ti = &test_inners[testcase];

    prelen = ti->pre == NULL ? 0 : ti->prelen;
    fblen = ti->forbork == NULL ? 0 : ti->fblen;
    postlen = ti->post == NULL ? 0 : ti->postlen;

    /* is it a ClientHello or not? */
    if (chlen > 10 && ch[0] == SSL3_RT_HANDSHAKE
        && ch[5] == SSL3_MT_CLIENT_HELLO)
        is_ch = 1;
    if (!TEST_true(ech_helper_get_ch_offsets((const unsigned char *)ch + 9,
                                             chlen - 9,
                                             &sessid, &exts, &extlens,
                                             &echoffset, &echtype, &echlen,
                                             &snioffset, &snilen, &inner)))
        return 0;

    /*
     * if it's not a ClientHello, or doesn't have an ECH, or if the
     * forbork value in our test array is NULL, just copy the entire
     * input to output
     **/
    if (is_ch == 0 || echoffset == 0 || ti->forbork == NULL) {
        if (!TEST_ptr(*chout = OPENSSL_memdup(ch, chlen)))
            return 0;
        *choutlen = chlen;
        return 1;
    }
    /* in this case, construct the encoded inner, then seal that */
    encoded_innerlen = prelen + fblen + postlen;
    if (!TEST_ptr(encoded_inner = OPENSSL_malloc(encoded_innerlen)))
        return 0;
    memcpy(encoded_inner, ti->pre, prelen);
    memcpy(encoded_inner + prelen, ti->forbork, fblen);
    memcpy(encoded_inner + prelen + fblen, ti->post, postlen);
    if (!TEST_true(seal_encoded_inner(chout, choutlen,
                                      encoded_inner, encoded_innerlen,
                                      ch, chlen, echoffset, echlen)))
        return 0;
    OPENSSL_free(encoded_inner);
    return 1;
}

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

static void copy_flags(BIO *bio)
{
    int flags;
    BIO *next = BIO_next(bio);

    flags = BIO_test_flags(next, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_set_flags(bio, flags);
}

static int tls_corrupt_read(BIO *bio, char *out, int outl)
{
    int ret;
    BIO *next = BIO_next(bio);

    ret = BIO_read(next, out, outl);
    copy_flags(bio);

    return ret;
}

static int tls_corrupt_write(BIO *bio, const char *in, int inl)
{
    int ret;
    BIO *next = BIO_next(bio);
    char *copy;
    int copylen;

    ret = corrupt_or_copy(in, inl, &copy, &copylen);
    if (ret == 0)
        return 0;
    ret = BIO_write(next, copy, inl);
    OPENSSL_free(copy);
    copy_flags(bio);

    return ret;
}

static long tls_corrupt_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret;
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;

    switch (cmd) {
    case BIO_CTRL_DUP:
        ret = 0L;
        break;
    default:
        ret = BIO_ctrl(next, cmd, num, ptr);
        break;
    }
    return ret;
}

static int tls_corrupt_gets(BIO *bio, char *buf, int size)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int tls_corrupt_puts(BIO *bio, const char *str)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int tls_corrupt_new(BIO *bio)
{
    BIO_set_init(bio, 1);

    return 1;
}

static int tls_corrupt_free(BIO *bio)
{
    BIO_set_init(bio, 0);

    return 1;
}

#define BIO_TYPE_CUSTOM_FILTER (0x80 | BIO_TYPE_FILTER)

static BIO_METHOD *method_tls_corrupt = NULL;

/* Note: Not thread safe! */
static const BIO_METHOD *bio_f_tls_corrupt_filter(void)
{
    if (method_tls_corrupt == NULL) {
        method_tls_corrupt = BIO_meth_new(BIO_TYPE_CUSTOM_FILTER,
                                          "TLS corrupt filter");
        if (method_tls_corrupt == NULL
            || !BIO_meth_set_write(method_tls_corrupt, tls_corrupt_write)
            || !BIO_meth_set_read(method_tls_corrupt, tls_corrupt_read)
            || !BIO_meth_set_puts(method_tls_corrupt, tls_corrupt_puts)
            || !BIO_meth_set_gets(method_tls_corrupt, tls_corrupt_gets)
            || !BIO_meth_set_ctrl(method_tls_corrupt, tls_corrupt_ctrl)
            || !BIO_meth_set_create(method_tls_corrupt, tls_corrupt_new)
            || !BIO_meth_set_destroy(method_tls_corrupt, tls_corrupt_free))
            return NULL;
    }
    return method_tls_corrupt;
}

static void bio_f_tls_corrupt_filter_free(void)
{
    BIO_meth_free(method_tls_corrupt);
}

static int test_ech_corrupt(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *c_to_s_fbio;
    int testresult = 0;
    int err;
    TEST_ECHINNER *ti = NULL;
    int connrv = 0;

    testcase = testidx;
    ti = &test_inners[testidx];

    if (verbose) 
        TEST_info("Starting #%d", testidx);

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile)))
        goto end;

    if (!TEST_ptr(c_to_s_fbio = BIO_new(bio_f_tls_corrupt_filter())))
        goto end;

    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL,
                                      c_to_s_fbio)))
        goto end;

    connrv = create_ssl_connection(server, client, SSL_ERROR_NONE);
    if (!TEST_int_eq(connrv, ti->rv_expected))
        goto end;

    if (connrv == 0) {
        do {
            err = ERR_get_error();

            if (err == 0) {
                TEST_error("Decryption failed or bad record MAC not seen");
                goto end;
            }
        } while (ERR_GET_REASON(err) != SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
    }
    
    testresult = 1;
 end:
    SSL_free(server);
    SSL_free(client);
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
        { OPT_HELP_STR, 1, '-', "Run ECH Corruption tests\n" },
        { NULL }
    };
    return test_options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;
    unsigned char *theirpub = NULL; size_t theirpublen = 0;

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

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
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

    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "echconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto err;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto err;
    echconfiglen = strlen(echconfig);
    bin_echconfiglen = ech_helper_base64_decode(echconfig, echconfiglen,
                                                &bin_echconfig);
    hpke_infolen = bin_echconfiglen + 200;
    if (!TEST_ptr(hpke_info = OPENSSL_malloc(hpke_infolen)))
        goto err;
    if (!TEST_true(ech_helper_make_enc_info((unsigned char *)bin_echconfig,
                                            bin_echconfiglen,
                                            hpke_info, &hpke_infolen)))
        goto err;
    if (!TEST_ptr(hctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, hpke_suite,
                                           OSSL_HPKE_ROLE_SENDER, NULL, NULL)))
        goto err;

    mypublen = OSSL_HPKE_get_public_encap_size(hpke_suite);
    if (!TEST_ptr(mypub = OPENSSL_malloc(mypublen)))
        goto err;
    theirpub = bin_echconfig + 11;
    theirpublen = 0x20;
    if (!TEST_true(OSSL_HPKE_encap(hctx, mypub, &mypublen,
                                   theirpub, theirpublen, 
                                   hpke_info, hpke_infolen)))
        goto err;

    ADD_ALL_TESTS(test_ech_corrupt, OSSL_NELEM(test_inners));
    return 1;
err:
    return 0;
}

void cleanup_tests(void)
{
    bio_f_tls_corrupt_filter_free();
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    OPENSSL_free(bin_echconfig);
    OPENSSL_free(mypub);
    OPENSSL_free(hpke_info);
    OSSL_HPKE_CTX_free(hctx);
}
