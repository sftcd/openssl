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

#define OSSL_ECH_MAX_LINELEN 1000 /* for a sanity check */
#define DEF_CERTS_DIR "test/certs"

static int docorrupt = 0;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;

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

    if (docorrupt) {
        if (!TEST_ptr(copy = OPENSSL_memdup(in, inl)))
            return 0;
        /* corrupt last bit of application data */
        copy[inl - 1] ^= 1;
        ret = BIO_write(next, copy, inl);
        OPENSSL_free(copy);
    } else {
        ret = BIO_write(next, in, inl);
    }
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

/*
 * The test is supposed to be executed with RSA key, customarily
 * with apps/server.pem used even in other tests. For this reason
 * |cipher_list| is initialized with RSA ciphers' names. This
 * naturally means that if test is to be re-purposed for other
 * type of key, then NID_auth_* filter below would need adjustment.
 */
static const char **cipher_list = NULL;

static int setup_cipher_list(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *sk_ciphers = NULL;
    int i, j, numciphers = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_server_method()))
            || !TEST_ptr(ssl = SSL_new(ctx))
            || !TEST_ptr(sk_ciphers = SSL_get1_supported_ciphers(ssl)))
        goto err;

    /*
     * The |cipher_list| will be filled only with names of RSA ciphers,
     * so that some of the allocated space will be wasted, but the loss
     * is deemed acceptable...
     */
    cipher_list = OPENSSL_malloc(sk_SSL_CIPHER_num(sk_ciphers) *
                                 sizeof(cipher_list[0]));
    if (!TEST_ptr(cipher_list))
        goto err;

    for (j = 0, i = 0; i < sk_SSL_CIPHER_num(sk_ciphers); i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(sk_ciphers, i);

        if (SSL_CIPHER_get_auth_nid(cipher) == NID_auth_rsa)
            cipher_list[j++] = SSL_CIPHER_get_name(cipher);
    }
    if (TEST_int_ne(j, 0))
        numciphers = j;

err:
    sk_SSL_CIPHER_free(sk_ciphers);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return numciphers;
}

static int test_ech_corrupt(int testidx)
{
    static unsigned char junk[16000] = { 0 };
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *c_to_s_fbio;
    int testresult = 0;
    STACK_OF(SSL_CIPHER) *ciphers;
    const SSL_CIPHER *currcipher;
    int err;
    char *echkeyfile = NULL;
    char *echconfig = NULL;
    size_t echconfiglen = 0;

    docorrupt = 0;

    TEST_info("Starting #%d, %s", testidx, cipher_list[testidx]);

    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "echconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto end;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto end;
    echconfiglen = strlen(echconfig);

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile)))
        goto end;

    if (!TEST_true(SSL_CTX_set_dh_auto(sctx, 1))
            || !TEST_true(SSL_CTX_set_cipher_list(cctx, cipher_list[testidx]))
            || !TEST_true(SSL_CTX_set_ciphersuites(cctx, ""))
            || !TEST_ptr(ciphers = SSL_CTX_get_ciphers(cctx))
            || !TEST_int_eq(sk_SSL_CIPHER_num(ciphers), 1)
            || !TEST_ptr(currcipher = sk_SSL_CIPHER_value(ciphers, 0)))
        goto end;

    /*
     * No ciphers we are using are TLSv1.3 compatible so we should not attempt
     * to negotiate TLSv1.3
     */
    if (!TEST_true(SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION)))
        goto end;

    if (!TEST_ptr(c_to_s_fbio = BIO_new(bio_f_tls_corrupt_filter())))
        goto end;

    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL,
                                      c_to_s_fbio)))
        goto end;

    if (!TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;

    docorrupt = 1;

    if (!TEST_int_ge(SSL_write(client, junk, sizeof(junk)), 0))
        goto end;

    if (!TEST_int_lt(SSL_read(server, junk, sizeof(junk)), 0))
        goto end;

    do {
        err = ERR_get_error();

        if (err == 0) {
            TEST_error("Decryption failed or bad record MAC not seen");
            goto end;
        }
    } while (ERR_GET_REASON(err) != SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);

    testresult = 1;
 end:
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
#define NOTREADY
    /* still a bit of a stub for now */
#ifdef NOTREADY
    return 1;
#endif
    return testresult;
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    int n;

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

    n = setup_cipher_list();
    if (n > 0)
        ADD_ALL_TESTS(test_ech_corrupt, n);
    return 1;
err:
    return 0;
}

void cleanup_tests(void)
{
    bio_f_tls_corrupt_filter_free();
    OPENSSL_free(cipher_list);
}
