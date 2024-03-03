/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "sech_local.h"
#include "ssl_local.h"
#include "ech_local.h"
#include "statem/statem_local.h"
#include <openssl/rand.h>
#include <openssl/trace.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* Needed to use stat for file status below in ech_check_filenames */
#include <sys/types.h>
#include <sys/stat.h>
#if !defined(OPENSSL_SYS_WINDOWS)
# include <unistd.h>
#endif
#include "internal/o_dir.h"


# ifndef PATH_MAX
#  define PATH_MAX 4096
# endif

/* For ossl_assert */
# include "internal/cryptlib.h"

/* For HPKE APIs */
# include <openssl/hpke.h>
# include "sech_local.h"

int SSL_CTX_sech_decode_sni(SSL_CTX *ctx)
{
    fprintf(stderr, "hello from SSL_CTX_sech_decode_sni");
    return 200*200;
}

int SSL_CTX_sech_symmetric_key(SSL_CTX *ctx, char *key)
{
    fprintf(stderr, "SECH: key %s\n", key);
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "SECH: test trace 1");
    } OSSL_TRACE_END(TLS);
    if (key == NULL) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "SECH: ERROR: Supplied symmetric key is NULL\n");
        } OSSL_TRACE_END(TLS);
        return 0;
    }
    if (ctx == NULL) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "SECH: ERROR: call to SSL_CTX_sech_symmetric_key with ctx==NULL.\n");
        } OSSL_TRACE_END(TLS);
        return 0;
    }
    int asciilen = strlen(key);
    if (asciilen%2 == 1) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "SECH: ERROR: Supplied symmetric odd length: %i\n", asciilen);
        } OSSL_TRACE_END(TLS);
        return 0;
    }
    if((asciilen/2) >= SECH_SYMMETRIC_KEY_MAX_LENGTH - 1) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "SECH: ERROR: Supplied symmetric key wrong length: %i > %i\n", asciilen, SECH_SYMMETRIC_KEY_MAX_LENGTH);
        } OSSL_TRACE_END(TLS);
        return 0;
    }

    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "SECH: Symmetric key ascii len %i\n", asciilen);
    } OSSL_TRACE_END(TLS);

    // zero the symmetric key
    for(int i = 0; i < SECH_SYMMETRIC_KEY_MAX_LENGTH; ++i) {
        ctx->sech.symmetric_key[i] = 0;
    }

    // parse ascii hex key to bytes
    int numBytes = asciilen / 2;
    ctx->sech.symmetric_key_len = numBytes;
    for(int i = 0; i < numBytes; ++i) {
        char hex[3] = {key[2*i], key[2*i+1], '\0'};
        ctx->sech.symmetric_key[i] = (char) strtol(hex, NULL, 16);
    }
    for(int i = 0; i < numBytes; ++i) {
        fprintf(stderr, "%02X ",(unsigned char) ctx->sech.symmetric_key[i]);
    }
    fprintf(stderr,"\n");
    OSSL_TRACE_BEGIN(TLS) {
        fprintf(stderr, "SECH: test trace 2 fprintf");
        BIO_printf(trc_out, "SECH: test trace 2");
    } OSSL_TRACE_END(TLS);
    return 1;
}
