/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This has the externally-visible data structures and prototypes
 * for handling Encrypted ClientHello (ECH)
 * See the documentation in SSL_ech_set1_echcofig.pod
 */
#ifndef OPENSSL_SECH_H
# define OPENSSL_SECH_H
# pragma once
# include <openssl/ssl.h>
# ifndef OPENSSL_NO_SECH
int SSL_CTX_sech_decode_sni(SSL_CTX *ctx);
int SSL_CTX_sech_symmetric_key(SSL_CTX *ctx, char *key);
# endif
#endif
