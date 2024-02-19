/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
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

# include "internal/ech_helpers.h"

int SSL_CTX_sech_decode_sni(SSL_CTX *ctx)
{
    fprintf(stderr, "hello from SSL_CTX_sech_decode_sni");
    return 200*200;
}
