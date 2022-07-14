/*
 * Copyright 2015-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/decoder.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/proverr.h>
#include "testutil.h"
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "crypto/evp.h"
#include "fake_rsaprov.h"
#include "../e_os.h" /* strcasecmp */
#ifndef OPENSSL_NO_EC
#include "openssl/hpke.h"
#endif

#ifdef STATIC_LEGACY
OSSL_provider_init_fn ossl_legacy_provider_init;
#endif

static OSSL_LIB_CTX *testctx = NULL;
static char *testpropq = NULL;

static OSSL_PROVIDER *nullprov = NULL;
static OSSL_PROVIDER *deflprov = NULL;
static OSSL_PROVIDER *lgcyprov = NULL;

/*
 * kExampleRSAKeyDER is an RSA private key in ASN.1, DER format. Of course, you
 * should never use this key anywhere but in an example.
 */
static const unsigned char kExampleRSAKeyDER[] = {
    0x30, 0x82, 0x02, 0x5c, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xf8,
    0xb8, 0x6c, 0x83, 0xb4, 0xbc, 0xd9, 0xa8, 0x57, 0xc0, 0xa5, 0xb4, 0x59,
    0x76, 0x8c, 0x54, 0x1d, 0x79, 0xeb, 0x22, 0x52, 0x04, 0x7e, 0xd3, 0x37,
    0xeb, 0x41, 0xfd, 0x83, 0xf9, 0xf0, 0xa6, 0x85, 0x15, 0x34, 0x75, 0x71,
    0x5a, 0x84, 0xa8, 0x3c, 0xd2, 0xef, 0x5a, 0x4e, 0xd3, 0xde, 0x97, 0x8a,
    0xdd, 0xff, 0xbb, 0xcf, 0x0a, 0xaa, 0x86, 0x92, 0xbe, 0xb8, 0x50, 0xe4,
    0xcd, 0x6f, 0x80, 0x33, 0x30, 0x76, 0x13, 0x8f, 0xca, 0x7b, 0xdc, 0xec,
    0x5a, 0xca, 0x63, 0xc7, 0x03, 0x25, 0xef, 0xa8, 0x8a, 0x83, 0x58, 0x76,
    0x20, 0xfa, 0x16, 0x77, 0xd7, 0x79, 0x92, 0x63, 0x01, 0x48, 0x1a, 0xd8,
    0x7b, 0x67, 0xf1, 0x52, 0x55, 0x49, 0x4e, 0xd6, 0x6e, 0x4a, 0x5c, 0xd7,
    0x7a, 0x37, 0x36, 0x0c, 0xde, 0xdd, 0x8f, 0x44, 0xe8, 0xc2, 0xa7, 0x2c,
    0x2b, 0xb5, 0xaf, 0x64, 0x4b, 0x61, 0x07, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x81, 0x80, 0x74, 0x88, 0x64, 0x3f, 0x69, 0x45, 0x3a, 0x6d, 0xc7,
    0x7f, 0xb9, 0xa3, 0xc0, 0x6e, 0xec, 0xdc, 0xd4, 0x5a, 0xb5, 0x32, 0x85,
    0x5f, 0x19, 0xd4, 0xf8, 0xd4, 0x3f, 0x3c, 0xfa, 0xc2, 0xf6, 0x5f, 0xee,
    0xe6, 0xba, 0x87, 0x74, 0x2e, 0xc7, 0x0c, 0xd4, 0x42, 0xb8, 0x66, 0x85,
    0x9c, 0x7b, 0x24, 0x61, 0xaa, 0x16, 0x11, 0xf6, 0xb5, 0xb6, 0xa4, 0x0a,
    0xc9, 0x55, 0x2e, 0x81, 0xa5, 0x47, 0x61, 0xcb, 0x25, 0x8f, 0xc2, 0x15,
    0x7b, 0x0e, 0x7c, 0x36, 0x9f, 0x3a, 0xda, 0x58, 0x86, 0x1c, 0x5b, 0x83,
    0x79, 0xe6, 0x2b, 0xcc, 0xe6, 0xfa, 0x2c, 0x61, 0xf2, 0x78, 0x80, 0x1b,
    0xe2, 0xf3, 0x9d, 0x39, 0x2b, 0x65, 0x57, 0x91, 0x3d, 0x71, 0x99, 0x73,
    0xa5, 0xc2, 0x79, 0x20, 0x8c, 0x07, 0x4f, 0xe5, 0xb4, 0x60, 0x1f, 0x99,
    0xa2, 0xb1, 0x4f, 0x0c, 0xef, 0xbc, 0x59, 0x53, 0x00, 0x7d, 0xb1, 0x02,
    0x41, 0x00, 0xfc, 0x7e, 0x23, 0x65, 0x70, 0xf8, 0xce, 0xd3, 0x40, 0x41,
    0x80, 0x6a, 0x1d, 0x01, 0xd6, 0x01, 0xff, 0xb6, 0x1b, 0x3d, 0x3d, 0x59,
    0x09, 0x33, 0x79, 0xc0, 0x4f, 0xde, 0x96, 0x27, 0x4b, 0x18, 0xc6, 0xd9,
    0x78, 0xf1, 0xf4, 0x35, 0x46, 0xe9, 0x7c, 0x42, 0x7a, 0x5d, 0x9f, 0xef,
    0x54, 0xb8, 0xf7, 0x9f, 0xc4, 0x33, 0x6c, 0xf3, 0x8c, 0x32, 0x46, 0x87,
    0x67, 0x30, 0x7b, 0xa7, 0xac, 0xe3, 0x02, 0x41, 0x00, 0xfc, 0x2c, 0xdf,
    0x0c, 0x0d, 0x88, 0xf5, 0xb1, 0x92, 0xa8, 0x93, 0x47, 0x63, 0x55, 0xf5,
    0xca, 0x58, 0x43, 0xba, 0x1c, 0xe5, 0x9e, 0xb6, 0x95, 0x05, 0xcd, 0xb5,
    0x82, 0xdf, 0xeb, 0x04, 0x53, 0x9d, 0xbd, 0xc2, 0x38, 0x16, 0xb3, 0x62,
    0xdd, 0xa1, 0x46, 0xdb, 0x6d, 0x97, 0x93, 0x9f, 0x8a, 0xc3, 0x9b, 0x64,
    0x7e, 0x42, 0xe3, 0x32, 0x57, 0x19, 0x1b, 0xd5, 0x6e, 0x85, 0xfa, 0xb8,
    0x8d, 0x02, 0x41, 0x00, 0xbc, 0x3d, 0xde, 0x6d, 0xd6, 0x97, 0xe8, 0xba,
    0x9e, 0x81, 0x37, 0x17, 0xe5, 0xa0, 0x64, 0xc9, 0x00, 0xb7, 0xe7, 0xfe,
    0xf4, 0x29, 0xd9, 0x2e, 0x43, 0x6b, 0x19, 0x20, 0xbd, 0x99, 0x75, 0xe7,
    0x76, 0xf8, 0xd3, 0xae, 0xaf, 0x7e, 0xb8, 0xeb, 0x81, 0xf4, 0x9d, 0xfe,
    0x07, 0x2b, 0x0b, 0x63, 0x0b, 0x5a, 0x55, 0x90, 0x71, 0x7d, 0xf1, 0xdb,
    0xd9, 0xb1, 0x41, 0x41, 0x68, 0x2f, 0x4e, 0x39, 0x02, 0x40, 0x5a, 0x34,
    0x66, 0xd8, 0xf5, 0xe2, 0x7f, 0x18, 0xb5, 0x00, 0x6e, 0x26, 0x84, 0x27,
    0x14, 0x93, 0xfb, 0xfc, 0xc6, 0x0f, 0x5e, 0x27, 0xe6, 0xe1, 0xe9, 0xc0,
    0x8a, 0xe4, 0x34, 0xda, 0xe9, 0xa2, 0x4b, 0x73, 0xbc, 0x8c, 0xb9, 0xba,
    0x13, 0x6c, 0x7a, 0x2b, 0x51, 0x84, 0xa3, 0x4a, 0xe0, 0x30, 0x10, 0x06,
    0x7e, 0xed, 0x17, 0x5a, 0x14, 0x00, 0xc9, 0xef, 0x85, 0xea, 0x52, 0x2c,
    0xbc, 0x65, 0x02, 0x40, 0x51, 0xe3, 0xf2, 0x83, 0x19, 0x9b, 0xc4, 0x1e,
    0x2f, 0x50, 0x3d, 0xdf, 0x5a, 0xa2, 0x18, 0xca, 0x5f, 0x2e, 0x49, 0xaf,
    0x6f, 0xcc, 0xfa, 0x65, 0x77, 0x94, 0xb5, 0xa1, 0x0a, 0xa9, 0xd1, 0x8a,
    0x39, 0x37, 0xf4, 0x0b, 0xa0, 0xd7, 0x82, 0x27, 0x5e, 0xae, 0x17, 0x17,
    0xa1, 0x1e, 0x54, 0x34, 0xbf, 0x6e, 0xc4, 0x8e, 0x99, 0x5d, 0x08, 0xf1,
    0x2d, 0x86, 0x9d, 0xa5, 0x20, 0x1b, 0xe5, 0xdf,
};

/*
* kExampleDSAKeyDER is a DSA private key in ASN.1, DER format. Of course, you
 * should never use this key anywhere but in an example.
 */
#ifndef OPENSSL_NO_DSA
static const unsigned char kExampleDSAKeyDER[] = {
    0x30, 0x82, 0x01, 0xba, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0x9a,
    0x05, 0x6d, 0x33, 0xcd, 0x5d, 0x78, 0xa1, 0xbb, 0xcb, 0x7d, 0x5b, 0x8d,
    0xb4, 0xcc, 0xbf, 0x03, 0x99, 0x64, 0xde, 0x38, 0x78, 0x06, 0x15, 0x2f,
    0x86, 0x26, 0x77, 0xf3, 0xb1, 0x85, 0x00, 0xed, 0xfc, 0x28, 0x3a, 0x42,
    0x4d, 0xab, 0xab, 0xdf, 0xbc, 0x9c, 0x16, 0xd0, 0x22, 0x50, 0xd1, 0x38,
    0xdd, 0x3f, 0x64, 0x05, 0x9e, 0x68, 0x7a, 0x1e, 0xf1, 0x56, 0xbf, 0x1e,
    0x2c, 0xc5, 0x97, 0x2a, 0xfe, 0x7a, 0x22, 0xdc, 0x6c, 0x68, 0xb8, 0x2e,
    0x06, 0xdb, 0x41, 0xca, 0x98, 0xd8, 0x54, 0xc7, 0x64, 0x48, 0x24, 0x04,
    0x20, 0xbc, 0x59, 0xe3, 0x6b, 0xea, 0x7e, 0xfc, 0x7e, 0xc5, 0x4e, 0xd4,
    0xd8, 0x3a, 0xed, 0xcd, 0x5d, 0x99, 0xb8, 0x5c, 0xa2, 0x8b, 0xbb, 0x0b,
    0xac, 0xe6, 0x8e, 0x25, 0x56, 0x22, 0x3a, 0x2d, 0x3a, 0x56, 0x41, 0x14,
    0x1f, 0x1c, 0x8f, 0x53, 0x46, 0x13, 0x85, 0x02, 0x15, 0x00, 0x98, 0x7e,
    0x92, 0x81, 0x88, 0xc7, 0x3f, 0x70, 0x49, 0x54, 0xf6, 0x76, 0xb4, 0xa3,
    0x9e, 0x1d, 0x45, 0x98, 0x32, 0x7f, 0x02, 0x81, 0x80, 0x69, 0x4d, 0xef,
    0x55, 0xff, 0x4d, 0x59, 0x2c, 0x01, 0xfa, 0x6a, 0x38, 0xe0, 0x70, 0x9f,
    0x9e, 0x66, 0x8e, 0x3e, 0x8c, 0x52, 0x22, 0x9d, 0x15, 0x7e, 0x3c, 0xef,
    0x4c, 0x7a, 0x61, 0x26, 0xe0, 0x2b, 0x81, 0x3f, 0xeb, 0xaf, 0x35, 0x38,
    0x8d, 0xfe, 0xed, 0x46, 0xff, 0x5f, 0x03, 0x9b, 0x81, 0x92, 0xe7, 0x6f,
    0x76, 0x4f, 0x1d, 0xd9, 0xbb, 0x89, 0xc9, 0x3e, 0xd9, 0x0b, 0xf9, 0xf4,
    0x78, 0x11, 0x59, 0xc0, 0x1d, 0xcd, 0x0e, 0xa1, 0x6f, 0x15, 0xf1, 0x4d,
    0xc1, 0xc9, 0x22, 0xed, 0x8d, 0xad, 0x67, 0xc5, 0x4b, 0x95, 0x93, 0x86,
    0xa6, 0xaf, 0x8a, 0xee, 0x06, 0x89, 0x2f, 0x37, 0x7e, 0x64, 0xaa, 0xf6,
    0xe7, 0xb1, 0x5a, 0x0a, 0x93, 0x95, 0x5d, 0x3e, 0x53, 0x9a, 0xde, 0x8a,
    0xc2, 0x95, 0x45, 0x81, 0xbe, 0x5c, 0x2f, 0xc2, 0xb2, 0x92, 0x58, 0x19,
    0x72, 0x80, 0xe9, 0x79, 0xa1, 0x02, 0x81, 0x80, 0x07, 0xd7, 0x62, 0xff,
    0xdf, 0x1a, 0x3f, 0xed, 0x32, 0xd4, 0xd4, 0x88, 0x7b, 0x2c, 0x63, 0x7f,
    0x97, 0xdc, 0x44, 0xd4, 0x84, 0xa2, 0xdd, 0x17, 0x16, 0x85, 0x13, 0xe0,
    0xac, 0x51, 0x8d, 0x29, 0x1b, 0x75, 0x9a, 0xe4, 0xe3, 0x8a, 0x92, 0x69,
    0x09, 0x03, 0xc5, 0x68, 0xae, 0x5e, 0x94, 0xfe, 0xc9, 0x92, 0x6c, 0x07,
    0xb4, 0x1e, 0x64, 0x62, 0x87, 0xc6, 0xa4, 0xfd, 0x0d, 0x5f, 0xe5, 0xf9,
    0x1b, 0x4f, 0x85, 0x5f, 0xae, 0xf3, 0x11, 0xe5, 0x18, 0xd4, 0x4d, 0x79,
    0x9f, 0xc4, 0x79, 0x26, 0x04, 0x27, 0xf0, 0x0b, 0xee, 0x2b, 0x86, 0x9f,
    0x86, 0x61, 0xe6, 0x51, 0xce, 0x04, 0x9b, 0x5d, 0x6b, 0x34, 0x43, 0x8c,
    0x85, 0x3c, 0xf1, 0x51, 0x9b, 0x08, 0x23, 0x1b, 0xf5, 0x7e, 0x33, 0x12,
    0xea, 0xab, 0x1f, 0xb7, 0x2d, 0xe2, 0x5f, 0xe6, 0x97, 0x99, 0xb5, 0x45,
    0x16, 0x5b, 0xc3, 0x41, 0x02, 0x14, 0x61, 0xbf, 0x51, 0x60, 0xcf, 0xc8,
    0xf1, 0x8c, 0x82, 0x97, 0xf2, 0xf4, 0x19, 0xba, 0x2b, 0xf3, 0x16, 0xbe,
    0x40, 0x48
};
#endif

/*
 * kExampleBadRSAKeyDER is an RSA private key in ASN.1, DER format. The private
 * components are not correct.
 */
static const unsigned char kExampleBadRSAKeyDER[] = {
    0x30, 0x82, 0x04, 0x27, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
    0xa6, 0x1a, 0x1e, 0x6e, 0x7b, 0xee, 0xc6, 0x89, 0x66, 0xe7, 0x93, 0xef,
    0x54, 0x12, 0x68, 0xea, 0xbf, 0x86, 0x2f, 0xdd, 0xd2, 0x79, 0xb8, 0xa9,
    0x6e, 0x03, 0xc2, 0xa3, 0xb9, 0xa3, 0xe1, 0x4b, 0x2a, 0xb3, 0xf8, 0xb4,
    0xcd, 0xea, 0xbe, 0x24, 0xa6, 0x57, 0x5b, 0x83, 0x1f, 0x0f, 0xf2, 0xd3,
    0xb7, 0xac, 0x7e, 0xd6, 0x8e, 0x6e, 0x1e, 0xbf, 0xb8, 0x73, 0x8c, 0x05,
    0x56, 0xe6, 0x35, 0x1f, 0xe9, 0x04, 0x0b, 0x09, 0x86, 0x7d, 0xf1, 0x26,
    0x08, 0x99, 0xad, 0x7b, 0xc8, 0x4d, 0x94, 0xb0, 0x0b, 0x8b, 0x38, 0xa0,
    0x5c, 0x62, 0xa0, 0xab, 0xd3, 0x8f, 0xd4, 0x09, 0x60, 0x72, 0x1e, 0x33,
    0x50, 0x80, 0x6e, 0x22, 0xa6, 0x77, 0x57, 0x6b, 0x9a, 0x33, 0x21, 0x66,
    0x87, 0x6e, 0x21, 0x7b, 0xc7, 0x24, 0x0e, 0xd8, 0x13, 0xdf, 0x83, 0xde,
    0xcd, 0x40, 0x58, 0x1d, 0x84, 0x86, 0xeb, 0xb8, 0x12, 0x4e, 0xd2, 0xfa,
    0x80, 0x1f, 0xe4, 0xe7, 0x96, 0x29, 0xb8, 0xcc, 0xce, 0x66, 0x6d, 0x53,
    0xca, 0xb9, 0x5a, 0xd7, 0xf6, 0x84, 0x6c, 0x2d, 0x9a, 0x1a, 0x14, 0x1c,
    0x4e, 0x93, 0x39, 0xba, 0x74, 0xed, 0xed, 0x87, 0x87, 0x5e, 0x48, 0x75,
    0x36, 0xf0, 0xbc, 0x34, 0xfb, 0x29, 0xf9, 0x9f, 0x96, 0x5b, 0x0b, 0xa7,
    0x54, 0x30, 0x51, 0x29, 0x18, 0x5b, 0x7d, 0xac, 0x0f, 0xd6, 0x5f, 0x7c,
    0xf8, 0x98, 0x8c, 0xd8, 0x86, 0x62, 0xb3, 0xdc, 0xff, 0x0f, 0xff, 0x7a,
    0xaf, 0x5c, 0x4c, 0x61, 0x49, 0x2e, 0xc8, 0x95, 0x86, 0xc4, 0x0e, 0x87,
    0xfc, 0x1d, 0xcf, 0x8b, 0x7c, 0x61, 0xf6, 0xd8, 0xd0, 0x69, 0xf6, 0xcd,
    0x8a, 0x8c, 0xf6, 0x62, 0xa2, 0x56, 0xa9, 0xe3, 0xd1, 0xcf, 0x4d, 0xa0,
    0xf6, 0x2d, 0x20, 0x0a, 0x04, 0xb7, 0xa2, 0xf7, 0xb5, 0x99, 0x47, 0x18,
    0x56, 0x85, 0x87, 0xc7, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
    0x01, 0x00, 0x99, 0x41, 0x38, 0x1a, 0xd0, 0x96, 0x7a, 0xf0, 0x83, 0xd5,
    0xdf, 0x94, 0xce, 0x89, 0x3d, 0xec, 0x7a, 0x52, 0x21, 0x10, 0x16, 0x06,
    0xe0, 0xee, 0xd2, 0xe6, 0xfd, 0x4b, 0x7b, 0x19, 0x4d, 0xe1, 0xc0, 0xc0,
    0xd5, 0x14, 0x5d, 0x79, 0xdd, 0x7e, 0x8b, 0x4b, 0xc6, 0xcf, 0xb0, 0x75,
    0x52, 0xa3, 0x2d, 0xb1, 0x26, 0x46, 0x68, 0x9c, 0x0a, 0x1a, 0xf2, 0xe1,
    0x09, 0xac, 0x53, 0x85, 0x8c, 0x36, 0xa9, 0x14, 0x65, 0xea, 0xa0, 0x00,
    0xcb, 0xe3, 0x3f, 0xc4, 0x2b, 0x61, 0x2e, 0x6b, 0x06, 0x69, 0x77, 0xfd,
    0x38, 0x7e, 0x1d, 0x3f, 0x92, 0xe7, 0x77, 0x08, 0x19, 0xa7, 0x9d, 0x29,
    0x2d, 0xdc, 0x42, 0xc6, 0x7c, 0xd7, 0xd3, 0xa8, 0x01, 0x2c, 0xf2, 0xd5,
    0x82, 0x57, 0xcb, 0x55, 0x3d, 0xe7, 0xaa, 0xd2, 0x06, 0x30, 0x30, 0x05,
    0xe6, 0xf2, 0x47, 0x86, 0xba, 0xc6, 0x61, 0x64, 0xeb, 0x4f, 0x2a, 0x5e,
    0x07, 0x29, 0xe0, 0x96, 0xb2, 0x43, 0xff, 0x5f, 0x1a, 0x54, 0x16, 0xcf,
    0xb5, 0x56, 0x5c, 0xa0, 0x9b, 0x0c, 0xfd, 0xb3, 0xd2, 0xe3, 0x79, 0x1d,
    0x21, 0xe2, 0xd6, 0x13, 0xc4, 0x74, 0xa6, 0xf5, 0x8e, 0x8e, 0x81, 0xbb,
    0xb4, 0xad, 0x8a, 0xf0, 0x93, 0x0a, 0xd8, 0x0a, 0x42, 0x36, 0xbc, 0xe5,
    0x26, 0x2a, 0x0d, 0x5d, 0x57, 0x13, 0xc5, 0x4e, 0x2f, 0x12, 0x0e, 0xef,
    0xa7, 0x81, 0x1e, 0xc3, 0xa5, 0xdb, 0xc9, 0x24, 0xeb, 0x1a, 0xa1, 0xf9,
    0xf6, 0xa1, 0x78, 0x98, 0x93, 0x77, 0x42, 0x45, 0x03, 0xe2, 0xc9, 0xa2,
    0xfe, 0x2d, 0x77, 0xc8, 0xc6, 0xac, 0x9b, 0x98, 0x89, 0x6d, 0x9a, 0xe7,
    0x61, 0x63, 0xb7, 0xf2, 0xec, 0xd6, 0xb1, 0xa1, 0x6e, 0x0a, 0x1a, 0xff,
    0xfd, 0x43, 0x28, 0xc3, 0x0c, 0xdc, 0xf2, 0x47, 0x4f, 0x27, 0xaa, 0x99,
    0x04, 0x8e, 0xac, 0xe8, 0x7c, 0x01, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78,
    0x02, 0x81, 0x81, 0x00, 0xca, 0x69, 0xe5, 0xbb, 0x3a, 0x90, 0x82, 0xcb,
    0x82, 0x50, 0x2f, 0x29, 0xe2, 0x76, 0x6a, 0x57, 0x55, 0x45, 0x4e, 0x35,
    0x18, 0x61, 0xe0, 0x12, 0x70, 0xc0, 0xab, 0xc7, 0x80, 0xa2, 0xd4, 0x46,
    0x34, 0x03, 0xa0, 0x19, 0x26, 0x23, 0x9e, 0xef, 0x1a, 0xcb, 0x75, 0xd6,
    0xba, 0x81, 0xf4, 0x7e, 0x52, 0xe5, 0x2a, 0xe8, 0xf1, 0x49, 0x6c, 0x0f,
    0x1a, 0xa0, 0xf9, 0xc6, 0xe7, 0xec, 0x60, 0xe4, 0xcb, 0x2a, 0xb5, 0x56,
    0xe9, 0x9c, 0xcd, 0x19, 0x75, 0x92, 0xb1, 0x66, 0xce, 0xc3, 0xd9, 0x3d,
    0x11, 0xcb, 0xc4, 0x09, 0xce, 0x1e, 0x30, 0xba, 0x2f, 0x60, 0x60, 0x55,
    0x8d, 0x02, 0xdc, 0x5d, 0xaf, 0xf7, 0x52, 0x31, 0x17, 0x07, 0x53, 0x20,
    0x33, 0xad, 0x8c, 0xd5, 0x2f, 0x5a, 0xd0, 0x57, 0xd7, 0xd1, 0x80, 0xd6,
    0x3a, 0x9b, 0x04, 0x4f, 0x35, 0xbf, 0xe7, 0xd5, 0xbc, 0x8f, 0xd4, 0x81,
    0x02, 0x81, 0x81, 0x00, 0xc0, 0x9f, 0xf8, 0xcd, 0xf7, 0x3f, 0x26, 0x8a,
    0x3d, 0x4d, 0x2b, 0x0c, 0x01, 0xd0, 0xa2, 0xb4, 0x18, 0xfe, 0xf7, 0x5e,
    0x2f, 0x06, 0x13, 0xcd, 0x63, 0xaa, 0x12, 0xa9, 0x24, 0x86, 0xe3, 0xf3,
    0x7b, 0xda, 0x1a, 0x3c, 0xb1, 0x38, 0x80, 0x80, 0xef, 0x64, 0x64, 0xa1,
    0x9b, 0xfe, 0x76, 0x63, 0x8e, 0x83, 0xd2, 0xd9, 0xb9, 0x86, 0xb0, 0xe6,
    0xa6, 0x0c, 0x7e, 0xa8, 0x84, 0x90, 0x98, 0x0c, 0x1e, 0xf3, 0x14, 0x77,
    0xe0, 0x5f, 0x81, 0x08, 0x11, 0x8f, 0xa6, 0x23, 0xc4, 0xba, 0xc0, 0x8a,
    0xe4, 0xc6, 0xe3, 0x5c, 0xbe, 0xc5, 0xec, 0x2c, 0xb9, 0xd8, 0x8c, 0x4d,
    0x1a, 0x9d, 0xe7, 0x7c, 0x85, 0x4c, 0x0d, 0x71, 0x4e, 0x72, 0x33, 0x1b,
    0xfe, 0xa9, 0x17, 0x72, 0x76, 0x56, 0x9d, 0x74, 0x7e, 0x52, 0x67, 0x9a,
    0x87, 0x9a, 0xdb, 0x30, 0xde, 0xe4, 0x49, 0x28, 0x3b, 0xd2, 0x67, 0xaf,
    0x02, 0x81, 0x81, 0x00, 0x89, 0x74, 0x9a, 0x8e, 0xa7, 0xb9, 0xa5, 0x28,
    0xc0, 0x68, 0xe5, 0x6e, 0x63, 0x1c, 0x99, 0x20, 0x8f, 0x86, 0x8e, 0x12,
    0x9e, 0x69, 0x30, 0xfa, 0x34, 0xd9, 0x92, 0x8d, 0xdb, 0x7c, 0x37, 0xfd,
    0x28, 0xab, 0x61, 0x98, 0x52, 0x7f, 0x14, 0x1a, 0x39, 0xae, 0xfb, 0x6a,
    0x03, 0xa3, 0xe6, 0xbd, 0xb6, 0x5b, 0x6b, 0xe5, 0x5e, 0x9d, 0xc6, 0xa5,
    0x07, 0x27, 0x54, 0x17, 0xd0, 0x3d, 0x84, 0x9b, 0x3a, 0xa0, 0xd9, 0x1e,
    0x99, 0x6c, 0x63, 0x17, 0xab, 0xf1, 0x1f, 0x49, 0xba, 0x95, 0xe3, 0x3b,
    0x86, 0x8f, 0x42, 0xa4, 0x89, 0xf5, 0x94, 0x8f, 0x8b, 0x46, 0xbe, 0x84,
    0xba, 0x4a, 0xbc, 0x0d, 0x5f, 0x46, 0xeb, 0xe8, 0xec, 0x43, 0x8c, 0x1e,
    0xad, 0x19, 0x69, 0x2f, 0x08, 0x86, 0x7a, 0x3f, 0x7d, 0x0f, 0x07, 0x97,
    0xf3, 0x9a, 0x7b, 0xb5, 0xb2, 0xc1, 0x8c, 0x95, 0x68, 0x04, 0xa0, 0x81,
    0x02, 0x81, 0x80, 0x4e, 0xbf, 0x7e, 0x1b, 0xcb, 0x13, 0x61, 0x75, 0x3b,
    0xdb, 0x59, 0x5f, 0xb1, 0xd4, 0xb8, 0xeb, 0x9e, 0x73, 0xb5, 0xe7, 0xf6,
    0x89, 0x3d, 0x1c, 0xda, 0xf0, 0x36, 0xff, 0x35, 0xbd, 0x1e, 0x0b, 0x74,
    0xe3, 0x9e, 0xf0, 0xf2, 0xf7, 0xd7, 0x82, 0xb7, 0x7b, 0x6a, 0x1b, 0x0e,
    0x30, 0x4a, 0x98, 0x0e, 0xb4, 0xf9, 0x81, 0x07, 0xe4, 0x75, 0x39, 0xe9,
    0x53, 0xca, 0xbb, 0x5c, 0xaa, 0x93, 0x07, 0x0e, 0xa8, 0x2f, 0xba, 0x98,
    0x49, 0x30, 0xa7, 0xcc, 0x1a, 0x3c, 0x68, 0x0c, 0xe1, 0xa4, 0xb1, 0x05,
    0xe6, 0xe0, 0x25, 0x78, 0x58, 0x14, 0x37, 0xf5, 0x1f, 0xe3, 0x22, 0xef,
    0xa8, 0x0e, 0x22, 0xa0, 0x94, 0x3a, 0xf6, 0xc9, 0x13, 0xe6, 0x06, 0xbf,
    0x7f, 0x99, 0xc6, 0xcc, 0xd8, 0xc6, 0xbe, 0xd9, 0x2e, 0x24, 0xc7, 0x69,
    0x8c, 0x95, 0xba, 0xf6, 0x04, 0xb3, 0x0a, 0xf4, 0xcb, 0xf0, 0xce,
};

/*
 * kExampleBad2RSAKeyDER is an RSA private key in ASN.1, DER format. All
 * values are 0.
 */
static const unsigned char kExampleBad2RSAKeyDER[] = {
    0x30, 0x1b, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02,
    0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02,
    0x01, 0x00, 0x02, 0x01, 0x00
};

static const unsigned char kMsg[] = { 1, 2, 3, 4 };

static const unsigned char kSignature[] = {
    0xa5, 0xf0, 0x8a, 0x47, 0x5d, 0x3c, 0xb3, 0xcc, 0xa9, 0x79, 0xaf, 0x4d,
    0x8c, 0xae, 0x4c, 0x14, 0xef, 0xc2, 0x0b, 0x34, 0x36, 0xde, 0xf4, 0x3e,
    0x3d, 0xbb, 0x4a, 0x60, 0x5c, 0xc8, 0x91, 0x28, 0xda, 0xfb, 0x7e, 0x04,
    0x96, 0x7e, 0x63, 0x13, 0x90, 0xce, 0xb9, 0xb4, 0x62, 0x7a, 0xfd, 0x09,
    0x3d, 0xc7, 0x67, 0x78, 0x54, 0x04, 0xeb, 0x52, 0x62, 0x6e, 0x24, 0x67,
    0xb4, 0x40, 0xfc, 0x57, 0x62, 0xc6, 0xf1, 0x67, 0xc1, 0x97, 0x8f, 0x6a,
    0xa8, 0xae, 0x44, 0x46, 0x5e, 0xab, 0x67, 0x17, 0x53, 0x19, 0x3a, 0xda,
    0x5a, 0xc8, 0x16, 0x3e, 0x86, 0xd5, 0xc5, 0x71, 0x2f, 0xfc, 0x23, 0x48,
    0xd9, 0x0b, 0x13, 0xdd, 0x7b, 0x5a, 0x25, 0x79, 0xef, 0xa5, 0x7b, 0x04,
    0xed, 0x44, 0xf6, 0x18, 0x55, 0xe4, 0x0a, 0xe9, 0x57, 0x79, 0x5d, 0xd7,
    0x55, 0xa7, 0xab, 0x45, 0x02, 0x97, 0x60, 0x42,
};

/*
 * kExampleRSAKeyPKCS8 is kExampleRSAKeyDER encoded in a PKCS #8
 * PrivateKeyInfo.
 */
static const unsigned char kExampleRSAKeyPKCS8[] = {
    0x30, 0x82, 0x02, 0x76, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
    0x02, 0x60, 0x30, 0x82, 0x02, 0x5c, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81,
    0x00, 0xf8, 0xb8, 0x6c, 0x83, 0xb4, 0xbc, 0xd9, 0xa8, 0x57, 0xc0, 0xa5,
    0xb4, 0x59, 0x76, 0x8c, 0x54, 0x1d, 0x79, 0xeb, 0x22, 0x52, 0x04, 0x7e,
    0xd3, 0x37, 0xeb, 0x41, 0xfd, 0x83, 0xf9, 0xf0, 0xa6, 0x85, 0x15, 0x34,
    0x75, 0x71, 0x5a, 0x84, 0xa8, 0x3c, 0xd2, 0xef, 0x5a, 0x4e, 0xd3, 0xde,
    0x97, 0x8a, 0xdd, 0xff, 0xbb, 0xcf, 0x0a, 0xaa, 0x86, 0x92, 0xbe, 0xb8,
    0x50, 0xe4, 0xcd, 0x6f, 0x80, 0x33, 0x30, 0x76, 0x13, 0x8f, 0xca, 0x7b,
    0xdc, 0xec, 0x5a, 0xca, 0x63, 0xc7, 0x03, 0x25, 0xef, 0xa8, 0x8a, 0x83,
    0x58, 0x76, 0x20, 0xfa, 0x16, 0x77, 0xd7, 0x79, 0x92, 0x63, 0x01, 0x48,
    0x1a, 0xd8, 0x7b, 0x67, 0xf1, 0x52, 0x55, 0x49, 0x4e, 0xd6, 0x6e, 0x4a,
    0x5c, 0xd7, 0x7a, 0x37, 0x36, 0x0c, 0xde, 0xdd, 0x8f, 0x44, 0xe8, 0xc2,
    0xa7, 0x2c, 0x2b, 0xb5, 0xaf, 0x64, 0x4b, 0x61, 0x07, 0x02, 0x03, 0x01,
    0x00, 0x01, 0x02, 0x81, 0x80, 0x74, 0x88, 0x64, 0x3f, 0x69, 0x45, 0x3a,
    0x6d, 0xc7, 0x7f, 0xb9, 0xa3, 0xc0, 0x6e, 0xec, 0xdc, 0xd4, 0x5a, 0xb5,
    0x32, 0x85, 0x5f, 0x19, 0xd4, 0xf8, 0xd4, 0x3f, 0x3c, 0xfa, 0xc2, 0xf6,
    0x5f, 0xee, 0xe6, 0xba, 0x87, 0x74, 0x2e, 0xc7, 0x0c, 0xd4, 0x42, 0xb8,
    0x66, 0x85, 0x9c, 0x7b, 0x24, 0x61, 0xaa, 0x16, 0x11, 0xf6, 0xb5, 0xb6,
    0xa4, 0x0a, 0xc9, 0x55, 0x2e, 0x81, 0xa5, 0x47, 0x61, 0xcb, 0x25, 0x8f,
    0xc2, 0x15, 0x7b, 0x0e, 0x7c, 0x36, 0x9f, 0x3a, 0xda, 0x58, 0x86, 0x1c,
    0x5b, 0x83, 0x79, 0xe6, 0x2b, 0xcc, 0xe6, 0xfa, 0x2c, 0x61, 0xf2, 0x78,
    0x80, 0x1b, 0xe2, 0xf3, 0x9d, 0x39, 0x2b, 0x65, 0x57, 0x91, 0x3d, 0x71,
    0x99, 0x73, 0xa5, 0xc2, 0x79, 0x20, 0x8c, 0x07, 0x4f, 0xe5, 0xb4, 0x60,
    0x1f, 0x99, 0xa2, 0xb1, 0x4f, 0x0c, 0xef, 0xbc, 0x59, 0x53, 0x00, 0x7d,
    0xb1, 0x02, 0x41, 0x00, 0xfc, 0x7e, 0x23, 0x65, 0x70, 0xf8, 0xce, 0xd3,
    0x40, 0x41, 0x80, 0x6a, 0x1d, 0x01, 0xd6, 0x01, 0xff, 0xb6, 0x1b, 0x3d,
    0x3d, 0x59, 0x09, 0x33, 0x79, 0xc0, 0x4f, 0xde, 0x96, 0x27, 0x4b, 0x18,
    0xc6, 0xd9, 0x78, 0xf1, 0xf4, 0x35, 0x46, 0xe9, 0x7c, 0x42, 0x7a, 0x5d,
    0x9f, 0xef, 0x54, 0xb8, 0xf7, 0x9f, 0xc4, 0x33, 0x6c, 0xf3, 0x8c, 0x32,
    0x46, 0x87, 0x67, 0x30, 0x7b, 0xa7, 0xac, 0xe3, 0x02, 0x41, 0x00, 0xfc,
    0x2c, 0xdf, 0x0c, 0x0d, 0x88, 0xf5, 0xb1, 0x92, 0xa8, 0x93, 0x47, 0x63,
    0x55, 0xf5, 0xca, 0x58, 0x43, 0xba, 0x1c, 0xe5, 0x9e, 0xb6, 0x95, 0x05,
    0xcd, 0xb5, 0x82, 0xdf, 0xeb, 0x04, 0x53, 0x9d, 0xbd, 0xc2, 0x38, 0x16,
    0xb3, 0x62, 0xdd, 0xa1, 0x46, 0xdb, 0x6d, 0x97, 0x93, 0x9f, 0x8a, 0xc3,
    0x9b, 0x64, 0x7e, 0x42, 0xe3, 0x32, 0x57, 0x19, 0x1b, 0xd5, 0x6e, 0x85,
    0xfa, 0xb8, 0x8d, 0x02, 0x41, 0x00, 0xbc, 0x3d, 0xde, 0x6d, 0xd6, 0x97,
    0xe8, 0xba, 0x9e, 0x81, 0x37, 0x17, 0xe5, 0xa0, 0x64, 0xc9, 0x00, 0xb7,
    0xe7, 0xfe, 0xf4, 0x29, 0xd9, 0x2e, 0x43, 0x6b, 0x19, 0x20, 0xbd, 0x99,
    0x75, 0xe7, 0x76, 0xf8, 0xd3, 0xae, 0xaf, 0x7e, 0xb8, 0xeb, 0x81, 0xf4,
    0x9d, 0xfe, 0x07, 0x2b, 0x0b, 0x63, 0x0b, 0x5a, 0x55, 0x90, 0x71, 0x7d,
    0xf1, 0xdb, 0xd9, 0xb1, 0x41, 0x41, 0x68, 0x2f, 0x4e, 0x39, 0x02, 0x40,
    0x5a, 0x34, 0x66, 0xd8, 0xf5, 0xe2, 0x7f, 0x18, 0xb5, 0x00, 0x6e, 0x26,
    0x84, 0x27, 0x14, 0x93, 0xfb, 0xfc, 0xc6, 0x0f, 0x5e, 0x27, 0xe6, 0xe1,
    0xe9, 0xc0, 0x8a, 0xe4, 0x34, 0xda, 0xe9, 0xa2, 0x4b, 0x73, 0xbc, 0x8c,
    0xb9, 0xba, 0x13, 0x6c, 0x7a, 0x2b, 0x51, 0x84, 0xa3, 0x4a, 0xe0, 0x30,
    0x10, 0x06, 0x7e, 0xed, 0x17, 0x5a, 0x14, 0x00, 0xc9, 0xef, 0x85, 0xea,
    0x52, 0x2c, 0xbc, 0x65, 0x02, 0x40, 0x51, 0xe3, 0xf2, 0x83, 0x19, 0x9b,
    0xc4, 0x1e, 0x2f, 0x50, 0x3d, 0xdf, 0x5a, 0xa2, 0x18, 0xca, 0x5f, 0x2e,
    0x49, 0xaf, 0x6f, 0xcc, 0xfa, 0x65, 0x77, 0x94, 0xb5, 0xa1, 0x0a, 0xa9,
    0xd1, 0x8a, 0x39, 0x37, 0xf4, 0x0b, 0xa0, 0xd7, 0x82, 0x27, 0x5e, 0xae,
    0x17, 0x17, 0xa1, 0x1e, 0x54, 0x34, 0xbf, 0x6e, 0xc4, 0x8e, 0x99, 0x5d,
    0x08, 0xf1, 0x2d, 0x86, 0x9d, 0xa5, 0x20, 0x1b, 0xe5, 0xdf,
};

#ifndef OPENSSL_NO_EC
/*
 * kExampleECKeyDER is a sample EC private key encoded as an ECPrivateKey
 * structure.
 */
static const unsigned char kExampleECKeyDER[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x07, 0x0f, 0x08, 0x72, 0x7a,
    0xd4, 0xa0, 0x4a, 0x9c, 0xdd, 0x59, 0xc9, 0x4d, 0x89, 0x68, 0x77, 0x08,
    0xb5, 0x6f, 0xc9, 0x5d, 0x30, 0x77, 0x0e, 0xe8, 0xd1, 0xc9, 0xce, 0x0a,
    0x8b, 0xb4, 0x6a, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xe6, 0x2b, 0x69,
    0xe2, 0xbf, 0x65, 0x9f, 0x97, 0xbe, 0x2f, 0x1e, 0x0d, 0x94, 0x8a, 0x4c,
    0xd5, 0x97, 0x6b, 0xb7, 0xa9, 0x1e, 0x0d, 0x46, 0xfb, 0xdd, 0xa9, 0xa9,
    0x1e, 0x9d, 0xdc, 0xba, 0x5a, 0x01, 0xe7, 0xd6, 0x97, 0xa8, 0x0a, 0x18,
    0xf9, 0xc3, 0xc4, 0xa3, 0x1e, 0x56, 0xe2, 0x7c, 0x83, 0x48, 0xdb, 0x16,
    0x1a, 0x1c, 0xf5, 0x1d, 0x7e, 0xf1, 0x94, 0x2d, 0x4b, 0xcf, 0x72, 0x22,
    0xc1,
};

/*
 * kExampleBadECKeyDER is a sample EC private key encoded as an ECPrivateKey
 * structure. The private key is equal to the order and will fail to import
 */
static const unsigned char kExampleBadECKeyDER[] = {
    0x30, 0x66, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
    0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03,
    0x01, 0x07, 0x04, 0x4C, 0x30, 0x4A, 0x02, 0x01, 0x01, 0x04, 0x20, 0xFF,
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3,
    0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51, 0xA1, 0x23, 0x03, 0x21, 0x00,
    0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

/* prime256v1 */
static const unsigned char kExampleECPubKeyDER[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xba, 0xeb, 0x83, 0xfb, 0x3b, 0xb2, 0xff, 0x30, 0x53,
    0xdb, 0xce, 0x32, 0xf2, 0xac, 0xae, 0x44, 0x0d, 0x3d, 0x13, 0x53, 0xb8,
    0xd1, 0x68, 0x55, 0xde, 0x44, 0x46, 0x05, 0xa6, 0xc9, 0xd2, 0x04, 0xb7,
    0xe3, 0xa2, 0x96, 0xc8, 0xb2, 0x5e, 0x22, 0x03, 0xd7, 0x03, 0x7a, 0x8b,
    0x13, 0x5c, 0x42, 0x49, 0xc2, 0xab, 0x86, 0xd6, 0xac, 0x6b, 0x93, 0x20,
    0x56, 0x6a, 0xc6, 0xc8, 0xa5, 0x0b, 0xe5
};

/*
 * kExampleBadECPubKeyDER is a sample EC public key with a wrong OID
 * 1.2.840.10045.2.2 instead of 1.2.840.10045.2.1 - EC Public Key
 */
static const unsigned char kExampleBadECPubKeyDER[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x02, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xba, 0xeb, 0x83, 0xfb, 0x3b, 0xb2, 0xff, 0x30, 0x53,
    0xdb, 0xce, 0x32, 0xf2, 0xac, 0xae, 0x44, 0x0d, 0x3d, 0x13, 0x53, 0xb8,
    0xd1, 0x68, 0x55, 0xde, 0x44, 0x46, 0x05, 0xa6, 0xc9, 0xd2, 0x04, 0xb7,
    0xe3, 0xa2, 0x96, 0xc8, 0xb2, 0x5e, 0x22, 0x03, 0xd7, 0x03, 0x7a, 0x8b,
    0x13, 0x5c, 0x42, 0x49, 0xc2, 0xab, 0x86, 0xd6, 0xac, 0x6b, 0x93, 0x20,
    0x56, 0x6a, 0xc6, 0xc8, 0xa5, 0x0b, 0xe5
};

static const unsigned char pExampleECParamDER[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

# ifndef OPENSSL_NO_ECX
static const unsigned char kExampleED25519KeyDER[] = {
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20, 0xba, 0x7b, 0xba, 0x20, 0x1b, 0x02, 0x75, 0x3a,
    0xe8, 0x88, 0xfe, 0x00, 0xcd, 0x8b, 0xc6, 0xf4, 0x5c, 0x47, 0x09, 0x46,
    0x66, 0xe4, 0x72, 0x85, 0x25, 0x26, 0x5e, 0x12, 0x33, 0x48, 0xf6, 0x50
};

static const unsigned char kExampleED25519PubKeyDER[] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    0xf5, 0xc5, 0xeb, 0x52, 0x3e, 0x7d, 0x07, 0x86, 0xb2, 0x55, 0x07, 0x45,
    0xef, 0x5b, 0x7c, 0x20, 0xe8, 0x66, 0x28, 0x30, 0x3c, 0x8a, 0x82, 0x40,
    0x97, 0xa3, 0x08, 0xdc, 0x65, 0x80, 0x39, 0x29
};

# ifndef OPENSSL_NO_DEPRECATED_3_0
static const unsigned char kExampleX25519KeyDER[] = {
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
    0x04, 0x22, 0x04, 0x20, 0xa0, 0x24, 0x3a, 0x31, 0x24, 0xc3, 0x3f, 0xf6,
    0x7b, 0x96, 0x0b, 0xd4, 0x8f, 0xd1, 0xee, 0x67, 0xf2, 0x9b, 0x88, 0xac,
    0x50, 0xce, 0x97, 0x36, 0xdd, 0xaf, 0x25, 0xf6, 0x10, 0x34, 0x96, 0x6e
};
#  endif
# endif
#endif

/* kExampleDHKeyDER is a DH private key in ASN.1, DER format. */
#ifndef OPENSSL_NO_DEPRECATED_3_0
# ifndef OPENSSL_NO_DH
static const unsigned char kExampleDHKeyDER[] = {
    0x30, 0x82, 0x01, 0x21, 0x02, 0x01, 0x00, 0x30, 0x81, 0x95, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01, 0x30, 0x81, 0x87,
    0x02, 0x81, 0x81, 0x00, 0xf7, 0x52, 0xc2, 0x68, 0xcc, 0x66, 0xc4, 0x8d,
    0x03, 0x3f, 0xfa, 0x9c, 0x52, 0xd0, 0xd8, 0x33, 0xf2, 0xe1, 0xc9, 0x9e,
    0xb7, 0xe7, 0x6e, 0x90, 0x97, 0xeb, 0x92, 0x91, 0x6a, 0x9a, 0x85, 0x63,
    0x92, 0x79, 0xab, 0xb6, 0x3d, 0x23, 0x58, 0x5a, 0xe8, 0x45, 0x06, 0x81,
    0x97, 0x77, 0xe1, 0xcc, 0x34, 0x4e, 0xae, 0x36, 0x80, 0xf2, 0xc4, 0x7f,
    0x8a, 0x52, 0xb8, 0xdb, 0x58, 0xc8, 0x4b, 0x12, 0x4c, 0xf1, 0x4c, 0x53,
    0xc1, 0x89, 0x39, 0x8d, 0xb6, 0x06, 0xd8, 0xea, 0x7f, 0x2d, 0x36, 0x53,
    0x96, 0x29, 0xbe, 0xb6, 0x75, 0xfc, 0xe7, 0xf3, 0x36, 0xd6, 0xf4, 0x8f,
    0x16, 0xa6, 0xc7, 0xec, 0x7b, 0xce, 0x42, 0x8d, 0x48, 0x2e, 0xb7, 0x74,
    0x00, 0x11, 0x52, 0x61, 0xb4, 0x19, 0x35, 0xec, 0x5c, 0xe4, 0xbe, 0x34,
    0xc6, 0x59, 0x64, 0x5e, 0x42, 0x61, 0x70, 0x54, 0xf4, 0xe9, 0x6b, 0x53,
    0x02, 0x01, 0x02, 0x04, 0x81, 0x83, 0x02, 0x81, 0x80, 0x64, 0xc2, 0xe3,
    0x09, 0x69, 0x37, 0x3c, 0xd2, 0x4a, 0xba, 0xc3, 0x78, 0x6a, 0x9b, 0x8a,
    0x2a, 0xdb, 0xe7, 0xe6, 0xc0, 0xfa, 0x3a, 0xbe, 0x39, 0x67, 0xc0, 0xa9,
    0x2a, 0xf0, 0x0a, 0xc1, 0x53, 0x1c, 0xdb, 0xfa, 0x1a, 0x26, 0x98, 0xb0,
    0x8c, 0xc6, 0x06, 0x4a, 0xa2, 0x48, 0xd3, 0xa4, 0x3b, 0xbd, 0x05, 0x48,
    0xea, 0x59, 0xdb, 0x18, 0xa4, 0xca, 0x66, 0xd9, 0x5d, 0xb8, 0x95, 0xd1,
    0xeb, 0x97, 0x3d, 0x66, 0x97, 0x5c, 0x86, 0x8f, 0x7e, 0x90, 0xd3, 0x43,
    0xd1, 0xa2, 0x0d, 0xcb, 0xe7, 0xeb, 0x90, 0xea, 0x09, 0x40, 0xb1, 0x6f,
    0xf7, 0x4c, 0xf2, 0x41, 0x83, 0x1d, 0xd0, 0x76, 0xef, 0xaf, 0x55, 0x6f,
    0x5d, 0xa9, 0xa3, 0x55, 0x81, 0x2a, 0xd1, 0x5d, 0x9d, 0x22, 0x77, 0x97,
    0x83, 0xde, 0xad, 0xb6, 0x5d, 0x19, 0xc1, 0x53, 0xec, 0xfb, 0xaf, 0x06,
    0x2e, 0x87, 0x2a, 0x0b, 0x7a
};
# endif
#endif

static const unsigned char kCFBDefaultKey[] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88,
    0x09, 0xCF, 0x4F, 0x3C
};

static const unsigned char kGCMDefaultKey[32] = { 0 };

static const unsigned char kGCMResetKey[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
    0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

static const unsigned char iCFBIV[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
};

static const unsigned char iGCMDefaultIV[12] = { 0 };

static const unsigned char iGCMResetIV1[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad
};

static const unsigned char iGCMResetIV2[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
};

static const unsigned char cfbPlaintext[] = {
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11,
    0x73, 0x93, 0x17, 0x2A
};
static const unsigned char cfbPlaintext_partial[] = {
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11,
    0x73, 0x93, 0x17, 0x2A, 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
};

static const unsigned char gcmDefaultPlaintext[16] = { 0 };

static const unsigned char gcmResetPlaintext[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
    0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
    0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
};

static const unsigned char cfbCiphertext[] = {
    0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8,
    0xE8, 0x3C, 0xFB, 0x4A
};

static const unsigned char cfbCiphertext_partial[] = {
    0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8,
    0xE8, 0x3C, 0xFB, 0x4A, 0x0D, 0x4A, 0x71, 0x82, 0x90, 0xF0, 0x9A, 0x35
};

static const unsigned char ofbCiphertext_partial[] = {
    0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8,
    0xE8, 0x3C, 0xFB, 0x4A, 0xB2, 0x65, 0x64, 0x38, 0x26, 0xD2, 0xBC, 0x09
};

static const unsigned char gcmDefaultCiphertext[] = {
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3,
    0xba, 0xf3, 0x9d, 0x18
};

static const unsigned char gcmResetCiphertext1[] = {
    0xc3, 0x76, 0x2d, 0xf1, 0xca, 0x78, 0x7d, 0x32, 0xae, 0x47, 0xc1, 0x3b,
    0xf1, 0x98, 0x44, 0xcb, 0xaf, 0x1a, 0xe1, 0x4d, 0x0b, 0x97, 0x6a, 0xfa,
    0xc5, 0x2f, 0xf7, 0xd7, 0x9b, 0xba, 0x9d, 0xe0, 0xfe, 0xb5, 0x82, 0xd3,
    0x39, 0x34, 0xa4, 0xf0, 0x95, 0x4c, 0xc2, 0x36, 0x3b, 0xc7, 0x3f, 0x78,
    0x62, 0xac, 0x43, 0x0e, 0x64, 0xab, 0xe4, 0x99, 0xf4, 0x7c, 0x9b, 0x1f
};

static const unsigned char gcmResetCiphertext2[] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3,
    0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48,
    0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62
};

static const unsigned char gcmAAD[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
    0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2
};

static const unsigned char gcmDefaultTag[] = {
    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
    0xd4, 0x8a, 0xb9, 0x19
};

static const unsigned char gcmResetTag1[] = {
    0x3a, 0x33, 0x7d, 0xbf, 0x46, 0xa7, 0x92, 0xc4, 0x5e, 0x45, 0x49, 0x13,
    0xfe, 0x2e, 0xa8, 0xf2
};

static const unsigned char gcmResetTag2[] = {
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53,
    0xbb, 0x2d, 0x55, 0x1b
};

typedef struct APK_DATA_st {
    const unsigned char *kder;
    size_t size;
    const char *keytype;
    int evptype;
    int check;
    int pub_check;
    int param_check;
    int type; /* 0 for private, 1 for public, 2 for params */
} APK_DATA;

static APK_DATA keydata[] = {
    {kExampleRSAKeyDER, sizeof(kExampleRSAKeyDER), "RSA", EVP_PKEY_RSA},
    {kExampleRSAKeyPKCS8, sizeof(kExampleRSAKeyPKCS8), "RSA", EVP_PKEY_RSA},
#ifndef OPENSSL_NO_EC
    {kExampleECKeyDER, sizeof(kExampleECKeyDER), "EC", EVP_PKEY_EC}
#endif
};

static APK_DATA keycheckdata[] = {
    {kExampleRSAKeyDER, sizeof(kExampleRSAKeyDER), "RSA", EVP_PKEY_RSA, 1, 1, 1,
     0},
    {kExampleBadRSAKeyDER, sizeof(kExampleBadRSAKeyDER), "RSA", EVP_PKEY_RSA,
     0, 1, 1, 0},
    {kExampleBad2RSAKeyDER, sizeof(kExampleBad2RSAKeyDER), "RSA", EVP_PKEY_RSA,
     0, 0, 1 /* Since there are no "params" in an RSA key this passes */, 0},
#ifndef OPENSSL_NO_EC
    {kExampleECKeyDER, sizeof(kExampleECKeyDER), "EC", EVP_PKEY_EC, 1, 1, 1, 0},
    /* group is also associated in our pub key */
    {kExampleECPubKeyDER, sizeof(kExampleECPubKeyDER), "EC", EVP_PKEY_EC, 0, 1,
     1, 1},
    {pExampleECParamDER, sizeof(pExampleECParamDER), "EC", EVP_PKEY_EC, 0, 0, 1,
     2},
# ifndef OPENSSL_NO_ECX
    {kExampleED25519KeyDER, sizeof(kExampleED25519KeyDER), "ED25519",
     EVP_PKEY_ED25519, 1, 1, 1, 0},
    {kExampleED25519PubKeyDER, sizeof(kExampleED25519PubKeyDER), "ED25519",
     EVP_PKEY_ED25519, 0, 1, 1, 1},
# endif
#endif
};

static EVP_PKEY *load_example_key(const char *keytype,
                                  const unsigned char *data, size_t data_len)
{
    const unsigned char **pdata = &data;
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx =
        OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, keytype, 0,
                                      testctx, testpropq);

    /* |pkey| will be NULL on error */
    (void)OSSL_DECODER_from_data(dctx, pdata, &data_len);
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

static EVP_PKEY *load_example_rsa_key(void)
{
    return load_example_key("RSA", kExampleRSAKeyDER,
                            sizeof(kExampleRSAKeyDER));
}

#ifndef OPENSSL_NO_DSA
static EVP_PKEY *load_example_dsa_key(void)
{
    return load_example_key("DSA", kExampleDSAKeyDER,
                            sizeof(kExampleDSAKeyDER));
}
#endif

#ifndef OPENSSL_NO_EC
static EVP_PKEY *load_example_ec_key(void)
{
    return load_example_key("EC", kExampleECKeyDER,
                            sizeof(kExampleECKeyDER));
}
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
# ifndef OPENSSL_NO_DH
static EVP_PKEY *load_example_dh_key(void)
{
    return load_example_key("DH", kExampleDHKeyDER,
                            sizeof(kExampleDHKeyDER));
}
# endif

# ifndef OPENSSL_NO_ECX
static EVP_PKEY *load_example_ed25519_key(void)
{
    return load_example_key("ED25519", kExampleED25519KeyDER,
                            sizeof(kExampleED25519KeyDER));
}

static EVP_PKEY *load_example_x25519_key(void)
{
    return load_example_key("X25519", kExampleX25519KeyDER,
                            sizeof(kExampleX25519KeyDER));
}
# endif
#endif /* OPENSSL_NO_DEPRECATED_3_0 */

static EVP_PKEY *load_example_hmac_key(void)
{
    EVP_PKEY *pkey = NULL;
    unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    pkey = EVP_PKEY_new_raw_private_key_ex(testctx, "HMAC",
                                           NULL, key, sizeof(key));
    if (!TEST_ptr(pkey))
        return NULL;

    return pkey;
}

static int test_EVP_set_default_properties(void)
{
    OSSL_LIB_CTX *ctx;
    EVP_MD *md = NULL;
    int res = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new())
            || !TEST_ptr(md = EVP_MD_fetch(ctx, "sha256", NULL)))
        goto err;
    EVP_MD_free(md);
    md = NULL;

    if (!TEST_true(EVP_set_default_properties(ctx, "provider=fizzbang"))
            || !TEST_ptr_null(md = EVP_MD_fetch(ctx, "sha256", NULL))
            || !TEST_ptr(md = EVP_MD_fetch(ctx, "sha256", "-provider")))
        goto err;
    EVP_MD_free(md);
    md = NULL;

    if (!TEST_true(EVP_set_default_properties(ctx, NULL))
            || !TEST_ptr(md = EVP_MD_fetch(ctx, "sha256", NULL)))
        goto err;
    res = 1;
err:
    EVP_MD_free(md);
    OSSL_LIB_CTX_free(ctx);
    return res;
}

#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_EC)
static EVP_PKEY *make_key_fromdata(char *keytype, OSSL_PARAM *params)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *tmp_pkey = NULL, *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, keytype, testpropq)))
        goto err;
    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &tmp_pkey, EVP_PKEY_KEYPAIR,
                                          params), 0))
        goto err;

    if (!TEST_ptr(tmp_pkey))
        goto err;

    pkey = tmp_pkey;
    tmp_pkey = NULL;
 err:
    EVP_PKEY_free(tmp_pkey);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static int test_selection(EVP_PKEY *pkey, int selection)
{
    int testresult = 0;
    int ret;
    BIO *bio = BIO_new(BIO_s_mem());

    ret = PEM_write_bio_PUBKEY(bio, pkey);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!TEST_true(ret))
            goto err;
    } else {
        if (!TEST_false(ret))
            goto err;
    }
    ret = PEM_write_bio_PrivateKey_ex(bio, pkey, NULL, NULL, 0, NULL, NULL,
                                      testctx, NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!TEST_true(ret))
            goto err;
    } else {
        if (!TEST_false(ret))
            goto err;
    }

    testresult = 1;
 err:
    BIO_free(bio);

    return testresult;
}
#endif /* !OPENSSL_NO_DH || !OPENSSL_NO_DSA || !OPENSSL_NO_EC */

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted
 */
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_DSA)
static int test_EVP_PKEY_ffc_priv_pub(char *keytype)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *just_params = NULL;
    EVP_PKEY *params_and_priv = NULL;
    EVP_PKEY *params_and_pub = NULL;
    EVP_PKEY *params_and_keypair = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our pkey object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    /* Test !priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(just_params = make_key_fromdata(keytype, params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(just_params, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        || test_selection(just_params, OSSL_KEYMGMT_SELECT_KEYPAIR))
        goto err;

    /* Test priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(params_and_priv = make_key_fromdata(keytype, params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(params_and_priv, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        || test_selection(params_and_priv, OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        goto err;

    /* Test !priv and pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                             pub)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(params_and_pub = make_key_fromdata(keytype, params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(params_and_pub, OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        || test_selection(params_and_pub, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        goto err;

    /* Test priv and pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                             pub))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(params_and_keypair = make_key_fromdata(keytype, params)))
        goto err;

    if (!test_selection(params_and_keypair, EVP_PKEY_KEYPAIR))
        goto err;

    ret = 1;
 err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(just_params);
    EVP_PKEY_free(params_and_priv);
    EVP_PKEY_free(params_and_pub);
    EVP_PKEY_free(params_and_keypair);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}
#endif /* !OPENSSL_NO_DH || !OPENSSL_NO_DSA */

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted for EC keys
 */
#ifndef OPENSSL_NO_EC
static unsigned char ec_priv[] = {
    0xe9, 0x25, 0xf7, 0x66, 0x58, 0xa4, 0xdd, 0x99, 0x61, 0xe7, 0xe8, 0x23,
    0x85, 0xc2, 0xe8, 0x33, 0x27, 0xc5, 0x5c, 0xeb, 0xdb, 0x43, 0x9f, 0xd5,
    0xf2, 0x5a, 0x75, 0x55, 0xd0, 0x2e, 0x6d, 0x16
};
static unsigned char ec_pub[] = {
    0x04, 0xad, 0x11, 0x90, 0x77, 0x4b, 0x46, 0xee, 0x72, 0x51, 0x15, 0x97,
    0x4a, 0x6a, 0xa7, 0xaf, 0x59, 0xfa, 0x4b, 0xf2, 0x41, 0xc8, 0x3a, 0x81,
    0x23, 0xb6, 0x90, 0x04, 0x6c, 0x67, 0x66, 0xd0, 0xdc, 0xf2, 0x15, 0x1d,
    0x41, 0x61, 0xb7, 0x95, 0x85, 0x38, 0x5a, 0x84, 0x56, 0xe8, 0xb3, 0x0e,
    0xf5, 0xc6, 0x5d, 0xa4, 0x54, 0x26, 0xb0, 0xf7, 0xa5, 0x4a, 0x33, 0xf1,
    0x08, 0x09, 0xb8, 0xdb, 0x03
};

static int test_EC_priv_pub(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *just_params = NULL;
    EVP_PKEY *params_and_priv = NULL;
    EVP_PKEY *params_and_pub = NULL;
    EVP_PKEY *params_and_keypair = NULL;
    BIGNUM *priv = NULL;
    int ret = 0;
    unsigned char *encoded = NULL;
    size_t len = 0;
    unsigned char buffer[128];

    /*
     * Setup the parameters for our pkey object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(priv = BN_bin2bn(ec_priv, sizeof(ec_priv), NULL)))
        goto err;

    /* Test !priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_utf8_string(bld,
                                                      OSSL_PKEY_PARAM_GROUP_NAME,
                                                      "P-256", 0)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(just_params = make_key_fromdata("EC", params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(just_params, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        || test_selection(just_params, OSSL_KEYMGMT_SELECT_KEYPAIR))
        goto err;

    /* Test priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_utf8_string(bld,
                                                      OSSL_PKEY_PARAM_GROUP_NAME,
                                                      "P-256", 0))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(params_and_priv = make_key_fromdata("EC", params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    /*
     * We indicate only parameters here, in spite of having built a key that
     * has a private part, because the PEM_write_bio_PrivateKey_ex call is
     * expected to fail because it does not support exporting a private EC
     * key without a corresponding public key
     */
    if (!test_selection(params_and_priv, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        || test_selection(params_and_priv, OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        goto err;

    /* Test !priv and pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_utf8_string(bld,
                                                      OSSL_PKEY_PARAM_GROUP_NAME,
                                                      "P-256", 0))
        || !TEST_true(OSSL_PARAM_BLD_push_octet_string(bld,
                                                       OSSL_PKEY_PARAM_PUB_KEY,
                                                       ec_pub, sizeof(ec_pub))))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(params_and_pub = make_key_fromdata("EC", params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(params_and_pub, OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        || test_selection(params_and_pub, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        goto err;

    /* Test priv and pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_utf8_string(bld,
                                                      OSSL_PKEY_PARAM_GROUP_NAME,
                                                      "P-256", 0))
        || !TEST_true(OSSL_PARAM_BLD_push_octet_string(bld,
                                                       OSSL_PKEY_PARAM_PUB_KEY,
                                                       ec_pub, sizeof(ec_pub)))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(params_and_keypair = make_key_fromdata("EC", params)))
        goto err;

    if (!test_selection(params_and_keypair, EVP_PKEY_KEYPAIR))
        goto err;

    /* Try key equality */
    if (!TEST_int_gt(EVP_PKEY_parameters_eq(just_params, just_params), 0)
        || !TEST_int_gt(EVP_PKEY_parameters_eq(just_params, params_and_pub),
                        0)
        || !TEST_int_gt(EVP_PKEY_parameters_eq(just_params, params_and_priv),
                        0)
        || !TEST_int_gt(EVP_PKEY_parameters_eq(just_params, params_and_keypair),
                        0)
        || !TEST_int_gt(EVP_PKEY_eq(params_and_pub, params_and_pub), 0)
        || !TEST_int_gt(EVP_PKEY_eq(params_and_priv, params_and_priv), 0)
        || !TEST_int_gt(EVP_PKEY_eq(params_and_keypair, params_and_pub), 0)
        || !TEST_int_gt(EVP_PKEY_eq(params_and_keypair, params_and_priv), 0))
        goto err;

    /* Positive and negative testcase for EVP_PKEY_get1_encoded_public_key */
    if (!TEST_int_gt(EVP_PKEY_get1_encoded_public_key(params_and_pub, &encoded), 0))
        goto err;
    OPENSSL_free(encoded);
    encoded = NULL;
    if (!TEST_int_eq(EVP_PKEY_get1_encoded_public_key(just_params, &encoded), 0)) {
        OPENSSL_free(encoded);
        encoded = NULL;
        goto err;
    }

    /* Positive and negative testcase for EVP_PKEY_get_octet_string_param */
    if (!TEST_int_eq(EVP_PKEY_get_octet_string_param(params_and_pub,
                                                     OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                     buffer, sizeof(buffer), &len), 1)
        || !TEST_int_eq(len, 65))
        goto err;

    len = 0;
    if (!TEST_int_eq(EVP_PKEY_get_octet_string_param(params_and_pub,
                                                     OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                     NULL, 0, &len), 1)
        || !TEST_int_eq(len, 65))
        goto err;

    /* too-short buffer len*/
    if (!TEST_int_eq(EVP_PKEY_get_octet_string_param(params_and_pub,
                                                     OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                     buffer, 10, &len), 0))
        goto err;

    ret = 1;
 err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(just_params);
    EVP_PKEY_free(params_and_priv);
    EVP_PKEY_free(params_and_pub);
    EVP_PKEY_free(params_and_keypair);
    BN_free(priv);

    return ret;
}

/* Also test that we can read the EC PUB affine coordinates */
static int test_evp_get_ec_pub(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    unsigned char *pad = NULL;
    EVP_PKEY *keypair = NULL;
    BIGNUM *priv = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int ret = 0;

    if (!TEST_ptr(priv = BN_bin2bn(ec_priv, sizeof(ec_priv), NULL)))
        goto err;

    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_utf8_string(bld,
                                                      OSSL_PKEY_PARAM_GROUP_NAME,
                                                      "P-256", 0))
        || !TEST_true(OSSL_PARAM_BLD_push_octet_string(bld,
                                                       OSSL_PKEY_PARAM_PUB_KEY,
                                                       ec_pub, sizeof(ec_pub)))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             priv)))
        goto err;

    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(keypair = make_key_fromdata("EC", params)))
        goto err;

    if (!test_selection(keypair, EVP_PKEY_KEYPAIR))
        goto err;

    if (!EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_EC_PUB_X, &x)
        || !EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_EC_PUB_Y, &y))
        goto err;

    if (!TEST_ptr(pad = OPENSSL_zalloc(sizeof(ec_pub))))
        goto err;

    pad[0] = ec_pub[0];
    BN_bn2bin(x, &pad[1]);
    BN_bn2bin(y, &pad[33]);
    if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(keypair);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);
    return ret;
}

/* Test that using a legacy EC key with only a private key in it works */
# ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_EC_priv_only_legacy(void)
{
    BIGNUM *priv = NULL;
    int ret = 0;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL, *dup_pk = NULL;
    EVP_MD_CTX *ctx = NULL;

    /* Create the low level EC_KEY */
    if (!TEST_ptr(priv = BN_bin2bn(ec_priv, sizeof(ec_priv), NULL)))
        goto err;

    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!TEST_ptr(eckey))
        goto err;

    if (!TEST_true(EC_KEY_set_private_key(eckey, priv)))
        goto err;

    pkey = EVP_PKEY_new();
    if (!TEST_ptr(pkey))
        goto err;

    if (!TEST_true(EVP_PKEY_assign_EC_KEY(pkey, eckey)))
        goto err;
    eckey = NULL;

    for (;;) {
        ret = 0;
        ctx = EVP_MD_CTX_new();
        if (!TEST_ptr(ctx))
            goto err;

        /*
         * The EVP_DigestSignInit function should create the key on the
         * provider side which is sufficient for this test.
         */
        if (!TEST_true(EVP_DigestSignInit_ex(ctx, NULL, NULL, testctx,
                                             testpropq, pkey, NULL)))
            goto err;
        EVP_MD_CTX_free(ctx);
        ctx = NULL;

        if (dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pkey)))
            goto err;
        /* EVP_PKEY_eq() returns -2 with missing public keys */
        ret = TEST_int_eq(EVP_PKEY_eq(pkey, dup_pk), -2);
        EVP_PKEY_free(pkey);
        pkey = dup_pk;
        if (!ret)
            goto err;
    }
    ret = 1;

 err:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    BN_free(priv);

    return ret;
}

static int test_evp_get_ec_pub_legacy(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    unsigned char *pad = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *priv = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int ret = 0;

    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new()))
        goto err;

    /* Create the legacy key */
    if (!TEST_ptr(eckey = EC_KEY_new_by_curve_name_ex(libctx, NULL,
                                                      NID_X9_62_prime256v1)))
        goto err;

    if (!TEST_ptr(priv = BN_bin2bn(ec_priv, sizeof(ec_priv), NULL)))
        goto err;

    if (!TEST_true(EC_KEY_set_private_key(eckey, priv)))
        goto err;

    if (!TEST_ptr(x = BN_bin2bn(&ec_pub[1], 32, NULL)))
        goto err;

    if (!TEST_ptr(y = BN_bin2bn(&ec_pub[33], 32, NULL)))
        goto err;

    if (!TEST_true(EC_KEY_set_public_key_affine_coordinates(eckey, x, y)))
        goto err;

    if (!TEST_ptr(pkey = EVP_PKEY_new()))
        goto err;

    /* Transfer the legacy key */
    if (!TEST_true(EVP_PKEY_assign_EC_KEY(pkey, eckey)))
        goto err;
    eckey = NULL;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x))
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y)))
        goto err;

    if (!TEST_ptr(pad = OPENSSL_zalloc(sizeof(ec_pub))))
        goto err;

    pad[0] = ec_pub[0];
    BN_bn2bin(x, &pad[1]);
    BN_bn2bin(y, &pad[33]);

    if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);

    return ret;
}
# endif /* OPENSSL_NO_DEPRECATED_3_0 */
#endif /* OPENSSL_NO_EC */

static int test_EVP_PKEY_sign(int tst)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0, shortsig_len = 1;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char tbs[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13
    };

    if (tst == 0) {
        if (!TEST_ptr(pkey = load_example_rsa_key()))
            goto out;
    } else if (tst == 1) {
#ifndef OPENSSL_NO_DSA
        if (!TEST_ptr(pkey = load_example_dsa_key()))
            goto out;
#else
        ret = 1;
        goto out;
#endif
    } else {
#ifndef OPENSSL_NO_EC
        if (!TEST_ptr(pkey = load_example_ec_key()))
            goto out;
#else
        ret = 1;
        goto out;
#endif
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(testctx, pkey, NULL);
    if (!TEST_ptr(ctx)
            || !TEST_int_gt(EVP_PKEY_sign_init(ctx), 0)
            || !TEST_int_gt(EVP_PKEY_sign(ctx, NULL, &sig_len, tbs,
                                          sizeof(tbs)), 0))
        goto out;
    sig = OPENSSL_malloc(sig_len);
    if (!TEST_ptr(sig)
            /* Test sending a signature buffer that is too short is rejected */
            || !TEST_int_le(EVP_PKEY_sign(ctx, sig, &shortsig_len, tbs,
                                          sizeof(tbs)), 0)
            || !TEST_int_gt(EVP_PKEY_sign(ctx, sig, &sig_len, tbs, sizeof(tbs)),
                            0)
            /* Test the signature round-trips */
            || !TEST_int_gt(EVP_PKEY_verify_init(ctx), 0)
            || !TEST_int_gt(EVP_PKEY_verify(ctx, sig, sig_len, tbs, sizeof(tbs)),
                            0))
        goto out;

    ret = 1;
 out:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(sig);
    EVP_PKEY_free(pkey);
    return ret;
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_EVP_PKEY_sign_with_app_method(int tst)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    RSA_METHOD *rsa_meth = NULL;
#ifndef OPENSSL_NO_DSA
    DSA *dsa = NULL;
    DSA_METHOD *dsa_meth = NULL;
#endif
    unsigned char *sig = NULL;
    size_t sig_len = 0, shortsig_len = 1;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char tbs[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13
    };

    if (tst == 0) {
        if (!TEST_ptr(pkey = load_example_rsa_key()))
            goto out;
        if (!TEST_ptr(rsa_meth = RSA_meth_dup(RSA_get_default_method())))
            goto out;

        if (!TEST_ptr(rsa = EVP_PKEY_get1_RSA(pkey))
            || !TEST_int_gt(RSA_set_method(rsa, rsa_meth), 0)
            || !TEST_int_gt(EVP_PKEY_assign_RSA(pkey, rsa), 0))
            goto out;
        rsa = NULL; /* now owned by the pkey */
    } else {
#ifndef OPENSSL_NO_DSA
        if (!TEST_ptr(pkey = load_example_dsa_key()))
                goto out;
        if (!TEST_ptr(dsa_meth = DSA_meth_dup(DSA_get_default_method())))
            goto out;

        if (!TEST_ptr(dsa = EVP_PKEY_get1_DSA(pkey))
            || !TEST_int_gt(DSA_set_method(dsa, dsa_meth), 0)
            || !TEST_int_gt(EVP_PKEY_assign_DSA(pkey, dsa), 0))
            goto out;
        dsa = NULL; /* now owned by the pkey */
#else
        ret = 1;
        goto out;
#endif
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(testctx, pkey, NULL);
    if (!TEST_ptr(ctx)
            || !TEST_int_gt(EVP_PKEY_sign_init(ctx), 0)
            || !TEST_int_gt(EVP_PKEY_sign(ctx, NULL, &sig_len, tbs,
                                          sizeof(tbs)), 0))
        goto out;
    sig = OPENSSL_malloc(sig_len);
    if (!TEST_ptr(sig)
            /* Test sending a signature buffer that is too short is rejected */
            || !TEST_int_le(EVP_PKEY_sign(ctx, sig, &shortsig_len, tbs,
                                          sizeof(tbs)), 0)
            || !TEST_int_gt(EVP_PKEY_sign(ctx, sig, &sig_len, tbs, sizeof(tbs)),
                            0)
            /* Test the signature round-trips */
            || !TEST_int_gt(EVP_PKEY_verify_init(ctx), 0)
            || !TEST_int_gt(EVP_PKEY_verify(ctx, sig, sig_len, tbs, sizeof(tbs)),
                            0))
        goto out;

    ret = 1;
 out:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(sig);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    RSA_meth_free(rsa_meth);
#ifndef OPENSSL_NO_DSA
    DSA_free(dsa);
    DSA_meth_free(dsa_meth);
#endif
    return ret;
}
#endif /* !OPENSSL_NO_DEPRECATED_3_0 */

/*
 * n = 0 => test using legacy cipher
 * n = 1 => test using fetched cipher
 */
static int test_EVP_Enveloped(int n)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_PKEY *keypair = NULL;
    unsigned char *kek = NULL;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    static const unsigned char msg[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    int len, kek_len, ciphertext_len, plaintext_len;
    unsigned char ciphertext[32], plaintext[16];
    EVP_CIPHER *type = NULL;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (n == 0)
        type = (EVP_CIPHER *)EVP_aes_256_cbc();
    else if (!TEST_ptr(type = EVP_CIPHER_fetch(testctx, "AES-256-CBC",
                                               testpropq)))
        goto err;

    if (!TEST_ptr(keypair = load_example_rsa_key())
            || !TEST_ptr(kek = OPENSSL_zalloc(EVP_PKEY_get_size(keypair)))
            || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_true(EVP_SealInit(ctx, type, &kek, &kek_len, iv,
                                       &keypair, 1))
            || !TEST_true(EVP_SealUpdate(ctx, ciphertext, &ciphertext_len,
                                         msg, sizeof(msg)))
            || !TEST_true(EVP_SealFinal(ctx, ciphertext + ciphertext_len,
                                        &len)))
        goto err;

    ciphertext_len += len;

    if (!TEST_true(EVP_OpenInit(ctx, type, kek, kek_len, iv, keypair))
            || !TEST_true(EVP_OpenUpdate(ctx, plaintext, &plaintext_len,
                                         ciphertext, ciphertext_len))
            || !TEST_true(EVP_OpenFinal(ctx, plaintext + plaintext_len, &len)))
        goto err;

    plaintext_len += len;
    if (!TEST_mem_eq(msg, sizeof(msg), plaintext, plaintext_len))
        goto err;

    ret = 1;
err:
    if (n != 0)
        EVP_CIPHER_free(type);
    OPENSSL_free(kek);
    EVP_PKEY_free(keypair);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * Test 0: Standard calls to EVP_DigestSignInit/Update/Final (Implicit fetch digest, RSA)
 * Test 1: Standard calls to EVP_DigestSignInit/Update/Final (Implicit fetch digest, DSA)
 * Test 2: Standard calls to EVP_DigestSignInit/Update/Final (Implicit fetch digest, HMAC)
 * Test 3: Standard calls to EVP_DigestSignInit/Update/Final (Explicit fetch digest, RSA)
 * Test 4: Standard calls to EVP_DigestSignInit/Update/Final (Explicit fetch digest, DSA)
 * Test 5: Standard calls to EVP_DigestSignInit/Update/Final (Explicit fetch diegst, HMAC)
 * Test 6: Use an MD BIO to do the Update calls instead (RSA)
 * Test 7: Use an MD BIO to do the Update calls instead (DSA)
 * Test 8: Use an MD BIO to do the Update calls instead (HMAC)
 * Test 9: Use EVP_DigestSign (Implicit fetch digest, RSA, short sig)
 * Test 10: Use EVP_DigestSign (Implicit fetch digest, DSA, short sig)
 * Test 11: Use EVP_DigestSign (Implicit fetch digest, HMAC, short sig)
 * Test 12: Use EVP_DigestSign (Implicit fetch digest, RSA)
 * Test 13: Use EVP_DigestSign (Implicit fetch digest, DSA)
 * Test 14: Use EVP_DigestSign (Implicit fetch digest, HMAC)
 * Test 15-29: Same as above with reinitialization
 */
static int test_EVP_DigestSignInit(int tst)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *sig2 = NULL;
    size_t sig_len = 0, sig2_len = 0, shortsig_len = 1;
    EVP_MD_CTX *md_ctx = NULL, *md_ctx_verify = NULL;
    EVP_MD_CTX *a_md_ctx = NULL, *a_md_ctx_verify = NULL;
    BIO *mdbio = NULL, *membio = NULL;
    size_t written;
    const EVP_MD *md;
    EVP_MD *mdexp = NULL;
    int reinit = 0;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (tst >= 15) {
        reinit = 1;
        tst -= 15;
    }

    if (tst >= 6 && tst <= 8) {
        membio = BIO_new(BIO_s_mem());
        mdbio = BIO_new(BIO_f_md());
        if (!TEST_ptr(membio) || !TEST_ptr(mdbio))
            goto out;
        BIO_push(mdbio, membio);
        if (!TEST_int_gt(BIO_get_md_ctx(mdbio, &md_ctx), 0))
            goto out;
    } else {
        if (!TEST_ptr(a_md_ctx = md_ctx = EVP_MD_CTX_new())
                || !TEST_ptr(a_md_ctx_verify = md_ctx_verify = EVP_MD_CTX_new()))
            goto out;
    }

    if (tst % 3 == 0) {
        if (!TEST_ptr(pkey = load_example_rsa_key()))
                goto out;
    } else if (tst % 3 == 1) {
#ifndef OPENSSL_NO_DSA
        if (!TEST_ptr(pkey = load_example_dsa_key()))
                goto out;
#else
        ret = 1;
        goto out;
#endif
    } else {
        if (!TEST_ptr(pkey = load_example_hmac_key()))
                goto out;
    }

    if (tst >= 3 && tst <= 5)
        md = mdexp = EVP_MD_fetch(NULL, "SHA256", NULL);
    else
        md = EVP_sha256();

    if (!TEST_true(EVP_DigestSignInit(md_ctx, NULL, md, NULL, pkey)))
        goto out;

    if (reinit && !TEST_true(EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, NULL)))
        goto out;

    if (tst >= 6 && tst <= 8) {
        if (!BIO_write_ex(mdbio, kMsg, sizeof(kMsg), &written))
            goto out;
    } else if (tst < 6) {
        if (!TEST_true(EVP_DigestSignUpdate(md_ctx, kMsg, sizeof(kMsg))))
            goto out;
    }

    if (tst >= 9) {
        /* Determine the size of the signature. */
        if (!TEST_true(EVP_DigestSign(md_ctx, NULL, &sig_len, kMsg,
                                      sizeof(kMsg)))
                || !TEST_ptr(sig = OPENSSL_malloc(sig_len)))
            goto out;
        if (tst <= 11) {
            /* Test that supply a short sig buffer fails */
            if (!TEST_false(EVP_DigestSign(md_ctx, sig, &shortsig_len, kMsg,
                                           sizeof(kMsg))))
                goto out;
            /*
             * We end here because once EVP_DigestSign() has failed you should
             * not call it again without re-initing the ctx
             */
            ret = 1;
            goto out;
        }
        if (!TEST_true(EVP_DigestSign(md_ctx, sig, &sig_len, kMsg,
                                      sizeof(kMsg))))
            goto out;
    } else {
        /* Determine the size of the signature. */
        if (!TEST_true(EVP_DigestSignFinal(md_ctx, NULL, &sig_len))
                || !TEST_ptr(sig = OPENSSL_malloc(sig_len))
                /*
                    * Trying to create a signature with a deliberately short
                    * buffer should fail.
                    */
                || !TEST_false(EVP_DigestSignFinal(md_ctx, sig, &shortsig_len))
                || !TEST_true(EVP_DigestSignFinal(md_ctx, sig, &sig_len)))
            goto out;
    }

    /*
     * Ensure that the signature round-trips (Verification isn't supported for
     * HMAC via EVP_DigestVerify*)
     */
    if (tst % 3 != 2) {
        if (tst >= 6 && tst <= 8) {
            if (!TEST_int_gt(BIO_reset(mdbio), 0)
                || !TEST_int_gt(BIO_get_md_ctx(mdbio, &md_ctx_verify), 0))
                goto out;
        }

        if (!TEST_true(EVP_DigestVerifyInit(md_ctx_verify, NULL, md,
                                            NULL, pkey)))
            goto out;

        if (tst >= 6 && tst <= 8) {
            if (!TEST_true(BIO_write_ex(mdbio, kMsg, sizeof(kMsg), &written)))
                goto out;
        } else {
            if (!TEST_true(EVP_DigestVerifyUpdate(md_ctx_verify, kMsg,
                                                  sizeof(kMsg))))
                goto out;
        }
        if (!TEST_int_gt(EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len), 0))
            goto out;

        /* Multiple calls to EVP_DigestVerifyFinal should work */
        if (!TEST_int_gt(EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len), 0))
            goto out;
    } else {
        /*
         * For HMAC a doubled call to DigestSignFinal should produce the same
         * value as finalization should not happen.
         */
        if (!TEST_true(EVP_DigestSignFinal(md_ctx, NULL, &sig2_len))
            || !TEST_ptr(sig2 = OPENSSL_malloc(sig2_len))
            || !TEST_true(EVP_DigestSignFinal(md_ctx, sig2, &sig2_len)))
            goto out;

        if (!TEST_mem_eq(sig, sig_len, sig2, sig2_len))
            goto out;
    }

    ret = 1;

 out:
    BIO_free(membio);
    BIO_free(mdbio);
    EVP_MD_CTX_free(a_md_ctx);
    EVP_MD_CTX_free(a_md_ctx_verify);
    EVP_PKEY_free(pkey);
    OPENSSL_free(sig);
    OPENSSL_free(sig2);
    EVP_MD_free(mdexp);

    return ret;
}

static int test_EVP_DigestVerifyInit(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (!TEST_ptr(md_ctx = EVP_MD_CTX_new())
            || !TEST_ptr(pkey = load_example_rsa_key()))
        goto out;

    if (!TEST_true(EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey))
            || !TEST_true(EVP_DigestVerifyUpdate(md_ctx, kMsg, sizeof(kMsg)))
            || !TEST_int_gt(EVP_DigestVerifyFinal(md_ctx, kSignature,
                                                 sizeof(kSignature)), 0))
        goto out;

    /* test with reinitialization */
    if (!TEST_true(EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, NULL))
            || !TEST_true(EVP_DigestVerifyUpdate(md_ctx, kMsg, sizeof(kMsg)))
            || !TEST_int_gt(EVP_DigestVerifyFinal(md_ctx, kSignature,
                                                 sizeof(kSignature)), 0))
        goto out;
    ret = 1;

 out:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

#ifndef OPENSSL_NO_SIPHASH
/* test SIPHASH MAC via EVP_PKEY with non-default parameters and reinit */
static int test_siphash_digestsign(void)
{
    unsigned char key[16];
    unsigned char buf[8], digest[8];
    unsigned char expected[8] = {
        0x6d, 0x3e, 0x54, 0xc2, 0x2f, 0xf1, 0xfe, 0xe2
    };
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;
    size_t len = 8;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    memset(buf, 0, 8);
    memset(key, 1, 16);
    if (!TEST_ptr(pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_SIPHASH, NULL,
                                                      key, 16)))
        goto out;

    if (!TEST_ptr(mdctx = EVP_MD_CTX_create()))
        goto out;

    if (!TEST_true(EVP_DigestSignInit(mdctx, &ctx, NULL, NULL, pkey)))
        goto out;
    if (!TEST_int_eq(EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_SIGNCTX,
                                       EVP_PKEY_CTRL_SET_DIGEST_SIZE,
                                       8, NULL), 1))
        goto out;
    /* reinitialize */
    if (!TEST_true(EVP_DigestSignInit(mdctx, NULL, NULL, NULL, NULL)))
        goto out;
    if (!TEST_true(EVP_DigestSignUpdate(mdctx, buf, 8)))
        goto out;
    if (!TEST_true(EVP_DigestSignFinal(mdctx, digest, &len)))
        goto out;
    if (!TEST_mem_eq(digest, len, expected, sizeof(expected)))
        goto out;

    ret = 1;
 out:
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    return ret;
}
#endif

/*
 * Test corner cases of EVP_DigestInit/Update/Final API call behavior.
 */
static int test_EVP_Digest(void)
{
    int ret = 0;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    EVP_MD *sha256 = NULL;
    EVP_MD *shake256 = NULL;

    if (!TEST_ptr(md_ctx = EVP_MD_CTX_new()))
        goto out;

    if (!TEST_ptr(sha256 = EVP_MD_fetch(testctx, "sha256", testpropq))
            || !TEST_ptr(shake256 = EVP_MD_fetch(testctx, "shake256", testpropq)))
        goto out;

    if (!TEST_true(EVP_DigestInit_ex(md_ctx, sha256, NULL))
            || !TEST_true(EVP_DigestUpdate(md_ctx, kMsg, sizeof(kMsg)))
            || !TEST_true(EVP_DigestFinal(md_ctx, md, NULL))
            /* EVP_DigestFinal resets the EVP_MD_CTX. */
            || !TEST_ptr_eq(EVP_MD_CTX_get0_md(md_ctx), NULL))
        goto out;

    if (!TEST_true(EVP_DigestInit_ex(md_ctx, sha256, NULL))
            || !TEST_true(EVP_DigestUpdate(md_ctx, kMsg, sizeof(kMsg)))
            || !TEST_true(EVP_DigestFinal_ex(md_ctx, md, NULL))
            /* EVP_DigestFinal_ex does not reset the EVP_MD_CTX. */
            || !TEST_ptr(EVP_MD_CTX_get0_md(md_ctx))
            /*
             * EVP_DigestInit_ex with NULL type should work on
             * pre-initialized context.
             */
            || !TEST_true(EVP_DigestInit_ex(md_ctx, NULL, NULL)))
        goto out;

    if (!TEST_true(EVP_DigestInit_ex(md_ctx, shake256, NULL))
            || !TEST_true(EVP_DigestUpdate(md_ctx, kMsg, sizeof(kMsg)))
            || !TEST_true(EVP_DigestFinalXOF(md_ctx, md, sizeof(md)))
            /* EVP_DigestFinalXOF does not reset the EVP_MD_CTX. */
            || !TEST_ptr(EVP_MD_CTX_get0_md(md_ctx))
            || !TEST_true(EVP_DigestInit_ex(md_ctx, NULL, NULL)))
        goto out;
    ret = 1;

 out:
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_free(sha256);
    EVP_MD_free(shake256);
    return ret;
}

static int test_EVP_md_null(void)
{
    int ret = 0;
    EVP_MD_CTX *md_ctx = NULL;
    const EVP_MD *md_null = EVP_md_null();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = sizeof(md_value);

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (!TEST_ptr(md_null)
        || !TEST_ptr(md_ctx = EVP_MD_CTX_new()))
        goto out;

    if (!TEST_true(EVP_DigestInit_ex(md_ctx, md_null, NULL))
        || !TEST_true(EVP_DigestUpdate(md_ctx, "test", 4))
        || !TEST_true(EVP_DigestFinal_ex(md_ctx, md_value, &md_len)))
        goto out;

    if (!TEST_uint_eq(md_len, 0))
        goto out;

    ret = 1;
 out:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

static int test_d2i_AutoPrivateKey(int i)
{
    int ret = 0;
    const unsigned char *p;
    EVP_PKEY *pkey = NULL;
    const APK_DATA *ak = &keydata[i];
    const unsigned char *input = ak->kder;
    size_t input_len = ak->size;
    int expected_id = ak->evptype;

    p = input;
    if (!TEST_ptr(pkey = d2i_AutoPrivateKey(NULL, &p, input_len))
            || !TEST_ptr_eq(p, input + input_len)
            || !TEST_int_eq(EVP_PKEY_get_id(pkey), expected_id))
        goto done;

    ret = 1;

 done:
    EVP_PKEY_free(pkey);
    return ret;
}

#ifndef OPENSSL_NO_EC

static const unsigned char ec_public_sect163k1_validxy[] = {
    0x30, 0x40, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x01, 0x03, 0x2c, 0x00, 0x04,
    0x02, 0x84, 0x58, 0xa6, 0xd4, 0xa0, 0x35, 0x2b, 0xae, 0xf0, 0xc0, 0x69,
    0x05, 0xcf, 0x2a, 0x50, 0x33, 0xf9, 0xe3, 0x92, 0x79, 0x02, 0xd1, 0x7b,
    0x9f, 0x22, 0x00, 0xf0, 0x3b, 0x0e, 0x5d, 0x2e, 0xb7, 0x23, 0x24, 0xf3,
    0x6a, 0xd8, 0x17, 0x65, 0x41, 0x2f
};

static const unsigned char ec_public_sect163k1_badx[] = {
    0x30, 0x40, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x01, 0x03, 0x2c, 0x00, 0x04,
    0x0a, 0x84, 0x58, 0xa6, 0xd4, 0xa0, 0x35, 0x2b, 0xae, 0xf0, 0xc0, 0x69,
    0x05, 0xcf, 0x2a, 0x50, 0x33, 0xf9, 0xe3, 0x92, 0xb0, 0x02, 0xd1, 0x7b,
    0x9f, 0x22, 0x00, 0xf0, 0x3b, 0x0e, 0x5d, 0x2e, 0xb7, 0x23, 0x24, 0xf3,
    0x6a, 0xd8, 0x17, 0x65, 0x41, 0x2f
};

static const unsigned char ec_public_sect163k1_bady[] = {
    0x30, 0x40, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x01, 0x03, 0x2c, 0x00, 0x04,
    0x02, 0x84, 0x58, 0xa6, 0xd4, 0xa0, 0x35, 0x2b, 0xae, 0xf0, 0xc0, 0x69,
    0x05, 0xcf, 0x2a, 0x50, 0x33, 0xf9, 0xe3, 0x92, 0x79, 0x0a, 0xd1, 0x7b,
    0x9f, 0x22, 0x00, 0xf0, 0x3b, 0x0e, 0x5d, 0x2e, 0xb7, 0x23, 0x24, 0xf3,
    0x6a, 0xd8, 0x17, 0x65, 0x41, 0xe6
};

static struct ec_der_pub_keys_st {
    const unsigned char *der;
    size_t len;
    int valid;
} ec_der_pub_keys[] = {
    { ec_public_sect163k1_validxy, sizeof(ec_public_sect163k1_validxy), 1 },
    { ec_public_sect163k1_badx, sizeof(ec_public_sect163k1_badx), 0 },
    { ec_public_sect163k1_bady, sizeof(ec_public_sect163k1_bady), 0 },
};

/*
 * Tests the range of the decoded EC char2 public point.
 * See ec_GF2m_simple_oct2point().
 */
static int test_invalide_ec_char2_pub_range_decode(int id)
{
    int ret = 0;
    EVP_PKEY *pkey;

    pkey = load_example_key("EC", ec_der_pub_keys[id].der,
                            ec_der_pub_keys[id].len);

    ret = (ec_der_pub_keys[id].valid && TEST_ptr(pkey))
          || TEST_ptr_null(pkey);
    EVP_PKEY_free(pkey);
    return ret;
}

/* Tests loading a bad key in PKCS8 format */
static int test_EVP_PKCS82PKEY(void)
{
    int ret = 0;
    const unsigned char *derp = kExampleBadECKeyDER;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    EVP_PKEY *pkey = NULL;

    if (!TEST_ptr(p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &derp,
                                              sizeof(kExampleBadECKeyDER))))
        goto done;

    if (!TEST_ptr_eq(derp,
                     kExampleBadECKeyDER + sizeof(kExampleBadECKeyDER)))
        goto done;

    if (!TEST_ptr_null(pkey = EVP_PKCS82PKEY(p8inf)))
        goto done;

    ret = 1;

 done:
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    EVP_PKEY_free(pkey);

    return ret;
}

#endif
static int test_EVP_PKCS82PKEY_wrong_tag(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkey2 = NULL;
    BIO *membio = NULL;
    char *membuf = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    int ok = 0;

    if (testctx != NULL)
        /* test not supported with non-default context */
        return 1;

    if (!TEST_ptr(membio = BIO_new(BIO_s_mem()))
        || !TEST_ptr(pkey = load_example_rsa_key())
        || !TEST_int_gt(i2d_PKCS8PrivateKey_bio(membio, pkey, NULL,
                                                NULL, 0, NULL, NULL),
                        0)
        || !TEST_int_gt(BIO_get_mem_data(membio, &membuf), 0)
        || !TEST_ptr(p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(membio, NULL))
        || !TEST_ptr(pkey2 = EVP_PKCS82PKEY(p8inf))
        || !TEST_int_eq(ERR_peek_last_error(), 0)) {
        goto done;
    }

    ok = 1;
 done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey2);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    BIO_free_all(membio);
    return ok;
}

/* This uses kExampleRSAKeyDER and kExampleRSAKeyPKCS8 to verify encoding */
static int test_privatekey_to_pkcs8(void)
{
    EVP_PKEY *pkey = NULL;
    BIO *membio = NULL;
    char *membuf = NULL;
    long membuf_len = 0;
    int ok = 0;

    if (!TEST_ptr(membio = BIO_new(BIO_s_mem()))
        || !TEST_ptr(pkey = load_example_rsa_key())
        || !TEST_int_gt(i2d_PKCS8PrivateKey_bio(membio, pkey, NULL,
                                                NULL, 0, NULL, NULL),
                        0)
        || !TEST_int_gt(membuf_len = BIO_get_mem_data(membio, &membuf), 0)
        || !TEST_ptr(membuf)
        || !TEST_mem_eq(membuf, (size_t)membuf_len,
                        kExampleRSAKeyPKCS8, sizeof(kExampleRSAKeyPKCS8))
        /*
         * We try to write PEM as well, just to see that it doesn't err, but
         * assume that the result is correct.
         */
        || !TEST_int_gt(PEM_write_bio_PKCS8PrivateKey(membio, pkey, NULL,
                                                      NULL, 0, NULL, NULL),
                        0))
        goto done;

    ok = 1;
 done:
    EVP_PKEY_free(pkey);
    BIO_free_all(membio);
    return ok;
}

#ifndef OPENSSL_NO_EC
static const struct {
    int encoding;
    const char *encoding_name;
} ec_encodings[] = {
    { OPENSSL_EC_EXPLICIT_CURVE, OSSL_PKEY_EC_ENCODING_EXPLICIT },
    { OPENSSL_EC_NAMED_CURVE,    OSSL_PKEY_EC_ENCODING_GROUP }
};

static int ec_export_get_encoding_cb(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p;
    const char *enc_name = NULL;
    int *enc = arg;
    size_t i;

    *enc = -1;

    if (!TEST_ptr(p = OSSL_PARAM_locate_const(params,
                                              OSSL_PKEY_PARAM_EC_ENCODING))
        || !TEST_true(OSSL_PARAM_get_utf8_string_ptr(p, &enc_name)))
        return 0;

    for (i = 0; i < OSSL_NELEM(ec_encodings); i++) {
        if (OPENSSL_strcasecmp(enc_name, ec_encodings[i].encoding_name) == 0) {
            *enc = ec_encodings[i].encoding;
            break;
        }
    }

    return (*enc != -1);
}

static int test_EC_keygen_with_enc(int idx)
{
    EVP_PKEY *params = NULL, *key = NULL;
    EVP_PKEY_CTX *pctx = NULL, *kctx = NULL;
    int enc;
    int ret = 0;

    enc = ec_encodings[idx].encoding;

    /* Create key parameters */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "EC", NULL))
        || !TEST_int_gt(EVP_PKEY_paramgen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_group_name(pctx, "P-256"), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_param_enc(pctx, enc), 0)
        || !TEST_true(EVP_PKEY_paramgen(pctx, &params))
        || !TEST_ptr(params))
        goto done;

    /* Create key */
    if (!TEST_ptr(kctx = EVP_PKEY_CTX_new_from_pkey(testctx, params, NULL))
        || !TEST_int_gt(EVP_PKEY_keygen_init(kctx), 0)
        || !TEST_true(EVP_PKEY_keygen(kctx, &key))
        || !TEST_ptr(key))
        goto done;

    /* Check that the encoding got all the way into the key */
    if (!TEST_true(evp_keymgmt_util_export(key, OSSL_KEYMGMT_SELECT_ALL,
                                           ec_export_get_encoding_cb, &enc))
        || !TEST_int_eq(enc, ec_encodings[idx].encoding))
        goto done;

    ret = 1;
 done:
    EVP_PKEY_free(key);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}
#endif

#if !defined(OPENSSL_NO_SM2)

static int test_EVP_SM2_verify(void)
{
    const char *pubkey =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEp1KLWq1ZE2jmoAnnBJE1LBGxVr18\n"
        "YvvqECWCpXfAQ9qUJ+UmthnUPf0iM3SaXKHe6PlLIDyNlWMWb9RUh/yU3g==\n"
        "-----END PUBLIC KEY-----\n";

    const char *msg = "message digest";
    const char *id = "ALICE123@YAHOO.COM";

    const uint8_t signature[] = {
        0x30, 0x44, 0x02, 0x20, 0x5b, 0xdb, 0xab, 0x81, 0x4f, 0xbb,
        0x8b, 0x69, 0xb1, 0x05, 0x9c, 0x99, 0x3b, 0xb2, 0x45, 0x06,
        0x4a, 0x30, 0x15, 0x59, 0x84, 0xcd, 0xee, 0x30, 0x60, 0x36,
        0x57, 0x87, 0xef, 0x5c, 0xd0, 0xbe, 0x02, 0x20, 0x43, 0x8d,
        0x1f, 0xc7, 0x77, 0x72, 0x39, 0xbb, 0x72, 0xe1, 0xfd, 0x07,
        0x58, 0xd5, 0x82, 0xc8, 0x2d, 0xba, 0x3b, 0x2c, 0x46, 0x24,
        0xe3, 0x50, 0xff, 0x04, 0xc7, 0xa0, 0x71, 0x9f, 0xa4, 0x70
    };

    int rc = 0;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD *sm3 = NULL;

    bio = BIO_new_mem_buf(pubkey, strlen(pubkey));
    if (!TEST_true(bio != NULL))
        goto done;

    pkey = PEM_read_bio_PUBKEY_ex(bio, NULL, NULL, NULL, testctx, testpropq);
    if (!TEST_true(pkey != NULL))
        goto done;

    if (!TEST_true(EVP_PKEY_is_a(pkey, "SM2")))
        goto done;

    if (!TEST_ptr(mctx = EVP_MD_CTX_new()))
        goto done;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_pkey(testctx, pkey, testpropq)))
        goto done;

    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

    if (!TEST_ptr(sm3 = EVP_MD_fetch(testctx, "sm3", testpropq)))
        goto done;

    if (!TEST_true(EVP_DigestVerifyInit(mctx, NULL, sm3, NULL, pkey)))
        goto done;

    if (!TEST_int_gt(EVP_PKEY_CTX_set1_id(pctx, id, strlen(id)), 0))
        goto done;

    if (!TEST_true(EVP_DigestVerifyUpdate(mctx, msg, strlen(msg))))
        goto done;

    if (!TEST_int_gt(EVP_DigestVerifyFinal(mctx, signature, sizeof(signature)), 0))
        goto done;
    rc = 1;

 done:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(sm3);
    return rc;
}

static int test_EVP_SM2(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkeyparams = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *sctx = NULL;
    size_t sig_len = 0;
    unsigned char *sig = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_MD_CTX *md_ctx_verify = NULL;
    EVP_PKEY_CTX *cctx = NULL;
    EVP_MD *check_md = NULL;

    uint8_t ciphertext[128];
    size_t ctext_len = sizeof(ciphertext);

    uint8_t plaintext[8];
    size_t ptext_len = sizeof(plaintext);

    uint8_t sm2_id[] = {1, 2, 3, 4, 'l', 'e', 't', 't', 'e', 'r'};

    OSSL_PARAM sparams[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    OSSL_PARAM gparams[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    int i;
    char mdname[OSSL_MAX_NAME_SIZE];

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx,
                                                    "SM2", testpropq)))
        goto done;

    if (!TEST_true(EVP_PKEY_paramgen_init(pctx) == 1))
        goto done;

    if (!TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2), 0))
        goto done;

    if (!TEST_true(EVP_PKEY_paramgen(pctx, &pkeyparams)))
        goto done;

    if (!TEST_ptr(kctx = EVP_PKEY_CTX_new_from_pkey(testctx,
                                                    pkeyparams, testpropq)))
        goto done;

    if (!TEST_int_gt(EVP_PKEY_keygen_init(kctx), 0))
        goto done;

    if (!TEST_true(EVP_PKEY_keygen(kctx, &pkey)))
        goto done;

    if (!TEST_ptr(md_ctx = EVP_MD_CTX_new()))
        goto done;

    if (!TEST_ptr(md_ctx_verify = EVP_MD_CTX_new()))
        goto done;

    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(testctx, pkey, testpropq)))
        goto done;

    EVP_MD_CTX_set_pkey_ctx(md_ctx, sctx);
    EVP_MD_CTX_set_pkey_ctx(md_ctx_verify, sctx);

    if (!TEST_ptr(check_md = EVP_MD_fetch(testctx, "sm3", testpropq)))
        goto done;

    if (!TEST_true(EVP_DigestSignInit(md_ctx, NULL, check_md, NULL, pkey)))
        goto done;

    if (!TEST_int_gt(EVP_PKEY_CTX_set1_id(sctx, sm2_id, sizeof(sm2_id)), 0))
        goto done;

    if (!TEST_true(EVP_DigestSignUpdate(md_ctx, kMsg, sizeof(kMsg))))
        goto done;

    /* Determine the size of the signature. */
    if (!TEST_true(EVP_DigestSignFinal(md_ctx, NULL, &sig_len)))
        goto done;

    if (!TEST_ptr(sig = OPENSSL_malloc(sig_len)))
        goto done;

    if (!TEST_true(EVP_DigestSignFinal(md_ctx, sig, &sig_len)))
        goto done;

    /* Ensure that the signature round-trips. */

    if (!TEST_true(EVP_DigestVerifyInit(md_ctx_verify, NULL, check_md, NULL,
                                        pkey)))
        goto done;

    if (!TEST_int_gt(EVP_PKEY_CTX_set1_id(sctx, sm2_id, sizeof(sm2_id)), 0))
        goto done;

    if (!TEST_true(EVP_DigestVerifyUpdate(md_ctx_verify, kMsg, sizeof(kMsg))))
        goto done;

    if (!TEST_int_gt(EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len), 0))
        goto done;

    /*
     * Try verify again with non-matching 0 length id but ensure that it can
     * be set on the context and overrides the previous value.
     */

    if (!TEST_true(EVP_DigestVerifyInit(md_ctx_verify, NULL, check_md, NULL,
                                        pkey)))
        goto done;

    if (!TEST_int_gt(EVP_PKEY_CTX_set1_id(sctx, NULL, 0), 0))
        goto done;

    if (!TEST_true(EVP_DigestVerifyUpdate(md_ctx_verify, kMsg, sizeof(kMsg))))
        goto done;

    if (!TEST_int_eq(EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len), 0))
        goto done;

    /* now check encryption/decryption */

    gparams[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST,
                                                  mdname, sizeof(mdname));
    for (i = 0; i < 2; i++) {
        const char *mdnames[] = {
#ifndef OPENSSL_NO_SM3
            "SM3",
#else
            NULL,
#endif
            "SHA2-256" };
        EVP_PKEY_CTX_free(cctx);

        if (mdnames[i] == NULL)
            continue;

        sparams[0] =
            OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST,
                                             (char *)mdnames[i], 0);

        if (!TEST_ptr(cctx = EVP_PKEY_CTX_new_from_pkey(testctx,
                                                        pkey, testpropq)))
            goto done;

        if (!TEST_true(EVP_PKEY_encrypt_init(cctx)))
            goto done;

        if (!TEST_true(EVP_PKEY_CTX_set_params(cctx, sparams)))
            goto done;

        if (!TEST_true(EVP_PKEY_encrypt(cctx, ciphertext, &ctext_len, kMsg,
                                        sizeof(kMsg))))
            goto done;

        if (!TEST_int_gt(EVP_PKEY_decrypt_init(cctx), 0))
            goto done;

        if (!TEST_true(EVP_PKEY_CTX_set_params(cctx, sparams)))
            goto done;

        if (!TEST_int_gt(EVP_PKEY_decrypt(cctx, plaintext, &ptext_len, ciphertext,
                                        ctext_len), 0))
            goto done;

        if (!TEST_true(EVP_PKEY_CTX_get_params(cctx, gparams)))
            goto done;

        /*
         * Test we're still using the digest we think we are.
         * Because of aliases, the easiest is to fetch the digest and
         * check the name with EVP_MD_is_a().
         */
        EVP_MD_free(check_md);
        if (!TEST_ptr(check_md = EVP_MD_fetch(testctx, mdname, testpropq)))
            goto done;
        if (!TEST_true(EVP_MD_is_a(check_md, mdnames[i]))) {
            TEST_info("Fetched md %s isn't %s", mdname, mdnames[i]);
            goto done;
        }

        if (!TEST_true(ptext_len == sizeof(kMsg)))
            goto done;

        if (!TEST_true(memcmp(plaintext, kMsg, sizeof(kMsg)) == 0))
            goto done;
    }

    ret = 1;
done:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyparams);
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_CTX_free(md_ctx_verify);
    EVP_MD_free(check_md);
    OPENSSL_free(sig);
    return ret;
}

#endif

static struct keys_st {
    int type;
    char *priv;
    char *pub;
} keys[] = {
    {
        EVP_PKEY_HMAC, "0123456789", NULL
    },
    {
        EVP_PKEY_HMAC, "", NULL
#ifndef OPENSSL_NO_POLY1305
    }, {
        EVP_PKEY_POLY1305, "01234567890123456789012345678901", NULL
#endif
#ifndef OPENSSL_NO_SIPHASH
    }, {
        EVP_PKEY_SIPHASH, "0123456789012345", NULL
#endif
    },
#ifndef OPENSSL_NO_ECX
    {
        EVP_PKEY_X25519, "01234567890123456789012345678901",
        "abcdefghijklmnopqrstuvwxyzabcdef"
    }, {
        EVP_PKEY_ED25519, "01234567890123456789012345678901",
        "abcdefghijklmnopqrstuvwxyzabcdef"
    }, {
        EVP_PKEY_X448,
        "01234567890123456789012345678901234567890123456789012345",
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd"
    }, {
        EVP_PKEY_ED448,
        "012345678901234567890123456789012345678901234567890123456",
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde"
    }
#endif
};

static int test_set_get_raw_keys_int(int tst, int pub, int uselibctx)
{
    int ret = 0;
    unsigned char buf[80];
    unsigned char *in;
    size_t inlen, len = 0, shortlen = 1;
    EVP_PKEY *pkey;

    /* Check if this algorithm supports public keys */
    if (pub && keys[tst].pub == NULL)
        return 1;

    memset(buf, 0, sizeof(buf));

    if (pub) {
#ifndef OPENSSL_NO_EC
        inlen = strlen(keys[tst].pub);
        in = (unsigned char *)keys[tst].pub;
        if (uselibctx) {
            pkey = EVP_PKEY_new_raw_public_key_ex(
                        testctx,
                        OBJ_nid2sn(keys[tst].type),
                        NULL,
                        in,
                        inlen);
        } else {
            pkey = EVP_PKEY_new_raw_public_key(keys[tst].type,
                                               NULL,
                                               in,
                                               inlen);
        }
#else
        return 1;
#endif
    } else {
        inlen = strlen(keys[tst].priv);
        in = (unsigned char *)keys[tst].priv;
        if (uselibctx) {
            pkey = EVP_PKEY_new_raw_private_key_ex(
                        testctx, OBJ_nid2sn(keys[tst].type),
                        NULL,
                        in,
                        inlen);
        } else {
            pkey = EVP_PKEY_new_raw_private_key(keys[tst].type,
                                                NULL,
                                                in,
                                                inlen);
        }
    }

    if (!TEST_ptr(pkey)
            || !TEST_int_eq(EVP_PKEY_eq(pkey, pkey), 1)
            || (!pub && !TEST_true(EVP_PKEY_get_raw_private_key(pkey, NULL, &len)))
            || (pub && !TEST_true(EVP_PKEY_get_raw_public_key(pkey, NULL, &len)))
            || !TEST_true(len == inlen))
        goto done;
    if (tst != 1) {
        /*
         * Test that supplying a buffer that is too small fails. Doesn't apply
         * to HMAC with a zero length key
         */
        if ((!pub && !TEST_false(EVP_PKEY_get_raw_private_key(pkey, buf,
                                                                 &shortlen)))
                || (pub && !TEST_false(EVP_PKEY_get_raw_public_key(pkey, buf,
                                                                   &shortlen))))
            goto done;
    }
    if ((!pub && !TEST_true(EVP_PKEY_get_raw_private_key(pkey, buf, &len)))
            || (pub && !TEST_true(EVP_PKEY_get_raw_public_key(pkey, buf, &len)))
            || !TEST_mem_eq(in, inlen, buf, len))
        goto done;

    ret = 1;
 done:
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_set_get_raw_keys(int tst)
{
    return (nullprov != NULL || test_set_get_raw_keys_int(tst, 0, 0))
           && test_set_get_raw_keys_int(tst, 0, 1)
           && (nullprov != NULL || test_set_get_raw_keys_int(tst, 1, 0))
           && test_set_get_raw_keys_int(tst, 1, 1);
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
static int pkey_custom_check(EVP_PKEY *pkey)
{
    return 0xbeef;
}

static int pkey_custom_pub_check(EVP_PKEY *pkey)
{
    return 0xbeef;
}

static int pkey_custom_param_check(EVP_PKEY *pkey)
{
    return 0xbeef;
}

static EVP_PKEY_METHOD *custom_pmeth;
#endif

static int test_EVP_PKEY_check(int i)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    EVP_PKEY_CTX *ctx2 = NULL;
#endif
    const APK_DATA *ak = &keycheckdata[i];
    const unsigned char *input = ak->kder;
    size_t input_len = ak->size;
    int expected_id = ak->evptype;
    int expected_check = ak->check;
    int expected_pub_check = ak->pub_check;
    int expected_param_check = ak->param_check;
    int type = ak->type;

    if (!TEST_ptr(pkey = load_example_key(ak->keytype, input, input_len)))
        goto done;
    if (type == 0
        && !TEST_int_eq(EVP_PKEY_get_id(pkey), expected_id))
        goto done;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(testctx, pkey, testpropq)))
        goto done;

    if (!TEST_int_eq(EVP_PKEY_check(ctx), expected_check))
        goto done;

    if (!TEST_int_eq(EVP_PKEY_public_check(ctx), expected_pub_check))
        goto done;

    if (!TEST_int_eq(EVP_PKEY_param_check(ctx), expected_param_check))
        goto done;

#ifndef OPENSSL_NO_DEPRECATED_3_0
    ctx2 = EVP_PKEY_CTX_new_id(0xdefaced, NULL);
    /* assign the pkey directly, as an internal test */
    EVP_PKEY_up_ref(pkey);
    ctx2->pkey = pkey;

    if (!TEST_int_eq(EVP_PKEY_check(ctx2), 0xbeef))
        goto done;

    if (!TEST_int_eq(EVP_PKEY_public_check(ctx2), 0xbeef))
        goto done;

    if (!TEST_int_eq(EVP_PKEY_param_check(ctx2), 0xbeef))
        goto done;
#endif

    ret = 1;

 done:
    EVP_PKEY_CTX_free(ctx);
#ifndef OPENSSL_NO_DEPRECATED_3_0
    EVP_PKEY_CTX_free(ctx2);
#endif
    EVP_PKEY_free(pkey);
    return ret;
}

#ifndef OPENSSL_NO_CMAC
static int get_cmac_val(EVP_PKEY *pkey, unsigned char *mac)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const char msg[] = "Hello World";
    size_t maclen = AES_BLOCK_SIZE;
    int ret = 1;

    if (!TEST_ptr(mdctx)
            || !TEST_true(EVP_DigestSignInit_ex(mdctx, NULL, NULL, testctx,
                                                testpropq, pkey, NULL))
            || !TEST_true(EVP_DigestSignUpdate(mdctx, msg, sizeof(msg)))
            || !TEST_true(EVP_DigestSignFinal(mdctx, mac, &maclen))
            || !TEST_size_t_eq(maclen, AES_BLOCK_SIZE))
        ret = 0;

    EVP_MD_CTX_free(mdctx);

    return ret;
}
static int test_CMAC_keygen(void)
{
    static unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    EVP_PKEY_CTX *kctx = NULL;
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char mac[AES_BLOCK_SIZE];
# if !defined(OPENSSL_NO_DEPRECATED_3_0)
    unsigned char mac2[AES_BLOCK_SIZE];
# endif

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    /*
     * This is a legacy method for CMACs, but should still work.
     * This verifies that it works without an ENGINE.
     */
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, NULL);

    /* Test a CMAC key created using the "generated" method */
    if (!TEST_int_gt(EVP_PKEY_keygen_init(kctx), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_ctrl(kctx, -1, EVP_PKEY_OP_KEYGEN,
                                            EVP_PKEY_CTRL_CIPHER,
                                            0, (void *)EVP_aes_256_cbc()), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_ctrl(kctx, -1, EVP_PKEY_OP_KEYGEN,
                                            EVP_PKEY_CTRL_SET_MAC_KEY,
                                            sizeof(key), (void *)key), 0)
            || !TEST_int_gt(EVP_PKEY_keygen(kctx, &pkey), 0)
            || !TEST_ptr(pkey)
            || !TEST_true(get_cmac_val(pkey, mac)))
        goto done;

# if !defined(OPENSSL_NO_DEPRECATED_3_0)
    EVP_PKEY_free(pkey);

    /*
     * Test a CMAC key using the direct method, and compare with the mac
     * created above.
     */
    pkey = EVP_PKEY_new_CMAC_key(NULL, key, sizeof(key), EVP_aes_256_cbc());
    if (!TEST_ptr(pkey)
            || !TEST_true(get_cmac_val(pkey, mac2))
            || !TEST_mem_eq(mac, sizeof(mac), mac2, sizeof(mac2)))
        goto done;
# endif

    ret = 1;

 done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return ret;
}
#endif

static int test_HKDF(void)
{
    EVP_PKEY_CTX *pctx;
    unsigned char out[20];
    size_t outlen;
    int i, ret = 0;
    unsigned char salt[] = "0123456789";
    unsigned char key[] = "012345678901234567890123456789";
    unsigned char info[] = "infostring";
    const unsigned char expected[] = {
        0xe5, 0x07, 0x70, 0x7f, 0xc6, 0x78, 0xd6, 0x54, 0x32, 0x5f, 0x7e, 0xc5,
        0x7b, 0x59, 0x3e, 0xd8, 0x03, 0x6b, 0xed, 0xca
    };
    size_t expectedlen = sizeof(expected);

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "HKDF", testpropq)))
        goto done;

    /* We do this twice to test reuse of the EVP_PKEY_CTX */
    for (i = 0; i < 2; i++) {
        outlen = sizeof(out);
        memset(out, 0, outlen);

        if (!TEST_int_gt(EVP_PKEY_derive_init(pctx), 0)
                || !TEST_int_gt(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()), 0)
                || !TEST_int_gt(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt,
                                                            sizeof(salt) - 1), 0)
                || !TEST_int_gt(EVP_PKEY_CTX_set1_hkdf_key(pctx, key,
                                                           sizeof(key) - 1), 0)
                || !TEST_int_gt(EVP_PKEY_CTX_add1_hkdf_info(pctx, info,
                                                            sizeof(info) - 1), 0)
                || !TEST_int_gt(EVP_PKEY_derive(pctx, out, &outlen), 0)
                || !TEST_mem_eq(out, outlen, expected, expectedlen))
            goto done;
    }

    ret = 1;

 done:
    EVP_PKEY_CTX_free(pctx);

    return ret;
}

static int test_emptyikm_HKDF(void)
{
    EVP_PKEY_CTX *pctx;
    unsigned char out[20];
    size_t outlen;
    int ret = 0;
    unsigned char salt[] = "9876543210";
    unsigned char key[] = "";
    unsigned char info[] = "stringinfo";
    const unsigned char expected[] = {
        0x68, 0x81, 0xa5, 0x3e, 0x5b, 0x9c, 0x7b, 0x6f, 0x2e, 0xec, 0xc8, 0x47,
        0x7c, 0xfa, 0x47, 0x35, 0x66, 0x82, 0x15, 0x30
    };
    size_t expectedlen = sizeof(expected);

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "HKDF", testpropq)))
        goto done;

    outlen = sizeof(out);
    memset(out, 0, outlen);

    if (!TEST_int_gt(EVP_PKEY_derive_init(pctx), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt,
                                                        sizeof(salt) - 1), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_set1_hkdf_key(pctx, key,
                                                       sizeof(key) - 1), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_add1_hkdf_info(pctx, info,
                                                        sizeof(info) - 1), 0)
            || !TEST_int_gt(EVP_PKEY_derive(pctx, out, &outlen), 0)
            || !TEST_mem_eq(out, outlen, expected, expectedlen))
        goto done;

    ret = 1;

 done:
    EVP_PKEY_CTX_free(pctx);

    return ret;
}

static int test_empty_salt_info_HKDF(void)
{
    EVP_PKEY_CTX *pctx;
    unsigned char out[20];
    size_t outlen;
    int ret = 0;
    unsigned char salt[] = "";
    unsigned char key[] = "012345678901234567890123456789";
    unsigned char info[] = "";
    const unsigned char expected[] = {
	0x67, 0x12, 0xf9, 0x27, 0x8a, 0x8a, 0x3a, 0x8f, 0x7d, 0x2c, 0xa3, 0x6a,
	0xaa, 0xe9, 0xb3, 0xb9, 0x52, 0x5f, 0xe0, 0x06,
    };
    size_t expectedlen = sizeof(expected);

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "HKDF", testpropq)))
        goto done;

    outlen = sizeof(out);
    memset(out, 0, outlen);

    if (!TEST_int_gt(EVP_PKEY_derive_init(pctx), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt,
                                                        sizeof(salt) - 1), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_set1_hkdf_key(pctx, key,
                                                       sizeof(key) - 1), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_add1_hkdf_info(pctx, info,
                                                        sizeof(info) - 1), 0)
            || !TEST_int_gt(EVP_PKEY_derive(pctx, out, &outlen), 0)
            || !TEST_mem_eq(out, outlen, expected, expectedlen))
        goto done;

    ret = 1;

 done:
    EVP_PKEY_CTX_free(pctx);

    return ret;
}

#ifndef OPENSSL_NO_EC
static int test_X509_PUBKEY_inplace(void)
{
    int ret = 0;
    X509_PUBKEY *xp = X509_PUBKEY_new_ex(testctx, testpropq);
    const unsigned char *p = kExampleECPubKeyDER;
    size_t input_len = sizeof(kExampleECPubKeyDER);

    if (!TEST_ptr(xp))
        goto done;
    if (!TEST_ptr(d2i_X509_PUBKEY(&xp, &p, input_len)))
        goto done;

    if (!TEST_ptr(X509_PUBKEY_get0(xp)))
        goto done;

    p = kExampleBadECPubKeyDER;
    input_len = sizeof(kExampleBadECPubKeyDER);

    if (!TEST_ptr(xp = d2i_X509_PUBKEY(&xp, &p, input_len)))
        goto done;

    if (!TEST_true(X509_PUBKEY_get0(xp) == NULL))
        goto done;

    ret = 1;

 done:
    X509_PUBKEY_free(xp);
    return ret;
}

static int test_X509_PUBKEY_dup(void)
{
    int ret = 0;
    X509_PUBKEY *xp = NULL, *xq = NULL;
    const unsigned char *p = kExampleECPubKeyDER;
    size_t input_len = sizeof(kExampleECPubKeyDER);

    xp = X509_PUBKEY_new_ex(testctx, testpropq);
    if (!TEST_ptr(xp)
            || !TEST_ptr(d2i_X509_PUBKEY(&xp, &p, input_len))
            || !TEST_ptr(xq = X509_PUBKEY_dup(xp))
            || !TEST_ptr_ne(xp, xq))
        goto done;

    if (!TEST_ptr(X509_PUBKEY_get0(xq))
            || !TEST_ptr(X509_PUBKEY_get0(xp))
            || !TEST_ptr_ne(X509_PUBKEY_get0(xq), X509_PUBKEY_get0(xp)))
        goto done;

    X509_PUBKEY_free(xq);
    xq = NULL;
    p = kExampleBadECPubKeyDER;
    input_len = sizeof(kExampleBadECPubKeyDER);

    if (!TEST_ptr(xp = d2i_X509_PUBKEY(&xp, &p, input_len))
            || !TEST_ptr(xq = X509_PUBKEY_dup(xp)))
        goto done;

    X509_PUBKEY_free(xp);
    xp = NULL;
    if (!TEST_true(X509_PUBKEY_get0(xq) == NULL))
        goto done;

    ret = 1;

 done:
    X509_PUBKEY_free(xp);
    X509_PUBKEY_free(xq);
    return ret;
}
#endif /* OPENSSL_NO_EC */

/* Test getting and setting parameters on an EVP_PKEY_CTX */
static int test_EVP_PKEY_CTX_get_set_params(EVP_PKEY *pkey)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    const OSSL_PARAM *params;
    OSSL_PARAM ourparams[2], *param = ourparams, *param_md;
    int ret = 0;
    const EVP_MD *md;
    char mdname[OSSL_MAX_NAME_SIZE];
    char ssl3ms[48];

    /* Initialise a sign operation */
    ctx = EVP_PKEY_CTX_new_from_pkey(testctx, pkey, testpropq);
    if (!TEST_ptr(ctx)
            || !TEST_int_gt(EVP_PKEY_sign_init(ctx), 0))
        goto err;

    /*
     * We should be able to query the parameters now.
     */
    params = EVP_PKEY_CTX_settable_params(ctx);
    if (!TEST_ptr(params)
        || !TEST_ptr(OSSL_PARAM_locate_const(params,
                                             OSSL_SIGNATURE_PARAM_DIGEST)))
        goto err;

    params = EVP_PKEY_CTX_gettable_params(ctx);
    if (!TEST_ptr(params)
        || !TEST_ptr(OSSL_PARAM_locate_const(params,
                                             OSSL_SIGNATURE_PARAM_ALGORITHM_ID))
        || !TEST_ptr(OSSL_PARAM_locate_const(params,
                                             OSSL_SIGNATURE_PARAM_DIGEST)))
        goto err;

    /*
     * Test getting and setting params via EVP_PKEY_CTX_set_params() and
     * EVP_PKEY_CTX_get_params()
     */
    strcpy(mdname, "SHA512");
    param_md = param;
    *param++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                                mdname, 0);
    *param++ = OSSL_PARAM_construct_end();

    if (!TEST_true(EVP_PKEY_CTX_set_params(ctx, ourparams)))
        goto err;

    mdname[0] = '\0';
    *param_md = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                                 mdname, sizeof(mdname));
    if (!TEST_true(EVP_PKEY_CTX_get_params(ctx, ourparams))
            || !TEST_str_eq(mdname, "SHA512"))
        goto err;

    /*
     * Test the TEST_PKEY_CTX_set_signature_md() and
     * TEST_PKEY_CTX_get_signature_md() functions
     */
    if (!TEST_int_gt(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_get_signature_md(ctx, &md), 0)
            || !TEST_ptr_eq(md, EVP_sha256()))
        goto err;

    /*
     * Test getting MD parameters via an associated EVP_PKEY_CTX
     */
    mdctx = EVP_MD_CTX_new();
    if (!TEST_ptr(mdctx)
        || !TEST_true(EVP_DigestSignInit_ex(mdctx, NULL, "SHA1", testctx, testpropq,
                                            pkey, NULL)))
        goto err;

    /*
     * We now have an EVP_MD_CTX with an EVP_PKEY_CTX inside it. We should be
     * able to obtain the digest's settable parameters from the provider.
     */
    params = EVP_MD_CTX_settable_params(mdctx);
    if (!TEST_ptr(params)
            || !TEST_int_eq(strcmp(params[0].key, OSSL_DIGEST_PARAM_SSL3_MS), 0)
               /* The final key should be NULL */
            || !TEST_ptr_null(params[1].key))
        goto err;

    param = ourparams;
    memset(ssl3ms, 0, sizeof(ssl3ms));
    *param++ = OSSL_PARAM_construct_octet_string(OSSL_DIGEST_PARAM_SSL3_MS,
                                                 ssl3ms, sizeof(ssl3ms));
    *param++ = OSSL_PARAM_construct_end();

    if (!TEST_true(EVP_MD_CTX_set_params(mdctx, ourparams)))
        goto err;

    ret = 1;

 err:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

#ifndef OPENSSL_NO_DSA
static int test_DSA_get_set_params(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our DSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "DSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                             pub))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                                          params), 0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

 err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted
 */
static int test_DSA_priv_pub(void)
{
    return test_EVP_PKEY_ffc_priv_pub("DSA");
}

#endif /* !OPENSSL_NO_DSA */

static int test_RSA_get_set_params(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our RSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(d = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                                          params), 0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

 err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}

static int test_RSA_OAEP_set_get_params(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *key_ctx = NULL;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (!TEST_ptr(key = load_example_rsa_key())
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(0, key, 0)))
        goto err;

    {
        int padding = RSA_PKCS1_OAEP_PADDING;
        OSSL_PARAM params[4];

        params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PAD_MODE, &padding);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                                     OSSL_DIGEST_NAME_SHA2_256, 0);
        params[2] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                                                     OSSL_DIGEST_NAME_SHA1, 0);
        params[3] = OSSL_PARAM_construct_end();

        if (!TEST_int_gt(EVP_PKEY_encrypt_init_ex(key_ctx, params),0))
            goto err;
    }
    {
        OSSL_PARAM params[3];
        char oaepmd[30] = { '\0' };
        char mgf1md[30] = { '\0' };

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                                     oaepmd, sizeof(oaepmd));
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                                                     mgf1md, sizeof(mgf1md));
        params[2] = OSSL_PARAM_construct_end();

        if (!TEST_true(EVP_PKEY_CTX_get_params(key_ctx, params)))
            goto err;

        if (!TEST_str_eq(oaepmd, OSSL_DIGEST_NAME_SHA2_256)
            || !TEST_str_eq(mgf1md, OSSL_DIGEST_NAME_SHA1))
            goto err;
    }

    ret = 1;

 err:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_ctx);

    return ret;
}

/* https://github.com/openssl/openssl/issues/21288 */
static int test_RSA_OAEP_set_null_label(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *key_ctx = NULL;

    if (!TEST_ptr(key = load_example_rsa_key())
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(testctx, key, NULL))
        || !TEST_true(EVP_PKEY_encrypt_init(key_ctx)))
        goto err;

    if (!TEST_true(EVP_PKEY_CTX_set_rsa_padding(key_ctx, RSA_PKCS1_OAEP_PADDING)))
        goto err;

    if (!TEST_true(EVP_PKEY_CTX_set0_rsa_oaep_label(key_ctx, OPENSSL_strdup("foo"), 0)))
        goto err;

    if (!TEST_true(EVP_PKEY_CTX_set0_rsa_oaep_label(key_ctx, NULL, 0)))
        goto err;

    ret = 1;

 err:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_ctx);

    return ret;
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_RSA_legacy(void)
{
    int ret = 0;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (!TEST_ptr(p = BN_dup(BN_value_one()))
        || !TEST_ptr(q = BN_dup(BN_value_one()))
        || !TEST_ptr(n = BN_dup(BN_value_one()))
        || !TEST_ptr(e = BN_dup(BN_value_one()))
        || !TEST_ptr(d = BN_dup(BN_value_one())))
        goto err;

    if (!TEST_ptr(rsa = RSA_new())
        || !TEST_ptr(pkey = EVP_PKEY_new())
        || !TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    if (!TEST_true(RSA_set0_factors(rsa, p, q)))
        goto err;
    p = NULL;
    q = NULL;

    if (!TEST_true(RSA_set0_key(rsa, n, e, d)))
        goto err;
    n = NULL;
    e = NULL;
    d = NULL;

    if (!TEST_true(EVP_PKEY_assign_RSA(pkey, rsa)))
        goto err;

    rsa = NULL;

    if (!TEST_true(EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)))
        goto err;

    ret = 1;

err:
    RSA_free(rsa);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}
#endif

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
static int test_decrypt_null_chunks(void)
{
    EVP_CIPHER_CTX* ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1
    };
    unsigned char iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };
    unsigned char msg[] = "It was the best of times, it was the worst of times";
    unsigned char ciphertext[80];
    unsigned char plaintext[80];
    /* We initialise tmp to a non zero value on purpose */
    int ctlen, ptlen, tmp = 99;
    int ret = 0;
    const int enc_offset = 10, dec_offset = 20;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(testctx, "ChaCha20-Poly1305", testpropq))
            || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_true(EVP_EncryptInit_ex(ctx, cipher, NULL,
                                             key, iv))
            || !TEST_true(EVP_EncryptUpdate(ctx, ciphertext, &ctlen, msg,
                                            enc_offset))
            /* Deliberate add a zero length update */
            || !TEST_true(EVP_EncryptUpdate(ctx, ciphertext + ctlen, &tmp, NULL,
                                            0))
            || !TEST_int_eq(tmp, 0)
            || !TEST_true(EVP_EncryptUpdate(ctx, ciphertext + ctlen, &tmp,
                                            msg + enc_offset,
                                            sizeof(msg) - enc_offset))
            || !TEST_int_eq(ctlen += tmp, sizeof(msg))
            || !TEST_true(EVP_EncryptFinal(ctx, ciphertext + ctlen, &tmp))
            || !TEST_int_eq(tmp, 0))
        goto err;

    /* Deliberately initialise tmp to a non zero value */
    tmp = 99;
    if (!TEST_true(EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
            || !TEST_true(EVP_DecryptUpdate(ctx, plaintext, &ptlen, ciphertext,
                                            dec_offset))
            /*
             * Deliberately add a zero length update. We also deliberately do
             * this at a different offset than for encryption.
             */
            || !TEST_true(EVP_DecryptUpdate(ctx, plaintext + ptlen, &tmp, NULL,
                                            0))
            || !TEST_int_eq(tmp, 0)
            || !TEST_true(EVP_DecryptUpdate(ctx, plaintext + ptlen, &tmp,
                                            ciphertext + dec_offset,
                                            ctlen - dec_offset))
            || !TEST_int_eq(ptlen += tmp, sizeof(msg))
            || !TEST_true(EVP_DecryptFinal(ctx, plaintext + ptlen, &tmp))
            || !TEST_int_eq(tmp, 0)
            || !TEST_mem_eq(msg, sizeof(msg), plaintext, ptlen))
        goto err;

    ret = 1;
 err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}
#endif /* !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305) */

#ifndef OPENSSL_NO_DH
/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted
 */
static int test_DH_priv_pub(void)
{
    return test_EVP_PKEY_ffc_priv_pub("DH");
}

# ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_EVP_PKEY_set1_DH(void)
{
    DH *x942dh = NULL, *noqdh = NULL;
    EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
    int ret = 0;
    BIGNUM *p, *g = NULL;
    BIGNUM *pubkey = NULL;
    unsigned char pub[2048 / 8];
    size_t len = 0;

    if (!TEST_ptr(p = BN_new())
            || !TEST_ptr(g = BN_new())
            || !TEST_ptr(pubkey = BN_new())
            || !TEST_true(BN_set_word(p, 9999))
            || !TEST_true(BN_set_word(g, 2))
            || !TEST_true(BN_set_word(pubkey, 4321))
            || !TEST_ptr(noqdh = DH_new())
            || !TEST_true(DH_set0_pqg(noqdh, p, NULL, g))
            || !TEST_true(DH_set0_key(noqdh, pubkey, NULL))
            || !TEST_ptr(pubkey = BN_new())
            || !TEST_true(BN_set_word(pubkey, 4321)))
        goto err;
    p = g = NULL;

    x942dh = DH_get_2048_256();
    pkey1 = EVP_PKEY_new();
    pkey2 = EVP_PKEY_new();
    if (!TEST_ptr(x942dh)
            || !TEST_ptr(noqdh)
            || !TEST_ptr(pkey1)
            || !TEST_ptr(pkey2)
            || !TEST_true(DH_set0_key(x942dh, pubkey, NULL)))
        goto err;
    pubkey = NULL;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey1, x942dh))
            || !TEST_int_eq(EVP_PKEY_get_id(pkey1), EVP_PKEY_DHX))
        goto err;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_PUB_KEY,
                                         &pubkey))
            || !TEST_ptr(pubkey))
        goto err;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey2, noqdh))
            || !TEST_int_eq(EVP_PKEY_get_id(pkey2), EVP_PKEY_DH))
        goto err;

    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey2,
                                                   OSSL_PKEY_PARAM_PUB_KEY,
                                                   pub, sizeof(pub), &len))
            || !TEST_size_t_ne(len, 0))
        goto err;

    ret = 1;
 err:
    BN_free(p);
    BN_free(g);
    BN_free(pubkey);
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);
    DH_free(x942dh);
    DH_free(noqdh);

    return ret;
}
# endif /* !OPENSSL_NO_DEPRECATED_3_0 */
#endif /* !OPENSSL_NO_DH */

/*
 * We test what happens with an empty template.  For the sake of this test,
 * the template must be ignored, and we know that's the case for RSA keys
 * (this might arguably be a misfeature, but that's what we currently do,
 * even in provider code, since that's how the legacy RSA implementation
 * does things)
 */
static int test_keygen_with_empty_template(int n)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *tkey = NULL;
    int ret = 0;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    switch (n) {
    case 0:
        /* We do test with no template at all as well */
        if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)))
            goto err;
        break;
    case 1:
        /* Here we create an empty RSA key that serves as our template */
        if (!TEST_ptr(tkey = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_set_type(tkey, EVP_PKEY_RSA))
            || !TEST_ptr(ctx = EVP_PKEY_CTX_new(tkey, NULL)))
            goto err;
        break;
    }

    if (!TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
        || !TEST_int_gt(EVP_PKEY_keygen(ctx, &pkey), 0))
        goto err;

    ret = 1;
 err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(tkey);
    return ret;
}

/*
 * Test that we fail if we attempt to use an algorithm that is not available
 * in the current library context (unless we are using an algorithm that
 * should be made available via legacy codepaths).
 *
 * 0:   RSA
 * 1:   SM2
 */
static int test_pkey_ctx_fail_without_provider(int tst)
{
    OSSL_LIB_CTX *tmpctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *tmpnullprov = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const char *keytype = NULL;
    int expect_null = 0;
    int ret = 0;

    if (!TEST_ptr(tmpctx))
        goto err;

    tmpnullprov = OSSL_PROVIDER_load(tmpctx, "null");
    if (!TEST_ptr(tmpnullprov))
        goto err;

    /*
     * We check for certain algos in the null provider.
     * If an algo is expected to have a provider keymgmt, constructing an
     * EVP_PKEY_CTX is expected to fail (return NULL).
     * Otherwise, if it's expected to have legacy support, constructing an
     * EVP_PKEY_CTX is expected to succeed (return non-NULL).
     */
    switch (tst) {
    case 0:
        keytype = "RSA";
        expect_null = 1;
        break;
    case 1:
        keytype = "SM2";
        expect_null = 1;
#ifdef OPENSSL_NO_EC
        TEST_info("EC disable, skipping SM2 check...");
        goto end;
#endif
#ifdef OPENSSL_NO_SM2
        TEST_info("SM2 disable, skipping SM2 check...");
        goto end;
#endif
        break;
    default:
        TEST_error("No test for case %d", tst);
        goto err;
    }

    pctx = EVP_PKEY_CTX_new_from_name(tmpctx, keytype, "");
    if (expect_null ? !TEST_ptr_null(pctx) : !TEST_ptr(pctx))
        goto err;

#if defined(OPENSSL_NO_EC) || defined(OPENSSL_NO_SM2)
 end:
#endif
    ret = 1;

 err:
    EVP_PKEY_CTX_free(pctx);
    OSSL_PROVIDER_unload(tmpnullprov);
    OSSL_LIB_CTX_free(tmpctx);
    return ret;
}

static int test_rand_agglomeration(void)
{
    EVP_RAND *rand;
    EVP_RAND_CTX *ctx;
    OSSL_PARAM params[3], *p = params;
    int res;
    unsigned int step = 7;
    static unsigned char seed[] = "It does not matter how slowly you go "
                                  "as long as you do not stop.";
    unsigned char out[sizeof(seed)];

    if (!TEST_int_ne(sizeof(seed) % step, 0)
            || !TEST_ptr(rand = EVP_RAND_fetch(testctx, "TEST-RAND", testpropq)))
        return 0;
    ctx = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);
    if (!TEST_ptr(ctx))
        return 0;

    memset(out, 0, sizeof(out));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                             seed, sizeof(seed));
    *p++ = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_MAX_REQUEST, &step);
    *p = OSSL_PARAM_construct_end();
    res = TEST_true(EVP_RAND_CTX_set_params(ctx, params))
          && TEST_true(EVP_RAND_generate(ctx, out, sizeof(out), 0, 1, NULL, 0))
          && TEST_mem_eq(seed, sizeof(seed), out, sizeof(out));
    EVP_RAND_CTX_free(ctx);
    return res;
}

/*
 * Test that we correctly return the original or "running" IV after
 * an encryption operation.
 * Run multiple times for some different relevant algorithms/modes.
 */
static int test_evp_iv_aes(int idx)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[16] = {0x4c, 0x43, 0xdb, 0xdd, 0x42, 0x73, 0x47, 0xd1,
                             0xe5, 0x62, 0x7d, 0xcd, 0x4d, 0x76, 0x4d, 0x57};
    unsigned char init_iv[EVP_MAX_IV_LENGTH] =
        {0x57, 0x71, 0x7d, 0xad, 0xdb, 0x9b, 0x98, 0x82,
         0x5a, 0x55, 0x91, 0x81, 0x42, 0xa8, 0x89, 0x34};
    static const unsigned char msg[] = { 1, 2, 3, 4, 5, 6, 7, 8,
                                         9, 10, 11, 12, 13, 14, 15, 16 };
    unsigned char ciphertext[32], oiv[16], iv[16];
    unsigned char *ref_iv;
    unsigned char cbc_state[16] = {0x10, 0x2f, 0x05, 0xcc, 0xc2, 0x55, 0x72, 0xb9,
                                   0x88, 0xe6, 0x4a, 0x17, 0x10, 0x74, 0x22, 0x5e};

    unsigned char ofb_state[16] = {0x76, 0xe6, 0x66, 0x61, 0xd0, 0x8a, 0xe4, 0x64,
                                   0xdd, 0x66, 0xbf, 0x00, 0xf0, 0xe3, 0x6f, 0xfd};
    unsigned char cfb_state[16] = {0x77, 0xe4, 0x65, 0x65, 0xd5, 0x8c, 0xe3, 0x6c,
                                   0xd4, 0x6c, 0xb4, 0x0c, 0xfd, 0xed, 0x60, 0xed};
    unsigned char gcm_state[12] = {0x57, 0x71, 0x7d, 0xad, 0xdb, 0x9b,
                                   0x98, 0x82, 0x5a, 0x55, 0x91, 0x81};
    unsigned char ccm_state[7] = {0x57, 0x71, 0x7d, 0xad, 0xdb, 0x9b, 0x98};
#ifndef OPENSSL_NO_OCB
    unsigned char ocb_state[12] = {0x57, 0x71, 0x7d, 0xad, 0xdb, 0x9b,
                                   0x98, 0x82, 0x5a, 0x55, 0x91, 0x81};
#endif
    int len = sizeof(ciphertext);
    size_t ivlen, ref_len;
    const EVP_CIPHER *type = NULL;
    int iv_reset = 0;

    if (nullprov != NULL && idx < 6)
        return TEST_skip("Test does not support a non-default library context");

    switch (idx) {
    case 0:
        type = EVP_aes_128_cbc();
        /* FALLTHROUGH */
    case 6:
        type = (type != NULL) ? type :
                                EVP_CIPHER_fetch(testctx, "aes-128-cbc", testpropq);
        ref_iv = cbc_state;
        ref_len = sizeof(cbc_state);
        iv_reset = 1;
        break;
    case 1:
        type = EVP_aes_128_ofb();
        /* FALLTHROUGH */
    case 7:
        type = (type != NULL) ? type :
                                EVP_CIPHER_fetch(testctx, "aes-128-ofb", testpropq);
        ref_iv = ofb_state;
        ref_len = sizeof(ofb_state);
        iv_reset = 1;
        break;
    case 2:
        type = EVP_aes_128_cfb();
        /* FALLTHROUGH */
    case 8:
        type = (type != NULL) ? type :
                                EVP_CIPHER_fetch(testctx, "aes-128-cfb", testpropq);
        ref_iv = cfb_state;
        ref_len = sizeof(cfb_state);
        iv_reset = 1;
        break;
    case 3:
        type = EVP_aes_128_gcm();
        /* FALLTHROUGH */
    case 9:
        type = (type != NULL) ? type :
                                EVP_CIPHER_fetch(testctx, "aes-128-gcm", testpropq);
        ref_iv = gcm_state;
        ref_len = sizeof(gcm_state);
        break;
    case 4:
        type = EVP_aes_128_ccm();
        /* FALLTHROUGH */
    case 10:
        type = (type != NULL) ? type :
                                EVP_CIPHER_fetch(testctx, "aes-128-ccm", testpropq);
        ref_iv = ccm_state;
        ref_len = sizeof(ccm_state);
        break;
#ifdef OPENSSL_NO_OCB
    case 5:
    case 11:
        return 1;
#else
    case 5:
        type = EVP_aes_128_ocb();
        /* FALLTHROUGH */
    case 11:
        type = (type != NULL) ? type :
                                EVP_CIPHER_fetch(testctx, "aes-128-ocb", testpropq);
        ref_iv = ocb_state;
        ref_len = sizeof(ocb_state);
        break;
#endif
    default:
        return 0;
    }

    if (!TEST_ptr(type)
            || !TEST_ptr((ctx = EVP_CIPHER_CTX_new()))
            || !TEST_true(EVP_EncryptInit_ex(ctx, type, NULL, key, init_iv))
            || !TEST_true(EVP_EncryptUpdate(ctx, ciphertext, &len, msg,
                          (int)sizeof(msg)))
            || !TEST_true(EVP_CIPHER_CTX_get_original_iv(ctx, oiv, sizeof(oiv)))
            || !TEST_true(EVP_CIPHER_CTX_get_updated_iv(ctx, iv, sizeof(iv)))
            || !TEST_true(EVP_EncryptFinal_ex(ctx, ciphertext, &len)))
        goto err;
    ivlen = EVP_CIPHER_CTX_get_iv_length(ctx);

    if (!TEST_int_gt(ivlen, 0))
        goto err;

    if (!TEST_mem_eq(init_iv, ivlen, oiv, ivlen)
            || !TEST_mem_eq(ref_iv, ref_len, iv, ivlen))
        goto err;

    /* CBC, OFB, and CFB modes: the updated iv must be reset after reinit */
    if (!TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL))
        || !TEST_true(EVP_CIPHER_CTX_get_updated_iv(ctx, iv, sizeof(iv))))
        goto err;
    if (iv_reset) {
        if (!TEST_mem_eq(init_iv, ivlen, iv, ivlen))
            goto err;
    } else {
        if (!TEST_mem_eq(ref_iv, ivlen, iv, ivlen))
            goto err;
    }

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    if (idx >= 6)
        EVP_CIPHER_free((EVP_CIPHER *)type);
    return ret;
}

#ifndef OPENSSL_NO_DES
static int test_evp_iv_des(int idx)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    static const unsigned char key[24] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xf1, 0xe0, 0xd3, 0xc2, 0xb5, 0xa4, 0x97, 0x86,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const unsigned char init_iv[8] = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const unsigned char msg[] = { 1, 2, 3, 4, 5, 6, 7, 8,
                                         9, 10, 11, 12, 13, 14, 15, 16 };
    unsigned char ciphertext[32], oiv[8], iv[8];
    unsigned const char *ref_iv;
    static const unsigned char cbc_state_des[8] = {
        0x4f, 0xa3, 0x85, 0xcd, 0x8b, 0xf3, 0x06, 0x2a
    };
    static const unsigned char cbc_state_3des[8] = {
        0x35, 0x27, 0x7d, 0x65, 0x6c, 0xfb, 0x50, 0xd9
    };
    static const unsigned char ofb_state_des[8] = {
        0xa7, 0x0d, 0x1d, 0x45, 0xf9, 0x96, 0x3f, 0x2c
    };
    static const unsigned char ofb_state_3des[8] = {
        0xab, 0x16, 0x24, 0xbb, 0x5b, 0xac, 0xed, 0x5e
    };
    static const unsigned char cfb_state_des[8] = {
        0x91, 0xeb, 0x6d, 0x29, 0x4b, 0x08, 0xbd, 0x73
    };
    static const unsigned char cfb_state_3des[8] = {
        0x34, 0xdd, 0xfb, 0x47, 0x33, 0x1c, 0x61, 0xf7
    };
    int len = sizeof(ciphertext);
    size_t ivlen, ref_len;
    EVP_CIPHER *type = NULL;

    if (lgcyprov == NULL && idx < 3)
        return TEST_skip("Test requires legacy provider to be loaded");

    switch (idx) {
    case 0:
        type = EVP_CIPHER_fetch(testctx, "des-cbc", testpropq);
        ref_iv = cbc_state_des;
        ref_len = sizeof(cbc_state_des);
        break;
    case 1:
        type = EVP_CIPHER_fetch(testctx, "des-ofb", testpropq);
        ref_iv = ofb_state_des;
        ref_len = sizeof(ofb_state_des);
        break;
    case 2:
        type = EVP_CIPHER_fetch(testctx, "des-cfb", testpropq);
        ref_iv = cfb_state_des;
        ref_len = sizeof(cfb_state_des);
        break;
    case 3:
        type = EVP_CIPHER_fetch(testctx, "des-ede3-cbc", testpropq);
        ref_iv = cbc_state_3des;
        ref_len = sizeof(cbc_state_3des);
        break;
    case 4:
        type = EVP_CIPHER_fetch(testctx, "des-ede3-ofb", testpropq);
        ref_iv = ofb_state_3des;
        ref_len = sizeof(ofb_state_3des);
        break;
    case 5:
        type = EVP_CIPHER_fetch(testctx, "des-ede3-cfb", testpropq);
        ref_iv = cfb_state_3des;
        ref_len = sizeof(cfb_state_3des);
        break;
    default:
        return 0;
    }

    if (!TEST_ptr(type)
            || !TEST_ptr((ctx = EVP_CIPHER_CTX_new()))
            || !TEST_true(EVP_EncryptInit_ex(ctx, type, NULL, key, init_iv))
            || !TEST_true(EVP_EncryptUpdate(ctx, ciphertext, &len, msg,
                          (int)sizeof(msg)))
            || !TEST_true(EVP_CIPHER_CTX_get_original_iv(ctx, oiv, sizeof(oiv)))
            || !TEST_true(EVP_CIPHER_CTX_get_updated_iv(ctx, iv, sizeof(iv)))
            || !TEST_true(EVP_EncryptFinal_ex(ctx, ciphertext, &len)))
        goto err;
    ivlen = EVP_CIPHER_CTX_get_iv_length(ctx);

    if (!TEST_int_gt(ivlen, 0))
        goto err;

    if (!TEST_mem_eq(init_iv, ivlen, oiv, ivlen)
            || !TEST_mem_eq(ref_iv, ref_len, iv, ivlen))
        goto err;

    if (!TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL))
        || !TEST_true(EVP_CIPHER_CTX_get_updated_iv(ctx, iv, sizeof(iv))))
        goto err;
    if (!TEST_mem_eq(init_iv, ivlen, iv, ivlen))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(type);
    return ret;
}
#endif

#ifndef OPENSSL_NO_BF
static int test_evp_bf_default_keylen(int idx)
{
    int ret = 0;
    static const char *algos[4] = {
        "bf-ecb", "bf-cbc", "bf-cfb", "bf-ofb"
    };
    int ivlen[4] = { 0, 8, 8, 8 };
    EVP_CIPHER *cipher = NULL;

    if (lgcyprov == NULL)
        return TEST_skip("Test requires legacy provider to be loaded");

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(testctx, algos[idx], testpropq))
            || !TEST_int_eq(EVP_CIPHER_get_key_length(cipher), 16)
            || !TEST_int_eq(EVP_CIPHER_get_iv_length(cipher), ivlen[idx]))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    return ret;
}
#endif

#ifndef OPENSSL_NO_EC
static int ecpub_nids[] = {
    NID_brainpoolP256r1, NID_X9_62_prime256v1,
    NID_secp384r1, NID_secp521r1,
# ifndef OPENSSL_NO_EC2M
    NID_sect233k1, NID_sect233r1, NID_sect283r1,
    NID_sect409k1, NID_sect409r1, NID_sect571k1, NID_sect571r1,
# endif
    NID_brainpoolP384r1, NID_brainpoolP512r1
};

static int test_ecpub(int idx)
{
    int ret = 0, len, savelen;
    int nid;
    unsigned char buf[1024];
    unsigned char *p;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
# ifndef OPENSSL_NO_DEPRECATED_3_0
    const unsigned char *q;
    EVP_PKEY *pkey2 = NULL;
    EC_KEY *ec = NULL;
# endif

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    nid = ecpub_nids[idx];

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!TEST_ptr(ctx)
        || !TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid), 0)
        || !TEST_true(EVP_PKEY_keygen(ctx, &pkey)))
        goto done;
    len = i2d_PublicKey(pkey, NULL);
    savelen = len;
    if (!TEST_int_ge(len, 1)
        || !TEST_int_lt(len, 1024))
        goto done;
    p = buf;
    len = i2d_PublicKey(pkey, &p);
    if (!TEST_int_ge(len, 1)
            || !TEST_int_eq(len, savelen))
        goto done;

# ifndef OPENSSL_NO_DEPRECATED_3_0
    /* Now try to decode the just-created DER. */
    q = buf;
    if (!TEST_ptr((pkey2 = EVP_PKEY_new()))
            || !TEST_ptr((ec = EC_KEY_new_by_curve_name(nid)))
            || !TEST_true(EVP_PKEY_assign_EC_KEY(pkey2, ec)))
        goto done;
    /* EC_KEY ownership transferred */
    ec = NULL;
    if (!TEST_ptr(d2i_PublicKey(EVP_PKEY_EC, &pkey2, &q, savelen)))
        goto done;
    /* The keys should match. */
    if (!TEST_int_eq(EVP_PKEY_eq(pkey, pkey2), 1))
        goto done;
# endif

    ret = 1;

 done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
# ifndef OPENSSL_NO_DEPRECATED_3_0
    EVP_PKEY_free(pkey2);
    EC_KEY_free(ec);
# endif
    return ret;
}
#endif

static int test_EVP_rsa_pss_with_keygen_bits(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD *md;

    md = EVP_MD_fetch(testctx, "sha256", testpropq);
    ret = TEST_ptr(md)
        && TEST_ptr((ctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA-PSS", testpropq)))
        && TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
        && TEST_int_gt(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 512), 0)
        && TEST_int_gt(EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md), 0)
        && TEST_true(EVP_PKEY_keygen(ctx, &pkey));

    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_EVP_rsa_pss_set_saltlen(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD *sha256 = NULL;
    EVP_MD_CTX *sha256_ctx = NULL;
    int saltlen = 9999; /* buggy EVP_PKEY_CTX_get_rsa_pss_saltlen() didn't update this */
    const int test_value = 32;

    ret = TEST_ptr(pkey = load_example_rsa_key())
        && TEST_ptr(sha256 = EVP_MD_fetch(testctx, "sha256", NULL))
        && TEST_ptr(sha256_ctx = EVP_MD_CTX_new())
        && TEST_true(EVP_DigestSignInit(sha256_ctx, &pkey_ctx, sha256, NULL, pkey))
        && TEST_true(EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING))
        && TEST_int_gt(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, test_value), 0)
        && TEST_int_gt(EVP_PKEY_CTX_get_rsa_pss_saltlen(pkey_ctx, &saltlen), 0)
        && TEST_int_eq(saltlen, test_value);

    EVP_MD_CTX_free(sha256_ctx);
    EVP_PKEY_free(pkey);
    EVP_MD_free(sha256);

    return ret;
}

static int success = 1;
static void md_names(const char *name, void *vctx)
{
    OSSL_LIB_CTX *ctx = (OSSL_LIB_CTX *)vctx;
    /* Force a namemap update */
    EVP_CIPHER *aes128 = EVP_CIPHER_fetch(ctx, "AES-128-CBC", NULL);

    if (!TEST_ptr(aes128))
        success = 0;

    EVP_CIPHER_free(aes128);
}

/*
 * Test that changing the namemap in a user callback works in a names_do_all
 * function.
 */
static int test_names_do_all(void)
{
    /* We use a custom libctx so that we know the state of the namemap */
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    EVP_MD *sha256 = NULL;
    int testresult = 0;

    if (!TEST_ptr(ctx))
        goto err;

    sha256 = EVP_MD_fetch(ctx, "SHA2-256", NULL);
    if (!TEST_ptr(sha256))
        goto err;

    /*
     * We loop through all the names for a given digest. This should still work
     * even if the namemap changes part way through.
     */
    if (!TEST_true(EVP_MD_names_do_all(sha256, md_names, ctx)))
        goto err;

    if (!TEST_true(success))
        goto err;

    testresult = 1;
 err:
    EVP_MD_free(sha256);
    OSSL_LIB_CTX_free(ctx);
    return testresult;
}

typedef struct {
    const char *cipher;
    const unsigned char *key;
    const unsigned char *iv;
    const unsigned char *input;
    const unsigned char *expected;
    const unsigned char *tag;
    size_t ivlen; /* 0 if we do not need to set a specific IV len */
    size_t inlen;
    size_t expectedlen;
    size_t taglen;
    int keyfirst;
    int initenc;
    int finalenc;
} EVP_INIT_TEST_st;

static const EVP_INIT_TEST_st evp_init_tests[] = {
    {
        "aes-128-cfb", kCFBDefaultKey, iCFBIV, cfbPlaintext,
        cfbCiphertext, NULL, 0, sizeof(cfbPlaintext), sizeof(cfbCiphertext),
        0, 1, 0, 1
    },
    {
        "aes-256-gcm", kGCMDefaultKey, iGCMDefaultIV, gcmDefaultPlaintext,
        gcmDefaultCiphertext, gcmDefaultTag, sizeof(iGCMDefaultIV),
        sizeof(gcmDefaultPlaintext), sizeof(gcmDefaultCiphertext),
        sizeof(gcmDefaultTag), 1, 0, 1
    },
    {
        "aes-128-cfb", kCFBDefaultKey, iCFBIV, cfbPlaintext,
        cfbCiphertext, NULL, 0, sizeof(cfbPlaintext), sizeof(cfbCiphertext),
        0, 0, 0, 1
    },
    {
        "aes-256-gcm", kGCMDefaultKey, iGCMDefaultIV, gcmDefaultPlaintext,
        gcmDefaultCiphertext, gcmDefaultTag, sizeof(iGCMDefaultIV),
        sizeof(gcmDefaultPlaintext), sizeof(gcmDefaultCiphertext),
        sizeof(gcmDefaultTag), 0, 0, 1
    },
    {
        "aes-128-cfb", kCFBDefaultKey, iCFBIV, cfbCiphertext,
        cfbPlaintext, NULL, 0, sizeof(cfbCiphertext), sizeof(cfbPlaintext),
        0, 1, 1, 0
    },
    {
        "aes-256-gcm", kGCMDefaultKey, iGCMDefaultIV, gcmDefaultCiphertext,
        gcmDefaultPlaintext, gcmDefaultTag, sizeof(iGCMDefaultIV),
        sizeof(gcmDefaultCiphertext), sizeof(gcmDefaultPlaintext),
        sizeof(gcmDefaultTag), 1, 1, 0
    },
    {
        "aes-128-cfb", kCFBDefaultKey, iCFBIV, cfbCiphertext,
        cfbPlaintext, NULL, 0, sizeof(cfbCiphertext), sizeof(cfbPlaintext),
        0, 0, 1, 0
    },
    {
        "aes-256-gcm", kGCMDefaultKey, iGCMDefaultIV, gcmDefaultCiphertext,
        gcmDefaultPlaintext, gcmDefaultTag, sizeof(iGCMDefaultIV),
        sizeof(gcmDefaultCiphertext), sizeof(gcmDefaultPlaintext),
        sizeof(gcmDefaultTag), 0, 1, 0
    }
};

/* use same key, iv and plaintext for cfb and ofb */
static const EVP_INIT_TEST_st evp_reinit_tests[] = {
    {
        "aes-128-cfb", kCFBDefaultKey, iCFBIV, cfbPlaintext_partial,
        cfbCiphertext_partial, NULL, 0, sizeof(cfbPlaintext_partial),
        sizeof(cfbCiphertext_partial), 0, 0, 1, 0
    },
    {
        "aes-128-cfb", kCFBDefaultKey, iCFBIV, cfbCiphertext_partial,
        cfbPlaintext_partial, NULL, 0, sizeof(cfbCiphertext_partial),
        sizeof(cfbPlaintext_partial), 0, 0, 0, 0
    },
    {
        "aes-128-ofb", kCFBDefaultKey, iCFBIV, cfbPlaintext_partial,
        ofbCiphertext_partial, NULL, 0, sizeof(cfbPlaintext_partial),
        sizeof(ofbCiphertext_partial), 0, 0, 1, 0
    },
    {
        "aes-128-ofb", kCFBDefaultKey, iCFBIV, ofbCiphertext_partial,
        cfbPlaintext_partial, NULL, 0, sizeof(ofbCiphertext_partial),
        sizeof(cfbPlaintext_partial), 0, 0, 0, 0
    },
};

static int evp_init_seq_set_iv(EVP_CIPHER_CTX *ctx, const EVP_INIT_TEST_st *t)
{
    int res = 0;

    if (t->ivlen != 0) {
        if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, t->ivlen, NULL), 0))
            goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, NULL, t->iv, -1)))
        goto err;
    res = 1;
 err:
    return res;
}

/*
 * Test step-wise cipher initialization via EVP_CipherInit_ex where the
 * arguments are given one at a time and a final adjustment to the enc
 * parameter sets the correct operation.
 */
static int test_evp_init_seq(int idx)
{
    int outlen1, outlen2;
    int testresult = 0;
    unsigned char outbuf[1024];
    unsigned char tag[16];
    const EVP_INIT_TEST_st *t = &evp_init_tests[idx];
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *type = NULL;
    size_t taglen = sizeof(tag);
    char *errmsg = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        errmsg = "CTX_ALLOC";
        goto err;
    }
    if (!TEST_ptr(type = EVP_CIPHER_fetch(testctx, t->cipher, testpropq))) {
        errmsg = "CIPHER_FETCH";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, t->initenc))) {
        errmsg = "EMPTY_ENC_INIT";
        goto err;
    }
    if (!TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))) {
        errmsg = "PADDING";
        goto err;
    }
    if (t->keyfirst && !TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, t->key, NULL, -1))) {
        errmsg = "KEY_INIT (before iv)";
        goto err;
    }
    if (!evp_init_seq_set_iv(ctx, t)) {
        errmsg = "IV_INIT";
        goto err;
    }
    if (t->keyfirst == 0 &&  !TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, t->key, NULL, -1))) {
        errmsg = "KEY_INIT (after iv)";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, NULL, NULL, t->finalenc))) {
        errmsg = "FINAL_ENC_INIT";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen1, t->input, t->inlen))) {
        errmsg = "CIPHER_UPDATE";
        goto err;
    }
    if (t->finalenc == 0 && t->tag != NULL) {
        /* Set expected tag */
        if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                           t->taglen, (void *)t->tag), 0)) {
            errmsg = "SET_TAG";
            goto err;
        }
    }
    if (!TEST_true(EVP_CipherFinal_ex(ctx, outbuf + outlen1, &outlen2))) {
        errmsg = "CIPHER_FINAL";
        goto err;
    }
    if (!TEST_mem_eq(t->expected, t->expectedlen, outbuf, outlen1 + outlen2)) {
        errmsg = "WRONG_RESULT";
        goto err;
    }
    if (t->finalenc != 0 && t->tag != NULL) {
        if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag), 0)) {
            errmsg = "GET_TAG";
            goto err;
        }
        if (!TEST_mem_eq(t->tag, t->taglen, tag, taglen)) {
            errmsg = "TAG_ERROR";
            goto err;
        }
    }
    testresult = 1;
 err:
    if (errmsg != NULL)
        TEST_info("evp_init_test %d: %s", idx, errmsg);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(type);
    return testresult;
}

/*
 * Test re-initialization of cipher context without changing key or iv.
 * The result of both iteration should be the same.
 */
static int test_evp_reinit_seq(int idx)
{
    int outlen1, outlen2, outlen_final;
    int testresult = 0;
    unsigned char outbuf1[1024];
    unsigned char outbuf2[1024];
    const EVP_INIT_TEST_st *t = &evp_reinit_tests[idx];
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *type = NULL;

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_ptr(type = EVP_CIPHER_fetch(testctx, t->cipher, testpropq))
            /* setup cipher context */
            || !TEST_true(EVP_CipherInit_ex2(ctx, type, t->key, t->iv, t->initenc, NULL))
            /* first iteration */
            || !TEST_true(EVP_CipherUpdate(ctx, outbuf1, &outlen1, t->input, t->inlen))
            || !TEST_true(EVP_CipherFinal_ex(ctx, outbuf1, &outlen_final))
            /* check test results iteration 1 */
            || !TEST_mem_eq(t->expected, t->expectedlen, outbuf1, outlen1 + outlen_final)
            /* now re-init the context (same cipher, key and iv) */
            || !TEST_true(EVP_CipherInit_ex2(ctx, NULL, NULL, NULL, -1, NULL))
            /* second iteration */
            || !TEST_true(EVP_CipherUpdate(ctx, outbuf2, &outlen2, t->input, t->inlen))
            || !TEST_true(EVP_CipherFinal_ex(ctx, outbuf2, &outlen_final))
            /* check test results iteration 2 */
            || !TEST_mem_eq(t->expected, t->expectedlen, outbuf2, outlen2 + outlen_final))
        goto err;
    testresult = 1;
 err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(type);
    return testresult;
}

typedef struct {
    const unsigned char *input;
    const unsigned char *expected;
    size_t inlen;
    size_t expectedlen;
    int enc;
} EVP_RESET_TEST_st;

static const EVP_RESET_TEST_st evp_reset_tests[] = {
    {
        cfbPlaintext, cfbCiphertext,
        sizeof(cfbPlaintext), sizeof(cfbCiphertext), 1
    },
    {
        cfbCiphertext, cfbPlaintext,
        sizeof(cfbCiphertext), sizeof(cfbPlaintext), 0
    }
};

/*
 * Test a reset of a cipher via EVP_CipherInit_ex after the cipher has already
 * been used.
 */
static int test_evp_reset(int idx)
{
    const EVP_RESET_TEST_st *t = &evp_reset_tests[idx];
    int outlen1, outlen2;
    int testresult = 0;
    unsigned char outbuf[1024];
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *type = NULL;
    char *errmsg = NULL;

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())) {
        errmsg = "CTX_ALLOC";
        goto err;
    }
    if (!TEST_ptr(type = EVP_CIPHER_fetch(testctx, "aes-128-cfb", testpropq))) {
        errmsg = "CIPHER_FETCH";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, type, NULL, kCFBDefaultKey, iCFBIV, t->enc))) {
        errmsg = "CIPHER_INIT";
        goto err;
    }
    if (!TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))) {
        errmsg = "PADDING";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen1, t->input, t->inlen))) {
        errmsg = "CIPHER_UPDATE";
        goto err;
    }
    if (!TEST_true(EVP_CipherFinal_ex(ctx, outbuf + outlen1, &outlen2))) {
        errmsg = "CIPHER_FINAL";
        goto err;
    }
    if (!TEST_mem_eq(t->expected, t->expectedlen, outbuf, outlen1 + outlen2)) {
        errmsg = "WRONG_RESULT";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, NULL, NULL, -1))) {
        errmsg = "CIPHER_REINIT";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen1, t->input, t->inlen))) {
        errmsg = "CIPHER_UPDATE (reinit)";
        goto err;
    }
    if (!TEST_true(EVP_CipherFinal_ex(ctx, outbuf + outlen1, &outlen2))) {
        errmsg = "CIPHER_FINAL (reinit)";
        goto err;
    }
    if (!TEST_mem_eq(t->expected, t->expectedlen, outbuf, outlen1 + outlen2)) {
        errmsg = "WRONG_RESULT (reinit)";
        goto err;
    }
    testresult = 1;
 err:
    if (errmsg != NULL)
        TEST_info("test_evp_reset %d: %s", idx, errmsg);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(type);
    return testresult;
}

typedef struct {
    const char *cipher;
    int enc;
} EVP_UPDATED_IV_TEST_st;

static const EVP_UPDATED_IV_TEST_st evp_updated_iv_tests[] = {
    {
        "aes-128-cfb", 1
    },
    {
        "aes-128-cfb", 0
    },
    {
        "aes-128-cfb1", 1
    },
    {
        "aes-128-cfb1", 0
    },
    {
        "aes-128-cfb8", 1
    },
    {
        "aes-128-cfb8", 0
    },
    {
        "aes-128-ofb", 1
    },
    {
        "aes-128-ofb", 0
    },
    {
        "aes-128-ctr", 1
    },
    {
        "aes-128-ctr", 0
    },
    {
        "aes-128-cbc", 1
    },
    {
        "aes-128-cbc", 0
    }
};

/*
 * Test that the IV in the context is updated during a crypto operation for CFB
 * and OFB.
 */
static int test_evp_updated_iv(int idx)
{
    const EVP_UPDATED_IV_TEST_st *t = &evp_updated_iv_tests[idx];
    int outlen1, outlen2;
    int testresult = 0;
    unsigned char outbuf[1024];
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *type = NULL;
    unsigned char updated_iv[EVP_MAX_IV_LENGTH];
    int iv_len;
    char *errmsg = NULL;

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())) {
        errmsg = "CTX_ALLOC";
        goto err;
    }
    if ((type = EVP_CIPHER_fetch(testctx, t->cipher, testpropq)) == NULL) {
        TEST_info("cipher %s not supported, skipping", t->cipher);
        goto ok;
    }

    if (!TEST_true(EVP_CipherInit_ex(ctx, type, NULL, kCFBDefaultKey, iCFBIV, t->enc))) {
        errmsg = "CIPHER_INIT";
        goto err;
    }
    if (!TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))) {
        errmsg = "PADDING";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen1, cfbPlaintext, sizeof(cfbPlaintext)))) {
        errmsg = "CIPHER_UPDATE";
        goto err;
    }
    if (!TEST_true(EVP_CIPHER_CTX_get_updated_iv(ctx, updated_iv, sizeof(updated_iv)))) {
        errmsg = "CIPHER_CTX_GET_UPDATED_IV";
        goto err;
    }
    iv_len = EVP_CIPHER_CTX_get_iv_length(ctx);
    if (!TEST_int_ge(iv_len,0)) {
        errmsg = "CIPHER_CTX_GET_IV_LEN";
        goto err;
    }
    if (!TEST_mem_ne(iCFBIV, sizeof(iCFBIV), updated_iv, iv_len)) {
        errmsg = "IV_NOT_UPDATED";
        goto err;
    }
    if (!TEST_true(EVP_CipherFinal_ex(ctx, outbuf + outlen1, &outlen2))) {
        errmsg = "CIPHER_FINAL";
        goto err;
    }
 ok:
    testresult = 1;
 err:
    if (errmsg != NULL)
        TEST_info("test_evp_updated_iv %d: %s", idx, errmsg);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(type);
    return testresult;
}

typedef struct {
    const unsigned char *iv1;
    const unsigned char *iv2;
    const unsigned char *expected1;
    const unsigned char *expected2;
    const unsigned char *tag1;
    const unsigned char *tag2;
    size_t ivlen1;
    size_t ivlen2;
    size_t expectedlen1;
    size_t expectedlen2;
} TEST_GCM_IV_REINIT_st;

static const TEST_GCM_IV_REINIT_st gcm_reinit_tests[] = {
    {
        iGCMResetIV1, iGCMResetIV2, gcmResetCiphertext1, gcmResetCiphertext2,
        gcmResetTag1, gcmResetTag2, sizeof(iGCMResetIV1), sizeof(iGCMResetIV2),
        sizeof(gcmResetCiphertext1), sizeof(gcmResetCiphertext2)
    },
    {
        iGCMResetIV2, iGCMResetIV1, gcmResetCiphertext2, gcmResetCiphertext1,
        gcmResetTag2, gcmResetTag1, sizeof(iGCMResetIV2), sizeof(iGCMResetIV1),
        sizeof(gcmResetCiphertext2), sizeof(gcmResetCiphertext1)
    }
};

static int test_gcm_reinit(int idx)
{
    int outlen1, outlen2, outlen3;
    int testresult = 0;
    unsigned char outbuf[1024];
    unsigned char tag[16];
    const TEST_GCM_IV_REINIT_st *t = &gcm_reinit_tests[idx];
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *type = NULL;
    size_t taglen = sizeof(tag);
    char *errmsg = NULL;

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())) {
        errmsg = "CTX_ALLOC";
        goto err;
    }
    if (!TEST_ptr(type = EVP_CIPHER_fetch(testctx, "aes-256-gcm", testpropq))) {
        errmsg = "CIPHER_FETCH";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 1))) {
        errmsg = "ENC_INIT";
        goto err;
    }
    if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, t->ivlen1, NULL), 0)) {
        errmsg = "SET_IVLEN1";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, kGCMResetKey, t->iv1, 1))) {
        errmsg = "SET_IV1";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, NULL, &outlen3, gcmAAD, sizeof(gcmAAD)))) {
        errmsg = "AAD1";
        goto err;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen1, gcmResetPlaintext,
                                    sizeof(gcmResetPlaintext)))) {
        errmsg = "CIPHER_UPDATE1";
        goto err;
    }
    if (!TEST_true(EVP_CipherFinal_ex(ctx, outbuf + outlen1, &outlen2))) {
        errmsg = "CIPHER_FINAL1";
        goto err;
    }
    if (!TEST_mem_eq(t->expected1, t->expectedlen1, outbuf, outlen1 + outlen2)) {
        errmsg = "WRONG_RESULT1";
        goto err;
    }
    if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag), 0)) {
        errmsg = "GET_TAG1";
        goto err;
    }
    if (!TEST_mem_eq(t->tag1, taglen, tag, taglen)) {
        errmsg = "TAG_ERROR1";
        goto err;
    }
    /* Now reinit */
    if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, t->ivlen2, NULL), 0)) {
        errmsg = "SET_IVLEN2";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, NULL, t->iv2, -1))) {
        errmsg = "SET_IV2";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, NULL, &outlen3, gcmAAD, sizeof(gcmAAD)))) {
        errmsg = "AAD2";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen1, gcmResetPlaintext,
                                    sizeof(gcmResetPlaintext)))) {
        errmsg = "CIPHER_UPDATE2";
        goto err;
    }
    if (!TEST_true(EVP_CipherFinal_ex(ctx, outbuf + outlen1, &outlen2))) {
        errmsg = "CIPHER_FINAL2";
        goto err;
    }
    if (!TEST_mem_eq(t->expected2, t->expectedlen2, outbuf, outlen1 + outlen2)) {
        errmsg = "WRONG_RESULT2";
        goto err;
    }
    if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag), 0)) {
        errmsg = "GET_TAG2";
        goto err;
    }
    if (!TEST_mem_eq(t->tag2, taglen, tag, taglen)) {
        errmsg = "TAG_ERROR2";
        goto err;
    }
    testresult = 1;
 err:
    if (errmsg != NULL)
        TEST_info("evp_init_test %d: %s", idx, errmsg);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(type);
    return testresult;
}

static const char *ivlen_change_ciphers[] = {
    "AES-256-GCM",
#ifndef OPENSSL_NO_OCB
    "AES-256-OCB",
#endif
    "AES-256-CCM"
};

/* Negative test for ivlen change after iv being set */
static int test_ivlen_change(int idx)
{
    int outlen;
    int res = 0;
    unsigned char outbuf[1024];
    static const unsigned char iv[] = {
         0x57, 0x71, 0x7d, 0xad, 0xdb, 0x9b, 0x98, 0x82,
         0x5a, 0x55, 0x91, 0x81, 0x42, 0xa8, 0x89, 0x34
    };
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *ciph = NULL;
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };
    size_t ivlen = 13; /* non-default IV length */

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
        goto err;

    if (!TEST_ptr(ciph = EVP_CIPHER_fetch(testctx, ivlen_change_ciphers[idx],
                                          testpropq)))
        goto err;

    if (!TEST_true(EVP_CipherInit_ex(ctx, ciph, NULL, kGCMDefaultKey, iv, 1)))
        goto err;

    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen, gcmDefaultPlaintext,
                                    sizeof(gcmDefaultPlaintext))))
        goto err;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &ivlen);
    if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx, params)))
        goto err;

    ERR_set_mark();
    if (!TEST_false(EVP_CipherUpdate(ctx, outbuf, &outlen, gcmDefaultPlaintext,
                                    sizeof(gcmDefaultPlaintext)))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();

    res = 1;
 err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(ciph);
    return res;
}

static const char *keylen_change_ciphers[] = {
#ifndef OPENSSL_NO_BF
    "BF-ECB",
#endif
#ifndef OPENSSL_NO_CAST
    "CAST5-ECB",
#endif
#ifndef OPENSSL_NO_RC2
    "RC2-ECB",
#endif
#ifndef OPENSSL_NO_RC4
    "RC4",
#endif
#ifndef OPENSSL_NO_RC5
    "RC5-ECB",
#endif
    NULL
};

/* Negative test for keylen change after key was set */
static int test_keylen_change(int idx)
{
    int outlen;
    int res = 0;
    unsigned char outbuf[1024];
    static const unsigned char key[] = {
         0x57, 0x71, 0x7d, 0xad, 0xdb, 0x9b, 0x98, 0x82,
         0x5a, 0x55, 0x91, 0x81, 0x42, 0xa8, 0x89, 0x34
    };
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *ciph = NULL;
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };
    size_t keylen = 12; /* non-default key length */

    if (lgcyprov == NULL)
        return TEST_skip("Test requires legacy provider to be loaded");

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
        goto err;

    if (!TEST_ptr(ciph = EVP_CIPHER_fetch(testctx, keylen_change_ciphers[idx],
                                          testpropq)))
        goto err;

    if (!TEST_true(EVP_CipherInit_ex(ctx, ciph, NULL, key, NULL, 1)))
        goto err;

    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen, gcmDefaultPlaintext,
                                    sizeof(gcmDefaultPlaintext))))
        goto err;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN,
                                            &keylen);
    if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx, params)))
        goto err;

    ERR_set_mark();
    if (!TEST_false(EVP_CipherUpdate(ctx, outbuf, &outlen, gcmDefaultPlaintext,
                                    sizeof(gcmDefaultPlaintext)))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();

    res = 1;
 err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(ciph);
    return res;
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
static EVP_PKEY_METHOD *custom_pmeth =  NULL;
static const EVP_PKEY_METHOD *orig_pmeth = NULL;

# define EVP_PKEY_CTRL_MY_COMMAND 9999

static int custom_pmeth_init(EVP_PKEY_CTX *ctx)
{
    int (*pinit)(EVP_PKEY_CTX *ctx);

    EVP_PKEY_meth_get_init(orig_pmeth, &pinit);
    return pinit(ctx);
}

static void custom_pmeth_cleanup(EVP_PKEY_CTX *ctx)
{
    void (*pcleanup)(EVP_PKEY_CTX *ctx);

    EVP_PKEY_meth_get_cleanup(orig_pmeth, &pcleanup);
    pcleanup(ctx);
}

static int custom_pmeth_sign(EVP_PKEY_CTX *ctx, unsigned char *out,
                             size_t *outlen, const unsigned char *in,
                             size_t inlen)
{
    int (*psign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);

    EVP_PKEY_meth_get_sign(orig_pmeth, NULL, &psign);
    return psign(ctx, out, outlen, in, inlen);
}

static int custom_pmeth_digestsign(EVP_MD_CTX *ctx, unsigned char *sig,
                                   size_t *siglen, const unsigned char *tbs,
                                   size_t tbslen)
{
    int (*pdigestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                       const unsigned char *tbs, size_t tbslen);

    EVP_PKEY_meth_get_digestsign(orig_pmeth, &pdigestsign);
    return pdigestsign(ctx, sig, siglen, tbs, tbslen);
}

static int custom_pmeth_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                               size_t *keylen)
{
    int (*pderive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

    EVP_PKEY_meth_get_derive(orig_pmeth, NULL, &pderive);
    return pderive(ctx, key, keylen);
}

static int custom_pmeth_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
{
    int (*pcopy)(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src);

    EVP_PKEY_meth_get_copy(orig_pmeth, &pcopy);
    return pcopy(dst, src);
}

static int ctrl_called;

static int custom_pmeth_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    int (*pctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);

    EVP_PKEY_meth_get_ctrl(orig_pmeth, &pctrl, NULL);

    if (type == EVP_PKEY_CTRL_MY_COMMAND) {
        ctrl_called = 1;
        return 1;
    }

    return pctrl(ctx, type, p1, p2);
}

static int test_custom_pmeth(int idx)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int id, orig_id, orig_flags;
    int testresult = 0;
    size_t reslen;
    unsigned char *res = NULL;
    unsigned char msg[] = { 'H', 'e', 'l', 'l', 'o' };
    const EVP_MD *md = EVP_sha256();
    int doderive = 0;

    ctrl_called = 0;

    /* We call deprecated APIs so this test doesn't support a custom libctx */
    if (testctx != NULL)
        return 1;

    switch (idx) {
    case 0:
    case 6:
        id = EVP_PKEY_RSA;
        pkey = load_example_rsa_key();
        break;
    case 1:
    case 7:
# ifndef OPENSSL_NO_DSA
        id = EVP_PKEY_DSA;
        pkey = load_example_dsa_key();
        break;
# else
        return 1;
# endif
    case 2:
    case 8:
# ifndef OPENSSL_NO_EC
        id = EVP_PKEY_EC;
        pkey = load_example_ec_key();
        break;
# else
        return 1;
# endif
    case 3:
    case 9:
# ifndef OPENSSL_NO_ECX
        id = EVP_PKEY_ED25519;
        md = NULL;
        pkey = load_example_ed25519_key();
        break;
# else
        return 1;
# endif
    case 4:
    case 10:
# ifndef OPENSSL_NO_DH
        id = EVP_PKEY_DH;
        doderive = 1;
        pkey = load_example_dh_key();
        break;
# else
        return 1;
# endif
    case 5:
    case 11:
# ifndef OPENSSL_NO_ECX
        id = EVP_PKEY_X25519;
        doderive = 1;
        pkey = load_example_x25519_key();
        break;
# else
        return 1;
# endif
    default:
        TEST_error("Should not happen");
        goto err;
    }

    if (!TEST_ptr(pkey))
        goto err;

    if (idx < 6) {
        if (!TEST_true(evp_pkey_is_provided(pkey)))
            goto err;
    } else {
        EVP_PKEY *tmp = pkey;

        /* Convert to a legacy key */
        pkey = EVP_PKEY_new();
        if (!TEST_ptr(pkey)) {
            pkey = tmp;
            goto err;
        }
        if (!TEST_true(evp_pkey_copy_downgraded(&pkey, tmp))) {
            EVP_PKEY_free(tmp);
            goto err;
        }
        EVP_PKEY_free(tmp);
        if (!TEST_true(evp_pkey_is_legacy(pkey)))
            goto err;
    }

    if (!TEST_ptr(orig_pmeth = EVP_PKEY_meth_find(id))
            || !TEST_ptr(pkey))
        goto err;

    EVP_PKEY_meth_get0_info(&orig_id, &orig_flags, orig_pmeth);
    if (!TEST_int_eq(orig_id, id)
            || !TEST_ptr(custom_pmeth = EVP_PKEY_meth_new(id, orig_flags)))
        goto err;

    if (id == EVP_PKEY_ED25519) {
        EVP_PKEY_meth_set_digestsign(custom_pmeth, custom_pmeth_digestsign);
    } if (id == EVP_PKEY_DH || id == EVP_PKEY_X25519) {
        EVP_PKEY_meth_set_derive(custom_pmeth, NULL, custom_pmeth_derive);
    } else {
        EVP_PKEY_meth_set_sign(custom_pmeth, NULL, custom_pmeth_sign);
    }
    if (id != EVP_PKEY_ED25519 && id != EVP_PKEY_X25519) {
        EVP_PKEY_meth_set_init(custom_pmeth, custom_pmeth_init);
        EVP_PKEY_meth_set_cleanup(custom_pmeth, custom_pmeth_cleanup);
        EVP_PKEY_meth_set_copy(custom_pmeth, custom_pmeth_copy);
    }
    EVP_PKEY_meth_set_ctrl(custom_pmeth, custom_pmeth_ctrl, NULL);
    if (!TEST_true(EVP_PKEY_meth_add0(custom_pmeth)))
        goto err;

    if (doderive) {
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!TEST_ptr(pctx)
                || !TEST_int_eq(EVP_PKEY_derive_init(pctx), 1)
                || !TEST_int_ge(EVP_PKEY_CTX_ctrl(pctx, -1, -1,
                                                EVP_PKEY_CTRL_MY_COMMAND, 0, NULL),
                                1)
                || !TEST_int_eq(ctrl_called, 1)
                || !TEST_int_ge(EVP_PKEY_derive_set_peer(pctx, pkey), 1)
                || !TEST_int_ge(EVP_PKEY_derive(pctx, NULL, &reslen), 1)
                || !TEST_ptr(res = OPENSSL_malloc(reslen))
                || !TEST_int_ge(EVP_PKEY_derive(pctx, res, &reslen), 1))
            goto err;
    } else {
        ctx = EVP_MD_CTX_new();
        reslen = EVP_PKEY_size(pkey);
        res = OPENSSL_malloc(reslen);
        if (!TEST_ptr(ctx)
                || !TEST_ptr(res)
                || !TEST_true(EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey))
                || !TEST_int_ge(EVP_PKEY_CTX_ctrl(pctx, -1, -1,
                                                EVP_PKEY_CTRL_MY_COMMAND, 0, NULL),
                                1)
                || !TEST_int_eq(ctrl_called, 1))
            goto err;

        if (id == EVP_PKEY_ED25519) {
            if (!TEST_true(EVP_DigestSign(ctx, res, &reslen, msg, sizeof(msg))))
                goto err;
        } else {
            if (!TEST_true(EVP_DigestUpdate(ctx, msg, sizeof(msg)))
                    || !TEST_true(EVP_DigestSignFinal(ctx, res, &reslen)))
                goto err;
        }
    }

    testresult = 1;
 err:
    OPENSSL_free(res);
    EVP_MD_CTX_free(ctx);
    if (doderive)
        EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_meth_remove(custom_pmeth);
    EVP_PKEY_meth_free(custom_pmeth);
    custom_pmeth = NULL;
    return testresult;
}

static int test_evp_md_cipher_meth(void)
{
    EVP_MD *md = EVP_MD_meth_dup(EVP_sha256());
    EVP_CIPHER *ciph = EVP_CIPHER_meth_dup(EVP_aes_128_cbc());
    int testresult = 0;

    if (!TEST_ptr(md) || !TEST_ptr(ciph))
        goto err;

    testresult = 1;

 err:
    EVP_MD_meth_free(md);
    EVP_CIPHER_meth_free(ciph);

    return testresult;
}

typedef struct {
        int data;
} custom_dgst_ctx;

static int custom_md_init_called = 0;
static int custom_md_cleanup_called = 0;

static int custom_md_init(EVP_MD_CTX *ctx)
{
    custom_dgst_ctx *p = EVP_MD_CTX_md_data(ctx);

    if (p == NULL)
        return 0;

    custom_md_init_called++;
    return 1;
}

static int custom_md_cleanup(EVP_MD_CTX *ctx)
{
    custom_dgst_ctx *p = EVP_MD_CTX_md_data(ctx);

    if (p == NULL)
        /* Nothing to do */
        return 1;

    custom_md_cleanup_called++;
    return 1;
}

static int test_custom_md_meth(void)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_MD *tmp = NULL;
    char mess[] = "Test Message\n";
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    int testresult = 0;
    int nid;

    /*
     * We are testing deprecated functions. We don't support a non-default
     * library context in this test.
     */
    if (testctx != NULL)
        return TEST_skip("Non-default libctx");

    custom_md_init_called = custom_md_cleanup_called = 0;

    nid = OBJ_create("1.3.6.1.4.1.16604.998866.1", "custom-md", "custom-md");
    if (!TEST_int_ne(nid, NID_undef))
        goto err;
    tmp = EVP_MD_meth_new(nid, NID_undef);
    if (!TEST_ptr(tmp))
        goto err;

    if (!TEST_true(EVP_MD_meth_set_init(tmp, custom_md_init))
            || !TEST_true(EVP_MD_meth_set_cleanup(tmp, custom_md_cleanup))
            || !TEST_true(EVP_MD_meth_set_app_datasize(tmp,
                                                       sizeof(custom_dgst_ctx))))
        goto err;

    mdctx = EVP_MD_CTX_new();
    if (!TEST_ptr(mdctx)
               /*
                * Initing our custom md and then initing another md should
                * result in the init and cleanup functions of the custom md
                * being called.
                */
            || !TEST_true(EVP_DigestInit_ex(mdctx, tmp, NULL))
            || !TEST_true(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
            || !TEST_true(EVP_DigestUpdate(mdctx, mess, strlen(mess)))
            || !TEST_true(EVP_DigestFinal_ex(mdctx, md_value, &md_len))
            || !TEST_int_eq(custom_md_init_called, 1)
            || !TEST_int_eq(custom_md_cleanup_called, 1))
        goto err;

    testresult = 1;
 err:
    EVP_MD_CTX_free(mdctx);
    EVP_MD_meth_free(tmp);
    return testresult;
}

typedef struct {
        int data;
} custom_ciph_ctx;

static int custom_ciph_init_called = 0;
static int custom_ciph_cleanup_called = 0;

static int custom_ciph_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    custom_ciph_ctx *p = EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (p == NULL)
        return 0;

    custom_ciph_init_called++;
    return 1;
}

static int custom_ciph_cleanup(EVP_CIPHER_CTX *ctx)
{
    custom_ciph_ctx *p = EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (p == NULL)
        /* Nothing to do */
        return 1;

    custom_ciph_cleanup_called++;
    return 1;
}

static int test_custom_ciph_meth(void)
{
    EVP_CIPHER_CTX *ciphctx = NULL;
    EVP_CIPHER *tmp = NULL;
    int testresult = 0;
    int nid;

    /*
     * We are testing deprecated functions. We don't support a non-default
     * library context in this test.
     */
    if (testctx != NULL)
        return TEST_skip("Non-default libctx");

    custom_ciph_init_called = custom_ciph_cleanup_called = 0;

    nid = OBJ_create("1.3.6.1.4.1.16604.998866.2", "custom-ciph", "custom-ciph");
    if (!TEST_int_ne(nid, NID_undef))
        goto err;
    tmp = EVP_CIPHER_meth_new(nid, 16, 16);
    if (!TEST_ptr(tmp))
        goto err;

    if (!TEST_true(EVP_CIPHER_meth_set_init(tmp, custom_ciph_init))
            || !TEST_true(EVP_CIPHER_meth_set_flags(tmp, EVP_CIPH_ALWAYS_CALL_INIT))
            || !TEST_true(EVP_CIPHER_meth_set_cleanup(tmp, custom_ciph_cleanup))
            || !TEST_true(EVP_CIPHER_meth_set_impl_ctx_size(tmp,
                                                            sizeof(custom_ciph_ctx))))
        goto err;

    ciphctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ciphctx)
            /*
             * Initing our custom cipher and then initing another cipher
             * should result in the init and cleanup functions of the custom
             * cipher being called.
             */
            || !TEST_true(EVP_CipherInit_ex(ciphctx, tmp, NULL, NULL, NULL, 1))
            || !TEST_true(EVP_CipherInit_ex(ciphctx, EVP_aes_128_cbc(), NULL,
                                            NULL, NULL, 1))
            || !TEST_int_eq(custom_ciph_init_called, 1)
            || !TEST_int_eq(custom_ciph_cleanup_called, 1))
        goto err;

    testresult = 1;
 err:
    EVP_CIPHER_CTX_free(ciphctx);
    EVP_CIPHER_meth_free(tmp);
    return testresult;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
/* Test we can create a signature keys with an associated ENGINE */
static int test_signatures_with_engine(int tst)
{
    ENGINE *e;
    const char *engine_id = "dasync";
    EVP_PKEY *pkey = NULL;
    const unsigned char badcmackey[] = { 0x00, 0x01 };
    const unsigned char cmackey[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char ed25519key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    int testresult = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *mac = NULL;
    size_t maclen = 0;
    int ret;

#  ifdef OPENSSL_NO_CMAC
    /* Skip CMAC tests in a no-cmac build */
    if (tst <= 1)
        return 1;
#  endif
#  ifdef OPENSSL_NO_ECX
    /* Skip ECX tests in a no-ecx build */
    if (tst == 2)
        return 1;
#  endif

    if (!TEST_ptr(e = ENGINE_by_id(engine_id)))
        return 0;

    if (!TEST_true(ENGINE_init(e))) {
        ENGINE_free(e);
        return 0;
    }

    switch (tst) {
    case 0:
        pkey = EVP_PKEY_new_CMAC_key(e, cmackey, sizeof(cmackey),
                                     EVP_aes_128_cbc());
        break;
    case 1:
        pkey = EVP_PKEY_new_CMAC_key(e, badcmackey, sizeof(badcmackey),
                                     EVP_aes_128_cbc());
        break;
    case 2:
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, e, ed25519key,
                                            sizeof(ed25519key));
        break;
    default:
        TEST_error("Invalid test case");
        goto err;
    }
    if (!TEST_ptr(pkey))
        goto err;

    if (!TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    ret = EVP_DigestSignInit(ctx, NULL, tst == 2 ? NULL : EVP_sha256(), NULL,
                             pkey);
    if (tst == 0) {
        if (!TEST_true(ret))
            goto err;

        if (!TEST_true(EVP_DigestSignUpdate(ctx, msg, sizeof(msg)))
                || !TEST_true(EVP_DigestSignFinal(ctx, NULL, &maclen)))
            goto err;

        if (!TEST_ptr(mac = OPENSSL_malloc(maclen)))
            goto err;

        if (!TEST_true(EVP_DigestSignFinal(ctx, mac, &maclen)))
            goto err;
    } else {
        /* We used a bad key. We expect a failure here */
        if (!TEST_false(ret))
            goto err;
    }

    testresult = 1;
 err:
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(mac);
    EVP_PKEY_free(pkey);
    ENGINE_finish(e);
    ENGINE_free(e);

    return testresult;
}

static int test_cipher_with_engine(void)
{
    ENGINE *e;
    const char *engine_id = "dasync";
    const unsigned char keyiv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    int testresult = 0;
    EVP_CIPHER_CTX *ctx = NULL, *ctx2 = NULL;
    unsigned char buf[AES_BLOCK_SIZE];
    int len = 0;

    if (!TEST_ptr(e = ENGINE_by_id(engine_id)))
        return 0;

    if (!TEST_true(ENGINE_init(e))) {
        ENGINE_free(e);
        return 0;
    }

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_ptr(ctx2 = EVP_CIPHER_CTX_new()))
        goto err;

    if (!TEST_true(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), e, keyiv, keyiv)))
        goto err;

    /* Copy the ctx, and complete the operation with the new ctx */
    if (!TEST_true(EVP_CIPHER_CTX_copy(ctx2, ctx)))
        goto err;

    if (!TEST_true(EVP_EncryptUpdate(ctx2, buf, &len, msg, sizeof(msg)))
            || !TEST_true(EVP_EncryptFinal_ex(ctx2, buf + len, &len)))
        goto err;

    testresult = 1;
 err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(ctx2);
    ENGINE_finish(e);
    ENGINE_free(e);

    return testresult;
}
# endif /* OPENSSL_NO_DYNAMIC_ENGINE */
#endif /* OPENSSL_NO_DEPRECATED_3_0 */

#ifndef OPENSSL_NO_ECX
static int ecxnids[] = {
    NID_X25519,
    NID_X448,
    NID_ED25519,
    NID_ED448
};

/* Test that creating ECX keys with a short private key fails as expected */
static int test_ecx_short_keys(int tst)
{
    unsigned char ecxkeydata = 1;
    EVP_PKEY *pkey;


    pkey = EVP_PKEY_new_raw_private_key_ex(testctx, OBJ_nid2sn(ecxnids[tst]),
                                           NULL, &ecxkeydata, 1);
    if (!TEST_ptr_null(pkey)) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_EC

/* HPKETESTSTART */
# define OSSL_HPKE_TEST_true(__x__, __str__) TEST_int_eq(__x__, 1)
# define OSSL_HPKE_TEST_false(__x__, __str__) TEST_false(__x__)

/*
 * Randomly toss a coin
 */
static unsigned char rb = 0;
#define COIN_IS_HEADS (RAND_bytes_ex(testctx, &rb, 1, 10) && rb % 2)

/* tables of HPKE modes and suite values */
static int hpke_mode_list[] = {
    OSSL_HPKE_MODE_BASE,
    OSSL_HPKE_MODE_PSK,
    OSSL_HPKE_MODE_AUTH,
    OSSL_HPKE_MODE_PSKAUTH
};
static uint16_t hpke_kem_list[] = {
    OSSL_HPKE_KEM_ID_P256,
    OSSL_HPKE_KEM_ID_P384,
    OSSL_HPKE_KEM_ID_P521,
    OSSL_HPKE_KEM_ID_25519,
    OSSL_HPKE_KEM_ID_448
};
static uint16_t hpke_kdf_list[] = {
    OSSL_HPKE_KDF_ID_HKDF_SHA256,
    OSSL_HPKE_KDF_ID_HKDF_SHA384,
    OSSL_HPKE_KDF_ID_HKDF_SHA512
};
static uint16_t hpke_aead_list[] = {
    OSSL_HPKE_AEAD_ID_AES_GCM_128,
    OSSL_HPKE_AEAD_ID_AES_GCM_256,
    OSSL_HPKE_AEAD_ID_CHACHA_POLY1305
};

/* we'll also test HPKE string to suite variations */
static char *suite_strs[] = {
    "P-256,hkdf-sha256,aes-128-gcm",
    "P-256,hkdf-sha256,aes-256-gcm",
    "P-256,hkdf-sha256,chacha20-poly1305",
    "P-256,hkdf-sha256,0x1",
    "P-256,hkdf-sha256,0x01",
    "P-256,hkdf-sha256,0x2",
    "P-256,hkdf-sha256,0x02",
    "P-256,hkdf-sha256,0x3",
    "P-256,hkdf-sha256,0x03",
    "P-256,hkdf-sha256,1",
    "P-256,hkdf-sha256,2",
    "P-256,hkdf-sha256,3",
    "P-256,hkdf-sha384,aes-128-gcm",
    "P-256,hkdf-sha384,aes-256-gcm",
    "P-256,hkdf-sha384,chacha20-poly1305",
    "P-256,hkdf-sha384,0x1",
    "P-256,hkdf-sha384,0x01",
    "P-256,hkdf-sha384,0x2",
    "P-256,hkdf-sha384,0x02",
    "P-256,hkdf-sha384,0x3",
    "P-256,hkdf-sha384,0x03",
    "P-256,hkdf-sha384,1",
    "P-256,hkdf-sha384,2",
    "P-256,hkdf-sha384,3",
    "P-256,hkdf-sha512,aes-128-gcm",
    "P-256,hkdf-sha512,aes-256-gcm",
    "P-256,hkdf-sha512,chacha20-poly1305",
    "P-256,hkdf-sha512,0x1",
    "P-256,hkdf-sha512,0x01",
    "P-256,hkdf-sha512,0x2",
    "P-256,hkdf-sha512,0x02",
    "P-256,hkdf-sha512,0x3",
    "P-256,hkdf-sha512,0x03",
    "P-256,hkdf-sha512,1",
    "P-256,hkdf-sha512,2",
    "P-256,hkdf-sha512,3",
    "P-256,0x1,aes-128-gcm",
    "P-256,0x1,aes-256-gcm",
    "P-256,0x1,chacha20-poly1305",
    "P-256,0x1,0x1",
    "P-256,0x1,0x01",
    "P-256,0x1,0x2",
    "P-256,0x1,0x02",
    "P-256,0x1,0x3",
    "P-256,0x1,0x03",
    "P-256,0x1,1",
    "P-256,0x1,2",
    "P-256,0x1,3",
    "P-256,0x01,aes-128-gcm",
    "P-256,0x01,aes-256-gcm",
    "P-256,0x01,chacha20-poly1305",
    "P-256,0x01,0x1",
    "P-256,0x01,0x01",
    "P-256,0x01,0x2",
    "P-256,0x01,0x02",
    "P-256,0x01,0x3",
    "P-256,0x01,0x03",
    "P-256,0x01,1",
    "P-256,0x01,2",
    "P-256,0x01,3",
    "P-256,0x2,aes-128-gcm",
    "P-256,0x2,aes-256-gcm",
    "P-256,0x2,chacha20-poly1305",
    "P-256,0x2,0x1",
    "P-256,0x2,0x01",
    "P-256,0x2,0x2",
    "P-256,0x2,0x02",
    "P-256,0x2,0x3",
    "P-256,0x2,0x03",
    "P-256,0x2,1",
    "P-256,0x2,2",
    "P-256,0x2,3",
    "P-256,0x02,aes-128-gcm",
    "P-256,0x02,aes-256-gcm",
    "P-256,0x02,chacha20-poly1305",
    "P-256,0x02,0x1",
    "P-256,0x02,0x01",
    "P-256,0x02,0x2",
    "P-256,0x02,0x02",
    "P-256,0x02,0x3",
    "P-256,0x02,0x03",
    "P-256,0x02,1",
    "P-256,0x02,2",
    "P-256,0x02,3",
    "P-256,0x3,aes-128-gcm",
    "P-256,0x3,aes-256-gcm",
    "P-256,0x3,chacha20-poly1305",
    "P-256,0x3,0x1",
    "P-256,0x3,0x01",
    "P-256,0x3,0x2",
    "P-256,0x3,0x02",
    "P-256,0x3,0x3",
    "P-256,0x3,0x03",
    "P-256,0x3,1",
    "P-256,0x3,2",
    "P-256,0x3,3",
    "P-256,0x03,aes-128-gcm",
    "P-256,0x03,aes-256-gcm",
    "P-256,0x03,chacha20-poly1305",
    "P-256,0x03,0x1",
    "P-256,0x03,0x01",
    "P-256,0x03,0x2",
    "P-256,0x03,0x02",
    "P-256,0x03,0x3",
    "P-256,0x03,0x03",
    "P-256,0x03,1",
    "P-256,0x03,2",
    "P-256,0x03,3",
    "P-256,1,aes-128-gcm",
    "P-256,1,aes-256-gcm",
    "P-256,1,chacha20-poly1305",
    "P-256,1,0x1",
    "P-256,1,0x01",
    "P-256,1,0x2",
    "P-256,1,0x02",
    "P-256,1,0x3",
    "P-256,1,0x03",
    "P-256,1,1",
    "P-256,1,2",
    "P-256,1,3",
    "P-256,2,aes-128-gcm",
    "P-256,2,aes-256-gcm",
    "P-256,2,chacha20-poly1305",
    "P-256,2,0x1",
    "P-256,2,0x01",
    "P-256,2,0x2",
    "P-256,2,0x02",
    "P-256,2,0x3",
    "P-256,2,0x03",
    "P-256,2,1",
    "P-256,2,2",
    "P-256,2,3",
    "P-256,3,aes-128-gcm",
    "P-256,3,aes-256-gcm",
    "P-256,3,chacha20-poly1305",
    "P-256,3,0x1",
    "P-256,3,0x01",
    "P-256,3,0x2",
    "P-256,3,0x02",
    "P-256,3,0x3",
    "P-256,3,0x03",
    "P-256,3,1",
    "P-256,3,2",
    "P-256,3,3",
    "P-384,hkdf-sha256,aes-128-gcm",
    "P-384,hkdf-sha256,aes-256-gcm",
    "P-384,hkdf-sha256,chacha20-poly1305",
    "P-384,hkdf-sha256,0x1",
    "P-384,hkdf-sha256,0x01",
    "P-384,hkdf-sha256,0x2",
    "P-384,hkdf-sha256,0x02",
    "P-384,hkdf-sha256,0x3",
    "P-384,hkdf-sha256,0x03",
    "P-384,hkdf-sha256,1",
    "P-384,hkdf-sha256,2",
    "P-384,hkdf-sha256,3",
    "P-384,hkdf-sha384,aes-128-gcm",
    "P-384,hkdf-sha384,aes-256-gcm",
    "P-384,hkdf-sha384,chacha20-poly1305",
    "P-384,hkdf-sha384,0x1",
    "P-384,hkdf-sha384,0x01",
    "P-384,hkdf-sha384,0x2",
    "P-384,hkdf-sha384,0x02",
    "P-384,hkdf-sha384,0x3",
    "P-384,hkdf-sha384,0x03",
    "P-384,hkdf-sha384,1",
    "P-384,hkdf-sha384,2",
    "P-384,hkdf-sha384,3",
    "P-384,hkdf-sha512,aes-128-gcm",
    "P-384,hkdf-sha512,aes-256-gcm",
    "P-384,hkdf-sha512,chacha20-poly1305",
    "P-384,hkdf-sha512,0x1",
    "P-384,hkdf-sha512,0x01",
    "P-384,hkdf-sha512,0x2",
    "P-384,hkdf-sha512,0x02",
    "P-384,hkdf-sha512,0x3",
    "P-384,hkdf-sha512,0x03",
    "P-384,hkdf-sha512,1",
    "P-384,hkdf-sha512,2",
    "P-384,hkdf-sha512,3",
    "P-384,0x1,aes-128-gcm",
    "P-384,0x1,aes-256-gcm",
    "P-384,0x1,chacha20-poly1305",
    "P-384,0x1,0x1",
    "P-384,0x1,0x01",
    "P-384,0x1,0x2",
    "P-384,0x1,0x02",
    "P-384,0x1,0x3",
    "P-384,0x1,0x03",
    "P-384,0x1,1",
    "P-384,0x1,2",
    "P-384,0x1,3",
    "P-384,0x01,aes-128-gcm",
    "P-384,0x01,aes-256-gcm",
    "P-384,0x01,chacha20-poly1305",
    "P-384,0x01,0x1",
    "P-384,0x01,0x01",
    "P-384,0x01,0x2",
    "P-384,0x01,0x02",
    "P-384,0x01,0x3",
    "P-384,0x01,0x03",
    "P-384,0x01,1",
    "P-384,0x01,2",
    "P-384,0x01,3",
    "P-384,0x2,aes-128-gcm",
    "P-384,0x2,aes-256-gcm",
    "P-384,0x2,chacha20-poly1305",
    "P-384,0x2,0x1",
    "P-384,0x2,0x01",
    "P-384,0x2,0x2",
    "P-384,0x2,0x02",
    "P-384,0x2,0x3",
    "P-384,0x2,0x03",
    "P-384,0x2,1",
    "P-384,0x2,2",
    "P-384,0x2,3",
    "P-384,0x02,aes-128-gcm",
    "P-384,0x02,aes-256-gcm",
    "P-384,0x02,chacha20-poly1305",
    "P-384,0x02,0x1",
    "P-384,0x02,0x01",
    "P-384,0x02,0x2",
    "P-384,0x02,0x02",
    "P-384,0x02,0x3",
    "P-384,0x02,0x03",
    "P-384,0x02,1",
    "P-384,0x02,2",
    "P-384,0x02,3",
    "P-384,0x3,aes-128-gcm",
    "P-384,0x3,aes-256-gcm",
    "P-384,0x3,chacha20-poly1305",
    "P-384,0x3,0x1",
    "P-384,0x3,0x01",
    "P-384,0x3,0x2",
    "P-384,0x3,0x02",
    "P-384,0x3,0x3",
    "P-384,0x3,0x03",
    "P-384,0x3,1",
    "P-384,0x3,2",
    "P-384,0x3,3",
    "P-384,0x03,aes-128-gcm",
    "P-384,0x03,aes-256-gcm",
    "P-384,0x03,chacha20-poly1305",
    "P-384,0x03,0x1",
    "P-384,0x03,0x01",
    "P-384,0x03,0x2",
    "P-384,0x03,0x02",
    "P-384,0x03,0x3",
    "P-384,0x03,0x03",
    "P-384,0x03,1",
    "P-384,0x03,2",
    "P-384,0x03,3",
    "P-384,1,aes-128-gcm",
    "P-384,1,aes-256-gcm",
    "P-384,1,chacha20-poly1305",
    "P-384,1,0x1",
    "P-384,1,0x01",
    "P-384,1,0x2",
    "P-384,1,0x02",
    "P-384,1,0x3",
    "P-384,1,0x03",
    "P-384,1,1",
    "P-384,1,2",
    "P-384,1,3",
    "P-384,2,aes-128-gcm",
    "P-384,2,aes-256-gcm",
    "P-384,2,chacha20-poly1305",
    "P-384,2,0x1",
    "P-384,2,0x01",
    "P-384,2,0x2",
    "P-384,2,0x02",
    "P-384,2,0x3",
    "P-384,2,0x03",
    "P-384,2,1",
    "P-384,2,2",
    "P-384,2,3",
    "P-384,3,aes-128-gcm",
    "P-384,3,aes-256-gcm",
    "P-384,3,chacha20-poly1305",
    "P-384,3,0x1",
    "P-384,3,0x01",
    "P-384,3,0x2",
    "P-384,3,0x02",
    "P-384,3,0x3",
    "P-384,3,0x03",
    "P-384,3,1",
    "P-384,3,2",
    "P-384,3,3",
    "P-521,hkdf-sha256,aes-128-gcm",
    "P-521,hkdf-sha256,aes-256-gcm",
    "P-521,hkdf-sha256,chacha20-poly1305",
    "P-521,hkdf-sha256,0x1",
    "P-521,hkdf-sha256,0x01",
    "P-521,hkdf-sha256,0x2",
    "P-521,hkdf-sha256,0x02",
    "P-521,hkdf-sha256,0x3",
    "P-521,hkdf-sha256,0x03",
    "P-521,hkdf-sha256,1",
    "P-521,hkdf-sha256,2",
    "P-521,hkdf-sha256,3",
    "P-521,hkdf-sha384,aes-128-gcm",
    "P-521,hkdf-sha384,aes-256-gcm",
    "P-521,hkdf-sha384,chacha20-poly1305",
    "P-521,hkdf-sha384,0x1",
    "P-521,hkdf-sha384,0x01",
    "P-521,hkdf-sha384,0x2",
    "P-521,hkdf-sha384,0x02",
    "P-521,hkdf-sha384,0x3",
    "P-521,hkdf-sha384,0x03",
    "P-521,hkdf-sha384,1",
    "P-521,hkdf-sha384,2",
    "P-521,hkdf-sha384,3",
    "P-521,hkdf-sha512,aes-128-gcm",
    "P-521,hkdf-sha512,aes-256-gcm",
    "P-521,hkdf-sha512,chacha20-poly1305",
    "P-521,hkdf-sha512,0x1",
    "P-521,hkdf-sha512,0x01",
    "P-521,hkdf-sha512,0x2",
    "P-521,hkdf-sha512,0x02",
    "P-521,hkdf-sha512,0x3",
    "P-521,hkdf-sha512,0x03",
    "P-521,hkdf-sha512,1",
    "P-521,hkdf-sha512,2",
    "P-521,hkdf-sha512,3",
    "P-521,0x1,aes-128-gcm",
    "P-521,0x1,aes-256-gcm",
    "P-521,0x1,chacha20-poly1305",
    "P-521,0x1,0x1",
    "P-521,0x1,0x01",
    "P-521,0x1,0x2",
    "P-521,0x1,0x02",
    "P-521,0x1,0x3",
    "P-521,0x1,0x03",
    "P-521,0x1,1",
    "P-521,0x1,2",
    "P-521,0x1,3",
    "P-521,0x01,aes-128-gcm",
    "P-521,0x01,aes-256-gcm",
    "P-521,0x01,chacha20-poly1305",
    "P-521,0x01,0x1",
    "P-521,0x01,0x01",
    "P-521,0x01,0x2",
    "P-521,0x01,0x02",
    "P-521,0x01,0x3",
    "P-521,0x01,0x03",
    "P-521,0x01,1",
    "P-521,0x01,2",
    "P-521,0x01,3",
    "P-521,0x2,aes-128-gcm",
    "P-521,0x2,aes-256-gcm",
    "P-521,0x2,chacha20-poly1305",
    "P-521,0x2,0x1",
    "P-521,0x2,0x01",
    "P-521,0x2,0x2",
    "P-521,0x2,0x02",
    "P-521,0x2,0x3",
    "P-521,0x2,0x03",
    "P-521,0x2,1",
    "P-521,0x2,2",
    "P-521,0x2,3",
    "P-521,0x02,aes-128-gcm",
    "P-521,0x02,aes-256-gcm",
    "P-521,0x02,chacha20-poly1305",
    "P-521,0x02,0x1",
    "P-521,0x02,0x01",
    "P-521,0x02,0x2",
    "P-521,0x02,0x02",
    "P-521,0x02,0x3",
    "P-521,0x02,0x03",
    "P-521,0x02,1",
    "P-521,0x02,2",
    "P-521,0x02,3",
    "P-521,0x3,aes-128-gcm",
    "P-521,0x3,aes-256-gcm",
    "P-521,0x3,chacha20-poly1305",
    "P-521,0x3,0x1",
    "P-521,0x3,0x01",
    "P-521,0x3,0x2",
    "P-521,0x3,0x02",
    "P-521,0x3,0x3",
    "P-521,0x3,0x03",
    "P-521,0x3,1",
    "P-521,0x3,2",
    "P-521,0x3,3",
    "P-521,0x03,aes-128-gcm",
    "P-521,0x03,aes-256-gcm",
    "P-521,0x03,chacha20-poly1305",
    "P-521,0x03,0x1",
    "P-521,0x03,0x01",
    "P-521,0x03,0x2",
    "P-521,0x03,0x02",
    "P-521,0x03,0x3",
    "P-521,0x03,0x03",
    "P-521,0x03,1",
    "P-521,0x03,2",
    "P-521,0x03,3",
    "P-521,1,aes-128-gcm",
    "P-521,1,aes-256-gcm",
    "P-521,1,chacha20-poly1305",
    "P-521,1,0x1",
    "P-521,1,0x01",
    "P-521,1,0x2",
    "P-521,1,0x02",
    "P-521,1,0x3",
    "P-521,1,0x03",
    "P-521,1,1",
    "P-521,1,2",
    "P-521,1,3",
    "P-521,2,aes-128-gcm",
    "P-521,2,aes-256-gcm",
    "P-521,2,chacha20-poly1305",
    "P-521,2,0x1",
    "P-521,2,0x01",
    "P-521,2,0x2",
    "P-521,2,0x02",
    "P-521,2,0x3",
    "P-521,2,0x03",
    "P-521,2,1",
    "P-521,2,2",
    "P-521,2,3",
    "P-521,3,aes-128-gcm",
    "P-521,3,aes-256-gcm",
    "P-521,3,chacha20-poly1305",
    "P-521,3,0x1",
    "P-521,3,0x01",
    "P-521,3,0x2",
    "P-521,3,0x02",
    "P-521,3,0x3",
    "P-521,3,0x03",
    "P-521,3,1",
    "P-521,3,2",
    "P-521,3,3",
    "x25519,hkdf-sha256,aes-128-gcm",
    "x25519,hkdf-sha256,aes-256-gcm",
    "x25519,hkdf-sha256,chacha20-poly1305",
    "x25519,hkdf-sha256,0x1",
    "x25519,hkdf-sha256,0x01",
    "x25519,hkdf-sha256,0x2",
    "x25519,hkdf-sha256,0x02",
    "x25519,hkdf-sha256,0x3",
    "x25519,hkdf-sha256,0x03",
    "x25519,hkdf-sha256,1",
    "x25519,hkdf-sha256,2",
    "x25519,hkdf-sha256,3",
    "x25519,hkdf-sha384,aes-128-gcm",
    "x25519,hkdf-sha384,aes-256-gcm",
    "x25519,hkdf-sha384,chacha20-poly1305",
    "x25519,hkdf-sha384,0x1",
    "x25519,hkdf-sha384,0x01",
    "x25519,hkdf-sha384,0x2",
    "x25519,hkdf-sha384,0x02",
    "x25519,hkdf-sha384,0x3",
    "x25519,hkdf-sha384,0x03",
    "x25519,hkdf-sha384,1",
    "x25519,hkdf-sha384,2",
    "x25519,hkdf-sha384,3",
    "x25519,hkdf-sha512,aes-128-gcm",
    "x25519,hkdf-sha512,aes-256-gcm",
    "x25519,hkdf-sha512,chacha20-poly1305",
    "x25519,hkdf-sha512,0x1",
    "x25519,hkdf-sha512,0x01",
    "x25519,hkdf-sha512,0x2",
    "x25519,hkdf-sha512,0x02",
    "x25519,hkdf-sha512,0x3",
    "x25519,hkdf-sha512,0x03",
    "x25519,hkdf-sha512,1",
    "x25519,hkdf-sha512,2",
    "x25519,hkdf-sha512,3",
    "x25519,0x1,aes-128-gcm",
    "x25519,0x1,aes-256-gcm",
    "x25519,0x1,chacha20-poly1305",
    "x25519,0x1,0x1",
    "x25519,0x1,0x01",
    "x25519,0x1,0x2",
    "x25519,0x1,0x02",
    "x25519,0x1,0x3",
    "x25519,0x1,0x03",
    "x25519,0x1,1",
    "x25519,0x1,2",
    "x25519,0x1,3",
    "x25519,0x01,aes-128-gcm",
    "x25519,0x01,aes-256-gcm",
    "x25519,0x01,chacha20-poly1305",
    "x25519,0x01,0x1",
    "x25519,0x01,0x01",
    "x25519,0x01,0x2",
    "x25519,0x01,0x02",
    "x25519,0x01,0x3",
    "x25519,0x01,0x03",
    "x25519,0x01,1",
    "x25519,0x01,2",
    "x25519,0x01,3",
    "x25519,0x2,aes-128-gcm",
    "x25519,0x2,aes-256-gcm",
    "x25519,0x2,chacha20-poly1305",
    "x25519,0x2,0x1",
    "x25519,0x2,0x01",
    "x25519,0x2,0x2",
    "x25519,0x2,0x02",
    "x25519,0x2,0x3",
    "x25519,0x2,0x03",
    "x25519,0x2,1",
    "x25519,0x2,2",
    "x25519,0x2,3",
    "x25519,0x02,aes-128-gcm",
    "x25519,0x02,aes-256-gcm",
    "x25519,0x02,chacha20-poly1305",
    "x25519,0x02,0x1",
    "x25519,0x02,0x01",
    "x25519,0x02,0x2",
    "x25519,0x02,0x02",
    "x25519,0x02,0x3",
    "x25519,0x02,0x03",
    "x25519,0x02,1",
    "x25519,0x02,2",
    "x25519,0x02,3",
    "x25519,0x3,aes-128-gcm",
    "x25519,0x3,aes-256-gcm",
    "x25519,0x3,chacha20-poly1305",
    "x25519,0x3,0x1",
    "x25519,0x3,0x01",
    "x25519,0x3,0x2",
    "x25519,0x3,0x02",
    "x25519,0x3,0x3",
    "x25519,0x3,0x03",
    "x25519,0x3,1",
    "x25519,0x3,2",
    "x25519,0x3,3",
    "x25519,0x03,aes-128-gcm",
    "x25519,0x03,aes-256-gcm",
    "x25519,0x03,chacha20-poly1305",
    "x25519,0x03,0x1",
    "x25519,0x03,0x01",
    "x25519,0x03,0x2",
    "x25519,0x03,0x02",
    "x25519,0x03,0x3",
    "x25519,0x03,0x03",
    "x25519,0x03,1",
    "x25519,0x03,2",
    "x25519,0x03,3",
    "x25519,1,aes-128-gcm",
    "x25519,1,aes-256-gcm",
    "x25519,1,chacha20-poly1305",
    "x25519,1,0x1",
    "x25519,1,0x01",
    "x25519,1,0x2",
    "x25519,1,0x02",
    "x25519,1,0x3",
    "x25519,1,0x03",
    "x25519,1,1",
    "x25519,1,2",
    "x25519,1,3",
    "x25519,2,aes-128-gcm",
    "x25519,2,aes-256-gcm",
    "x25519,2,chacha20-poly1305",
    "x25519,2,0x1",
    "x25519,2,0x01",
    "x25519,2,0x2",
    "x25519,2,0x02",
    "x25519,2,0x3",
    "x25519,2,0x03",
    "x25519,2,1",
    "x25519,2,2",
    "x25519,2,3",
    "x25519,3,aes-128-gcm",
    "x25519,3,aes-256-gcm",
    "x25519,3,chacha20-poly1305",
    "x25519,3,0x1",
    "x25519,3,0x01",
    "x25519,3,0x2",
    "x25519,3,0x02",
    "x25519,3,0x3",
    "x25519,3,0x03",
    "x25519,3,1",
    "x25519,3,2",
    "x25519,3,3",
    "x448,hkdf-sha256,aes-128-gcm",
    "x448,hkdf-sha256,aes-256-gcm",
    "x448,hkdf-sha256,chacha20-poly1305",
    "x448,hkdf-sha256,0x1",
    "x448,hkdf-sha256,0x01",
    "x448,hkdf-sha256,0x2",
    "x448,hkdf-sha256,0x02",
    "x448,hkdf-sha256,0x3",
    "x448,hkdf-sha256,0x03",
    "x448,hkdf-sha256,1",
    "x448,hkdf-sha256,2",
    "x448,hkdf-sha256,3",
    "x448,hkdf-sha384,aes-128-gcm",
    "x448,hkdf-sha384,aes-256-gcm",
    "x448,hkdf-sha384,chacha20-poly1305",
    "x448,hkdf-sha384,0x1",
    "x448,hkdf-sha384,0x01",
    "x448,hkdf-sha384,0x2",
    "x448,hkdf-sha384,0x02",
    "x448,hkdf-sha384,0x3",
    "x448,hkdf-sha384,0x03",
    "x448,hkdf-sha384,1",
    "x448,hkdf-sha384,2",
    "x448,hkdf-sha384,3",
    "x448,hkdf-sha512,aes-128-gcm",
    "x448,hkdf-sha512,aes-256-gcm",
    "x448,hkdf-sha512,chacha20-poly1305",
    "x448,hkdf-sha512,0x1",
    "x448,hkdf-sha512,0x01",
    "x448,hkdf-sha512,0x2",
    "x448,hkdf-sha512,0x02",
    "x448,hkdf-sha512,0x3",
    "x448,hkdf-sha512,0x03",
    "x448,hkdf-sha512,1",
    "x448,hkdf-sha512,2",
    "x448,hkdf-sha512,3",
    "x448,0x1,aes-128-gcm",
    "x448,0x1,aes-256-gcm",
    "x448,0x1,chacha20-poly1305",
    "x448,0x1,0x1",
    "x448,0x1,0x01",
    "x448,0x1,0x2",
    "x448,0x1,0x02",
    "x448,0x1,0x3",
    "x448,0x1,0x03",
    "x448,0x1,1",
    "x448,0x1,2",
    "x448,0x1,3",
    "x448,0x01,aes-128-gcm",
    "x448,0x01,aes-256-gcm",
    "x448,0x01,chacha20-poly1305",
    "x448,0x01,0x1",
    "x448,0x01,0x01",
    "x448,0x01,0x2",
    "x448,0x01,0x02",
    "x448,0x01,0x3",
    "x448,0x01,0x03",
    "x448,0x01,1",
    "x448,0x01,2",
    "x448,0x01,3",
    "x448,0x2,aes-128-gcm",
    "x448,0x2,aes-256-gcm",
    "x448,0x2,chacha20-poly1305",
    "x448,0x2,0x1",
    "x448,0x2,0x01",
    "x448,0x2,0x2",
    "x448,0x2,0x02",
    "x448,0x2,0x3",
    "x448,0x2,0x03",
    "x448,0x2,1",
    "x448,0x2,2",
    "x448,0x2,3",
    "x448,0x02,aes-128-gcm",
    "x448,0x02,aes-256-gcm",
    "x448,0x02,chacha20-poly1305",
    "x448,0x02,0x1",
    "x448,0x02,0x01",
    "x448,0x02,0x2",
    "x448,0x02,0x02",
    "x448,0x02,0x3",
    "x448,0x02,0x03",
    "x448,0x02,1",
    "x448,0x02,2",
    "x448,0x02,3",
    "x448,0x3,aes-128-gcm",
    "x448,0x3,aes-256-gcm",
    "x448,0x3,chacha20-poly1305",
    "x448,0x3,0x1",
    "x448,0x3,0x01",
    "x448,0x3,0x2",
    "x448,0x3,0x02",
    "x448,0x3,0x3",
    "x448,0x3,0x03",
    "x448,0x3,1",
    "x448,0x3,2",
    "x448,0x3,3",
    "x448,0x03,aes-128-gcm",
    "x448,0x03,aes-256-gcm",
    "x448,0x03,chacha20-poly1305",
    "x448,0x03,0x1",
    "x448,0x03,0x01",
    "x448,0x03,0x2",
    "x448,0x03,0x02",
    "x448,0x03,0x3",
    "x448,0x03,0x03",
    "x448,0x03,1",
    "x448,0x03,2",
    "x448,0x03,3",
    "x448,1,aes-128-gcm",
    "x448,1,aes-256-gcm",
    "x448,1,chacha20-poly1305",
    "x448,1,0x1",
    "x448,1,0x01",
    "x448,1,0x2",
    "x448,1,0x02",
    "x448,1,0x3",
    "x448,1,0x03",
    "x448,1,1",
    "x448,1,2",
    "x448,1,3",
    "x448,2,aes-128-gcm",
    "x448,2,aes-256-gcm",
    "x448,2,chacha20-poly1305",
    "x448,2,0x1",
    "x448,2,0x01",
    "x448,2,0x2",
    "x448,2,0x02",
    "x448,2,0x3",
    "x448,2,0x03",
    "x448,2,1",
    "x448,2,2",
    "x448,2,3",
    "x448,3,aes-128-gcm",
    "x448,3,aes-256-gcm",
    "x448,3,chacha20-poly1305",
    "x448,3,0x1",
    "x448,3,0x01",
    "x448,3,0x2",
    "x448,3,0x02",
    "x448,3,0x3",
    "x448,3,0x03",
    "x448,3,1",
    "x448,3,2",
    "x448,3,3",
    "0x10,hkdf-sha256,aes-128-gcm",
    "0x10,hkdf-sha256,aes-256-gcm",
    "0x10,hkdf-sha256,chacha20-poly1305",
    "0x10,hkdf-sha256,0x1",
    "0x10,hkdf-sha256,0x01",
    "0x10,hkdf-sha256,0x2",
    "0x10,hkdf-sha256,0x02",
    "0x10,hkdf-sha256,0x3",
    "0x10,hkdf-sha256,0x03",
    "0x10,hkdf-sha256,1",
    "0x10,hkdf-sha256,2",
    "0x10,hkdf-sha256,3",
    "0x10,hkdf-sha384,aes-128-gcm",
    "0x10,hkdf-sha384,aes-256-gcm",
    "0x10,hkdf-sha384,chacha20-poly1305",
    "0x10,hkdf-sha384,0x1",
    "0x10,hkdf-sha384,0x01",
    "0x10,hkdf-sha384,0x2",
    "0x10,hkdf-sha384,0x02",
    "0x10,hkdf-sha384,0x3",
    "0x10,hkdf-sha384,0x03",
    "0x10,hkdf-sha384,1",
    "0x10,hkdf-sha384,2",
    "0x10,hkdf-sha384,3",
    "0x10,hkdf-sha512,aes-128-gcm",
    "0x10,hkdf-sha512,aes-256-gcm",
    "0x10,hkdf-sha512,chacha20-poly1305",
    "0x10,hkdf-sha512,0x1",
    "0x10,hkdf-sha512,0x01",
    "0x10,hkdf-sha512,0x2",
    "0x10,hkdf-sha512,0x02",
    "0x10,hkdf-sha512,0x3",
    "0x10,hkdf-sha512,0x03",
    "0x10,hkdf-sha512,1",
    "0x10,hkdf-sha512,2",
    "0x10,hkdf-sha512,3",
    "0x10,0x1,aes-128-gcm",
    "0x10,0x1,aes-256-gcm",
    "0x10,0x1,chacha20-poly1305",
    "0x10,0x1,0x1",
    "0x10,0x1,0x01",
    "0x10,0x1,0x2",
    "0x10,0x1,0x02",
    "0x10,0x1,0x3",
    "0x10,0x1,0x03",
    "0x10,0x1,1",
    "0x10,0x1,2",
    "0x10,0x1,3",
    "0x10,0x01,aes-128-gcm",
    "0x10,0x01,aes-256-gcm",
    "0x10,0x01,chacha20-poly1305",
    "0x10,0x01,0x1",
    "0x10,0x01,0x01",
    "0x10,0x01,0x2",
    "0x10,0x01,0x02",
    "0x10,0x01,0x3",
    "0x10,0x01,0x03",
    "0x10,0x01,1",
    "0x10,0x01,2",
    "0x10,0x01,3",
    "0x10,0x2,aes-128-gcm",
    "0x10,0x2,aes-256-gcm",
    "0x10,0x2,chacha20-poly1305",
    "0x10,0x2,0x1",
    "0x10,0x2,0x01",
    "0x10,0x2,0x2",
    "0x10,0x2,0x02",
    "0x10,0x2,0x3",
    "0x10,0x2,0x03",
    "0x10,0x2,1",
    "0x10,0x2,2",
    "0x10,0x2,3",
    "0x10,0x02,aes-128-gcm",
    "0x10,0x02,aes-256-gcm",
    "0x10,0x02,chacha20-poly1305",
    "0x10,0x02,0x1",
    "0x10,0x02,0x01",
    "0x10,0x02,0x2",
    "0x10,0x02,0x02",
    "0x10,0x02,0x3",
    "0x10,0x02,0x03",
    "0x10,0x02,1",
    "0x10,0x02,2",
    "0x10,0x02,3",
    "0x10,0x3,aes-128-gcm",
    "0x10,0x3,aes-256-gcm",
    "0x10,0x3,chacha20-poly1305",
    "0x10,0x3,0x1",
    "0x10,0x3,0x01",
    "0x10,0x3,0x2",
    "0x10,0x3,0x02",
    "0x10,0x3,0x3",
    "0x10,0x3,0x03",
    "0x10,0x3,1",
    "0x10,0x3,2",
    "0x10,0x3,3",
    "0x10,0x03,aes-128-gcm",
    "0x10,0x03,aes-256-gcm",
    "0x10,0x03,chacha20-poly1305",
    "0x10,0x03,0x1",
    "0x10,0x03,0x01",
    "0x10,0x03,0x2",
    "0x10,0x03,0x02",
    "0x10,0x03,0x3",
    "0x10,0x03,0x03",
    "0x10,0x03,1",
    "0x10,0x03,2",
    "0x10,0x03,3",
    "0x10,1,aes-128-gcm",
    "0x10,1,aes-256-gcm",
    "0x10,1,chacha20-poly1305",
    "0x10,1,0x1",
    "0x10,1,0x01",
    "0x10,1,0x2",
    "0x10,1,0x02",
    "0x10,1,0x3",
    "0x10,1,0x03",
    "0x10,1,1",
    "0x10,1,2",
    "0x10,1,3",
    "0x10,2,aes-128-gcm",
    "0x10,2,aes-256-gcm",
    "0x10,2,chacha20-poly1305",
    "0x10,2,0x1",
    "0x10,2,0x01",
    "0x10,2,0x2",
    "0x10,2,0x02",
    "0x10,2,0x3",
    "0x10,2,0x03",
    "0x10,2,1",
    "0x10,2,2",
    "0x10,2,3",
    "0x10,3,aes-128-gcm",
    "0x10,3,aes-256-gcm",
    "0x10,3,chacha20-poly1305",
    "0x10,3,0x1",
    "0x10,3,0x01",
    "0x10,3,0x2",
    "0x10,3,0x02",
    "0x10,3,0x3",
    "0x10,3,0x03",
    "0x10,3,1",
    "0x10,3,2",
    "0x10,3,3",
    "0x11,hkdf-sha256,aes-128-gcm",
    "0x11,hkdf-sha256,aes-256-gcm",
    "0x11,hkdf-sha256,chacha20-poly1305",
    "0x11,hkdf-sha256,0x1",
    "0x11,hkdf-sha256,0x01",
    "0x11,hkdf-sha256,0x2",
    "0x11,hkdf-sha256,0x02",
    "0x11,hkdf-sha256,0x3",
    "0x11,hkdf-sha256,0x03",
    "0x11,hkdf-sha256,1",
    "0x11,hkdf-sha256,2",
    "0x11,hkdf-sha256,3",
    "0x11,hkdf-sha384,aes-128-gcm",
    "0x11,hkdf-sha384,aes-256-gcm",
    "0x11,hkdf-sha384,chacha20-poly1305",
    "0x11,hkdf-sha384,0x1",
    "0x11,hkdf-sha384,0x01",
    "0x11,hkdf-sha384,0x2",
    "0x11,hkdf-sha384,0x02",
    "0x11,hkdf-sha384,0x3",
    "0x11,hkdf-sha384,0x03",
    "0x11,hkdf-sha384,1",
    "0x11,hkdf-sha384,2",
    "0x11,hkdf-sha384,3",
    "0x11,hkdf-sha512,aes-128-gcm",
    "0x11,hkdf-sha512,aes-256-gcm",
    "0x11,hkdf-sha512,chacha20-poly1305",
    "0x11,hkdf-sha512,0x1",
    "0x11,hkdf-sha512,0x01",
    "0x11,hkdf-sha512,0x2",
    "0x11,hkdf-sha512,0x02",
    "0x11,hkdf-sha512,0x3",
    "0x11,hkdf-sha512,0x03",
    "0x11,hkdf-sha512,1",
    "0x11,hkdf-sha512,2",
    "0x11,hkdf-sha512,3",
    "0x11,0x1,aes-128-gcm",
    "0x11,0x1,aes-256-gcm",
    "0x11,0x1,chacha20-poly1305",
    "0x11,0x1,0x1",
    "0x11,0x1,0x01",
    "0x11,0x1,0x2",
    "0x11,0x1,0x02",
    "0x11,0x1,0x3",
    "0x11,0x1,0x03",
    "0x11,0x1,1",
    "0x11,0x1,2",
    "0x11,0x1,3",
    "0x11,0x01,aes-128-gcm",
    "0x11,0x01,aes-256-gcm",
    "0x11,0x01,chacha20-poly1305",
    "0x11,0x01,0x1",
    "0x11,0x01,0x01",
    "0x11,0x01,0x2",
    "0x11,0x01,0x02",
    "0x11,0x01,0x3",
    "0x11,0x01,0x03",
    "0x11,0x01,1",
    "0x11,0x01,2",
    "0x11,0x01,3",
    "0x11,0x2,aes-128-gcm",
    "0x11,0x2,aes-256-gcm",
    "0x11,0x2,chacha20-poly1305",
    "0x11,0x2,0x1",
    "0x11,0x2,0x01",
    "0x11,0x2,0x2",
    "0x11,0x2,0x02",
    "0x11,0x2,0x3",
    "0x11,0x2,0x03",
    "0x11,0x2,1",
    "0x11,0x2,2",
    "0x11,0x2,3",
    "0x11,0x02,aes-128-gcm",
    "0x11,0x02,aes-256-gcm",
    "0x11,0x02,chacha20-poly1305",
    "0x11,0x02,0x1",
    "0x11,0x02,0x01",
    "0x11,0x02,0x2",
    "0x11,0x02,0x02",
    "0x11,0x02,0x3",
    "0x11,0x02,0x03",
    "0x11,0x02,1",
    "0x11,0x02,2",
    "0x11,0x02,3",
    "0x11,0x3,aes-128-gcm",
    "0x11,0x3,aes-256-gcm",
    "0x11,0x3,chacha20-poly1305",
    "0x11,0x3,0x1",
    "0x11,0x3,0x01",
    "0x11,0x3,0x2",
    "0x11,0x3,0x02",
    "0x11,0x3,0x3",
    "0x11,0x3,0x03",
    "0x11,0x3,1",
    "0x11,0x3,2",
    "0x11,0x3,3",
    "0x11,0x03,aes-128-gcm",
    "0x11,0x03,aes-256-gcm",
    "0x11,0x03,chacha20-poly1305",
    "0x11,0x03,0x1",
    "0x11,0x03,0x01",
    "0x11,0x03,0x2",
    "0x11,0x03,0x02",
    "0x11,0x03,0x3",
    "0x11,0x03,0x03",
    "0x11,0x03,1",
    "0x11,0x03,2",
    "0x11,0x03,3",
    "0x11,1,aes-128-gcm",
    "0x11,1,aes-256-gcm",
    "0x11,1,chacha20-poly1305",
    "0x11,1,0x1",
    "0x11,1,0x01",
    "0x11,1,0x2",
    "0x11,1,0x02",
    "0x11,1,0x3",
    "0x11,1,0x03",
    "0x11,1,1",
    "0x11,1,2",
    "0x11,1,3",
    "0x11,2,aes-128-gcm",
    "0x11,2,aes-256-gcm",
    "0x11,2,chacha20-poly1305",
    "0x11,2,0x1",
    "0x11,2,0x01",
    "0x11,2,0x2",
    "0x11,2,0x02",
    "0x11,2,0x3",
    "0x11,2,0x03",
    "0x11,2,1",
    "0x11,2,2",
    "0x11,2,3",
    "0x11,3,aes-128-gcm",
    "0x11,3,aes-256-gcm",
    "0x11,3,chacha20-poly1305",
    "0x11,3,0x1",
    "0x11,3,0x01",
    "0x11,3,0x2",
    "0x11,3,0x02",
    "0x11,3,0x3",
    "0x11,3,0x03",
    "0x11,3,1",
    "0x11,3,2",
    "0x11,3,3",
    "0x12,hkdf-sha256,aes-128-gcm",
    "0x12,hkdf-sha256,aes-256-gcm",
    "0x12,hkdf-sha256,chacha20-poly1305",
    "0x12,hkdf-sha256,0x1",
    "0x12,hkdf-sha256,0x01",
    "0x12,hkdf-sha256,0x2",
    "0x12,hkdf-sha256,0x02",
    "0x12,hkdf-sha256,0x3",
    "0x12,hkdf-sha256,0x03",
    "0x12,hkdf-sha256,1",
    "0x12,hkdf-sha256,2",
    "0x12,hkdf-sha256,3",
    "0x12,hkdf-sha384,aes-128-gcm",
    "0x12,hkdf-sha384,aes-256-gcm",
    "0x12,hkdf-sha384,chacha20-poly1305",
    "0x12,hkdf-sha384,0x1",
    "0x12,hkdf-sha384,0x01",
    "0x12,hkdf-sha384,0x2",
    "0x12,hkdf-sha384,0x02",
    "0x12,hkdf-sha384,0x3",
    "0x12,hkdf-sha384,0x03",
    "0x12,hkdf-sha384,1",
    "0x12,hkdf-sha384,2",
    "0x12,hkdf-sha384,3",
    "0x12,hkdf-sha512,aes-128-gcm",
    "0x12,hkdf-sha512,aes-256-gcm",
    "0x12,hkdf-sha512,chacha20-poly1305",
    "0x12,hkdf-sha512,0x1",
    "0x12,hkdf-sha512,0x01",
    "0x12,hkdf-sha512,0x2",
    "0x12,hkdf-sha512,0x02",
    "0x12,hkdf-sha512,0x3",
    "0x12,hkdf-sha512,0x03",
    "0x12,hkdf-sha512,1",
    "0x12,hkdf-sha512,2",
    "0x12,hkdf-sha512,3",
    "0x12,0x1,aes-128-gcm",
    "0x12,0x1,aes-256-gcm",
    "0x12,0x1,chacha20-poly1305",
    "0x12,0x1,0x1",
    "0x12,0x1,0x01",
    "0x12,0x1,0x2",
    "0x12,0x1,0x02",
    "0x12,0x1,0x3",
    "0x12,0x1,0x03",
    "0x12,0x1,1",
    "0x12,0x1,2",
    "0x12,0x1,3",
    "0x12,0x01,aes-128-gcm",
    "0x12,0x01,aes-256-gcm",
    "0x12,0x01,chacha20-poly1305",
    "0x12,0x01,0x1",
    "0x12,0x01,0x01",
    "0x12,0x01,0x2",
    "0x12,0x01,0x02",
    "0x12,0x01,0x3",
    "0x12,0x01,0x03",
    "0x12,0x01,1",
    "0x12,0x01,2",
    "0x12,0x01,3",
    "0x12,0x2,aes-128-gcm",
    "0x12,0x2,aes-256-gcm",
    "0x12,0x2,chacha20-poly1305",
    "0x12,0x2,0x1",
    "0x12,0x2,0x01",
    "0x12,0x2,0x2",
    "0x12,0x2,0x02",
    "0x12,0x2,0x3",
    "0x12,0x2,0x03",
    "0x12,0x2,1",
    "0x12,0x2,2",
    "0x12,0x2,3",
    "0x12,0x02,aes-128-gcm",
    "0x12,0x02,aes-256-gcm",
    "0x12,0x02,chacha20-poly1305",
    "0x12,0x02,0x1",
    "0x12,0x02,0x01",
    "0x12,0x02,0x2",
    "0x12,0x02,0x02",
    "0x12,0x02,0x3",
    "0x12,0x02,0x03",
    "0x12,0x02,1",
    "0x12,0x02,2",
    "0x12,0x02,3",
    "0x12,0x3,aes-128-gcm",
    "0x12,0x3,aes-256-gcm",
    "0x12,0x3,chacha20-poly1305",
    "0x12,0x3,0x1",
    "0x12,0x3,0x01",
    "0x12,0x3,0x2",
    "0x12,0x3,0x02",
    "0x12,0x3,0x3",
    "0x12,0x3,0x03",
    "0x12,0x3,1",
    "0x12,0x3,2",
    "0x12,0x3,3",
    "0x12,0x03,aes-128-gcm",
    "0x12,0x03,aes-256-gcm",
    "0x12,0x03,chacha20-poly1305",
    "0x12,0x03,0x1",
    "0x12,0x03,0x01",
    "0x12,0x03,0x2",
    "0x12,0x03,0x02",
    "0x12,0x03,0x3",
    "0x12,0x03,0x03",
    "0x12,0x03,1",
    "0x12,0x03,2",
    "0x12,0x03,3",
    "0x12,1,aes-128-gcm",
    "0x12,1,aes-256-gcm",
    "0x12,1,chacha20-poly1305",
    "0x12,1,0x1",
    "0x12,1,0x01",
    "0x12,1,0x2",
    "0x12,1,0x02",
    "0x12,1,0x3",
    "0x12,1,0x03",
    "0x12,1,1",
    "0x12,1,2",
    "0x12,1,3",
    "0x12,2,aes-128-gcm",
    "0x12,2,aes-256-gcm",
    "0x12,2,chacha20-poly1305",
    "0x12,2,0x1",
    "0x12,2,0x01",
    "0x12,2,0x2",
    "0x12,2,0x02",
    "0x12,2,0x3",
    "0x12,2,0x03",
    "0x12,2,1",
    "0x12,2,2",
    "0x12,2,3",
    "0x12,3,aes-128-gcm",
    "0x12,3,aes-256-gcm",
    "0x12,3,chacha20-poly1305",
    "0x12,3,0x1",
    "0x12,3,0x01",
    "0x12,3,0x2",
    "0x12,3,0x02",
    "0x12,3,0x3",
    "0x12,3,0x03",
    "0x12,3,1",
    "0x12,3,2",
    "0x12,3,3",
    "0x20,hkdf-sha256,aes-128-gcm",
    "0x20,hkdf-sha256,aes-256-gcm",
    "0x20,hkdf-sha256,chacha20-poly1305",
    "0x20,hkdf-sha256,0x1",
    "0x20,hkdf-sha256,0x01",
    "0x20,hkdf-sha256,0x2",
    "0x20,hkdf-sha256,0x02",
    "0x20,hkdf-sha256,0x3",
    "0x20,hkdf-sha256,0x03",
    "0x20,hkdf-sha256,1",
    "0x20,hkdf-sha256,2",
    "0x20,hkdf-sha256,3",
    "0x20,hkdf-sha384,aes-128-gcm",
    "0x20,hkdf-sha384,aes-256-gcm",
    "0x20,hkdf-sha384,chacha20-poly1305",
    "0x20,hkdf-sha384,0x1",
    "0x20,hkdf-sha384,0x01",
    "0x20,hkdf-sha384,0x2",
    "0x20,hkdf-sha384,0x02",
    "0x20,hkdf-sha384,0x3",
    "0x20,hkdf-sha384,0x03",
    "0x20,hkdf-sha384,1",
    "0x20,hkdf-sha384,2",
    "0x20,hkdf-sha384,3",
    "0x20,hkdf-sha512,aes-128-gcm",
    "0x20,hkdf-sha512,aes-256-gcm",
    "0x20,hkdf-sha512,chacha20-poly1305",
    "0x20,hkdf-sha512,0x1",
    "0x20,hkdf-sha512,0x01",
    "0x20,hkdf-sha512,0x2",
    "0x20,hkdf-sha512,0x02",
    "0x20,hkdf-sha512,0x3",
    "0x20,hkdf-sha512,0x03",
    "0x20,hkdf-sha512,1",
    "0x20,hkdf-sha512,2",
    "0x20,hkdf-sha512,3",
    "0x20,0x1,aes-128-gcm",
    "0x20,0x1,aes-256-gcm",
    "0x20,0x1,chacha20-poly1305",
    "0x20,0x1,0x1",
    "0x20,0x1,0x01",
    "0x20,0x1,0x2",
    "0x20,0x1,0x02",
    "0x20,0x1,0x3",
    "0x20,0x1,0x03",
    "0x20,0x1,1",
    "0x20,0x1,2",
    "0x20,0x1,3",
    "0x20,0x01,aes-128-gcm",
    "0x20,0x01,aes-256-gcm",
    "0x20,0x01,chacha20-poly1305",
    "0x20,0x01,0x1",
    "0x20,0x01,0x01",
    "0x20,0x01,0x2",
    "0x20,0x01,0x02",
    "0x20,0x01,0x3",
    "0x20,0x01,0x03",
    "0x20,0x01,1",
    "0x20,0x01,2",
    "0x20,0x01,3",
    "0x20,0x2,aes-128-gcm",
    "0x20,0x2,aes-256-gcm",
    "0x20,0x2,chacha20-poly1305",
    "0x20,0x2,0x1",
    "0x20,0x2,0x01",
    "0x20,0x2,0x2",
    "0x20,0x2,0x02",
    "0x20,0x2,0x3",
    "0x20,0x2,0x03",
    "0x20,0x2,1",
    "0x20,0x2,2",
    "0x20,0x2,3",
    "0x20,0x02,aes-128-gcm",
    "0x20,0x02,aes-256-gcm",
    "0x20,0x02,chacha20-poly1305",
    "0x20,0x02,0x1",
    "0x20,0x02,0x01",
    "0x20,0x02,0x2",
    "0x20,0x02,0x02",
    "0x20,0x02,0x3",
    "0x20,0x02,0x03",
    "0x20,0x02,1",
    "0x20,0x02,2",
    "0x20,0x02,3",
    "0x20,0x3,aes-128-gcm",
    "0x20,0x3,aes-256-gcm",
    "0x20,0x3,chacha20-poly1305",
    "0x20,0x3,0x1",
    "0x20,0x3,0x01",
    "0x20,0x3,0x2",
    "0x20,0x3,0x02",
    "0x20,0x3,0x3",
    "0x20,0x3,0x03",
    "0x20,0x3,1",
    "0x20,0x3,2",
    "0x20,0x3,3",
    "0x20,0x03,aes-128-gcm",
    "0x20,0x03,aes-256-gcm",
    "0x20,0x03,chacha20-poly1305",
    "0x20,0x03,0x1",
    "0x20,0x03,0x01",
    "0x20,0x03,0x2",
    "0x20,0x03,0x02",
    "0x20,0x03,0x3",
    "0x20,0x03,0x03",
    "0x20,0x03,1",
    "0x20,0x03,2",
    "0x20,0x03,3",
    "0x20,1,aes-128-gcm",
    "0x20,1,aes-256-gcm",
    "0x20,1,chacha20-poly1305",
    "0x20,1,0x1",
    "0x20,1,0x01",
    "0x20,1,0x2",
    "0x20,1,0x02",
    "0x20,1,0x3",
    "0x20,1,0x03",
    "0x20,1,1",
    "0x20,1,2",
    "0x20,1,3",
    "0x20,2,aes-128-gcm",
    "0x20,2,aes-256-gcm",
    "0x20,2,chacha20-poly1305",
    "0x20,2,0x1",
    "0x20,2,0x01",
    "0x20,2,0x2",
    "0x20,2,0x02",
    "0x20,2,0x3",
    "0x20,2,0x03",
    "0x20,2,1",
    "0x20,2,2",
    "0x20,2,3",
    "0x20,3,aes-128-gcm",
    "0x20,3,aes-256-gcm",
    "0x20,3,chacha20-poly1305",
    "0x20,3,0x1",
    "0x20,3,0x01",
    "0x20,3,0x2",
    "0x20,3,0x02",
    "0x20,3,0x3",
    "0x20,3,0x03",
    "0x20,3,1",
    "0x20,3,2",
    "0x20,3,3",
    "0x21,hkdf-sha256,aes-128-gcm",
    "0x21,hkdf-sha256,aes-256-gcm",
    "0x21,hkdf-sha256,chacha20-poly1305",
    "0x21,hkdf-sha256,0x1",
    "0x21,hkdf-sha256,0x01",
    "0x21,hkdf-sha256,0x2",
    "0x21,hkdf-sha256,0x02",
    "0x21,hkdf-sha256,0x3",
    "0x21,hkdf-sha256,0x03",
    "0x21,hkdf-sha256,1",
    "0x21,hkdf-sha256,2",
    "0x21,hkdf-sha256,3",
    "0x21,hkdf-sha384,aes-128-gcm",
    "0x21,hkdf-sha384,aes-256-gcm",
    "0x21,hkdf-sha384,chacha20-poly1305",
    "0x21,hkdf-sha384,0x1",
    "0x21,hkdf-sha384,0x01",
    "0x21,hkdf-sha384,0x2",
    "0x21,hkdf-sha384,0x02",
    "0x21,hkdf-sha384,0x3",
    "0x21,hkdf-sha384,0x03",
    "0x21,hkdf-sha384,1",
    "0x21,hkdf-sha384,2",
    "0x21,hkdf-sha384,3",
    "0x21,hkdf-sha512,aes-128-gcm",
    "0x21,hkdf-sha512,aes-256-gcm",
    "0x21,hkdf-sha512,chacha20-poly1305",
    "0x21,hkdf-sha512,0x1",
    "0x21,hkdf-sha512,0x01",
    "0x21,hkdf-sha512,0x2",
    "0x21,hkdf-sha512,0x02",
    "0x21,hkdf-sha512,0x3",
    "0x21,hkdf-sha512,0x03",
    "0x21,hkdf-sha512,1",
    "0x21,hkdf-sha512,2",
    "0x21,hkdf-sha512,3",
    "0x21,0x1,aes-128-gcm",
    "0x21,0x1,aes-256-gcm",
    "0x21,0x1,chacha20-poly1305",
    "0x21,0x1,0x1",
    "0x21,0x1,0x01",
    "0x21,0x1,0x2",
    "0x21,0x1,0x02",
    "0x21,0x1,0x3",
    "0x21,0x1,0x03",
    "0x21,0x1,1",
    "0x21,0x1,2",
    "0x21,0x1,3",
    "0x21,0x01,aes-128-gcm",
    "0x21,0x01,aes-256-gcm",
    "0x21,0x01,chacha20-poly1305",
    "0x21,0x01,0x1",
    "0x21,0x01,0x01",
    "0x21,0x01,0x2",
    "0x21,0x01,0x02",
    "0x21,0x01,0x3",
    "0x21,0x01,0x03",
    "0x21,0x01,1",
    "0x21,0x01,2",
    "0x21,0x01,3",
    "0x21,0x2,aes-128-gcm",
    "0x21,0x2,aes-256-gcm",
    "0x21,0x2,chacha20-poly1305",
    "0x21,0x2,0x1",
    "0x21,0x2,0x01",
    "0x21,0x2,0x2",
    "0x21,0x2,0x02",
    "0x21,0x2,0x3",
    "0x21,0x2,0x03",
    "0x21,0x2,1",
    "0x21,0x2,2",
    "0x21,0x2,3",
    "0x21,0x02,aes-128-gcm",
    "0x21,0x02,aes-256-gcm",
    "0x21,0x02,chacha20-poly1305",
    "0x21,0x02,0x1",
    "0x21,0x02,0x01",
    "0x21,0x02,0x2",
    "0x21,0x02,0x02",
    "0x21,0x02,0x3",
    "0x21,0x02,0x03",
    "0x21,0x02,1",
    "0x21,0x02,2",
    "0x21,0x02,3",
    "0x21,0x3,aes-128-gcm",
    "0x21,0x3,aes-256-gcm",
    "0x21,0x3,chacha20-poly1305",
    "0x21,0x3,0x1",
    "0x21,0x3,0x01",
    "0x21,0x3,0x2",
    "0x21,0x3,0x02",
    "0x21,0x3,0x3",
    "0x21,0x3,0x03",
    "0x21,0x3,1",
    "0x21,0x3,2",
    "0x21,0x3,3",
    "0x21,0x03,aes-128-gcm",
    "0x21,0x03,aes-256-gcm",
    "0x21,0x03,chacha20-poly1305",
    "0x21,0x03,0x1",
    "0x21,0x03,0x01",
    "0x21,0x03,0x2",
    "0x21,0x03,0x02",
    "0x21,0x03,0x3",
    "0x21,0x03,0x03",
    "0x21,0x03,1",
    "0x21,0x03,2",
    "0x21,0x03,3",
    "0x21,1,aes-128-gcm",
    "0x21,1,aes-256-gcm",
    "0x21,1,chacha20-poly1305",
    "0x21,1,0x1",
    "0x21,1,0x01",
    "0x21,1,0x2",
    "0x21,1,0x02",
    "0x21,1,0x3",
    "0x21,1,0x03",
    "0x21,1,1",
    "0x21,1,2",
    "0x21,1,3",
    "0x21,2,aes-128-gcm",
    "0x21,2,aes-256-gcm",
    "0x21,2,chacha20-poly1305",
    "0x21,2,0x1",
    "0x21,2,0x01",
    "0x21,2,0x2",
    "0x21,2,0x02",
    "0x21,2,0x3",
    "0x21,2,0x03",
    "0x21,2,1",
    "0x21,2,2",
    "0x21,2,3",
    "0x21,3,aes-128-gcm",
    "0x21,3,aes-256-gcm",
    "0x21,3,chacha20-poly1305",
    "0x21,3,0x1",
    "0x21,3,0x01",
    "0x21,3,0x2",
    "0x21,3,0x02",
    "0x21,3,0x3",
    "0x21,3,0x03",
    "0x21,3,1",
    "0x21,3,2",
    "0x21,3,3",
    "16,hkdf-sha256,aes-128-gcm",
    "16,hkdf-sha256,aes-256-gcm",
    "16,hkdf-sha256,chacha20-poly1305",
    "16,hkdf-sha256,0x1",
    "16,hkdf-sha256,0x01",
    "16,hkdf-sha256,0x2",
    "16,hkdf-sha256,0x02",
    "16,hkdf-sha256,0x3",
    "16,hkdf-sha256,0x03",
    "16,hkdf-sha256,1",
    "16,hkdf-sha256,2",
    "16,hkdf-sha256,3",
    "16,hkdf-sha384,aes-128-gcm",
    "16,hkdf-sha384,aes-256-gcm",
    "16,hkdf-sha384,chacha20-poly1305",
    "16,hkdf-sha384,0x1",
    "16,hkdf-sha384,0x01",
    "16,hkdf-sha384,0x2",
    "16,hkdf-sha384,0x02",
    "16,hkdf-sha384,0x3",
    "16,hkdf-sha384,0x03",
    "16,hkdf-sha384,1",
    "16,hkdf-sha384,2",
    "16,hkdf-sha384,3",
    "16,hkdf-sha512,aes-128-gcm",
    "16,hkdf-sha512,aes-256-gcm",
    "16,hkdf-sha512,chacha20-poly1305",
    "16,hkdf-sha512,0x1",
    "16,hkdf-sha512,0x01",
    "16,hkdf-sha512,0x2",
    "16,hkdf-sha512,0x02",
    "16,hkdf-sha512,0x3",
    "16,hkdf-sha512,0x03",
    "16,hkdf-sha512,1",
    "16,hkdf-sha512,2",
    "16,hkdf-sha512,3",
    "16,0x1,aes-128-gcm",
    "16,0x1,aes-256-gcm",
    "16,0x1,chacha20-poly1305",
    "16,0x1,0x1",
    "16,0x1,0x01",
    "16,0x1,0x2",
    "16,0x1,0x02",
    "16,0x1,0x3",
    "16,0x1,0x03",
    "16,0x1,1",
    "16,0x1,2",
    "16,0x1,3",
    "16,0x01,aes-128-gcm",
    "16,0x01,aes-256-gcm",
    "16,0x01,chacha20-poly1305",
    "16,0x01,0x1",
    "16,0x01,0x01",
    "16,0x01,0x2",
    "16,0x01,0x02",
    "16,0x01,0x3",
    "16,0x01,0x03",
    "16,0x01,1",
    "16,0x01,2",
    "16,0x01,3",
    "16,0x2,aes-128-gcm",
    "16,0x2,aes-256-gcm",
    "16,0x2,chacha20-poly1305",
    "16,0x2,0x1",
    "16,0x2,0x01",
    "16,0x2,0x2",
    "16,0x2,0x02",
    "16,0x2,0x3",
    "16,0x2,0x03",
    "16,0x2,1",
    "16,0x2,2",
    "16,0x2,3",
    "16,0x02,aes-128-gcm",
    "16,0x02,aes-256-gcm",
    "16,0x02,chacha20-poly1305",
    "16,0x02,0x1",
    "16,0x02,0x01",
    "16,0x02,0x2",
    "16,0x02,0x02",
    "16,0x02,0x3",
    "16,0x02,0x03",
    "16,0x02,1",
    "16,0x02,2",
    "16,0x02,3",
    "16,0x3,aes-128-gcm",
    "16,0x3,aes-256-gcm",
    "16,0x3,chacha20-poly1305",
    "16,0x3,0x1",
    "16,0x3,0x01",
    "16,0x3,0x2",
    "16,0x3,0x02",
    "16,0x3,0x3",
    "16,0x3,0x03",
    "16,0x3,1",
    "16,0x3,2",
    "16,0x3,3",
    "16,0x03,aes-128-gcm",
    "16,0x03,aes-256-gcm",
    "16,0x03,chacha20-poly1305",
    "16,0x03,0x1",
    "16,0x03,0x01",
    "16,0x03,0x2",
    "16,0x03,0x02",
    "16,0x03,0x3",
    "16,0x03,0x03",
    "16,0x03,1",
    "16,0x03,2",
    "16,0x03,3",
    "16,1,aes-128-gcm",
    "16,1,aes-256-gcm",
    "16,1,chacha20-poly1305",
    "16,1,0x1",
    "16,1,0x01",
    "16,1,0x2",
    "16,1,0x02",
    "16,1,0x3",
    "16,1,0x03",
    "16,1,1",
    "16,1,2",
    "16,1,3",
    "16,2,aes-128-gcm",
    "16,2,aes-256-gcm",
    "16,2,chacha20-poly1305",
    "16,2,0x1",
    "16,2,0x01",
    "16,2,0x2",
    "16,2,0x02",
    "16,2,0x3",
    "16,2,0x03",
    "16,2,1",
    "16,2,2",
    "16,2,3",
    "16,3,aes-128-gcm",
    "16,3,aes-256-gcm",
    "16,3,chacha20-poly1305",
    "16,3,0x1",
    "16,3,0x01",
    "16,3,0x2",
    "16,3,0x02",
    "16,3,0x3",
    "16,3,0x03",
    "16,3,1",
    "16,3,2",
    "16,3,3",
    "17,hkdf-sha256,aes-128-gcm",
    "17,hkdf-sha256,aes-256-gcm",
    "17,hkdf-sha256,chacha20-poly1305",
    "17,hkdf-sha256,0x1",
    "17,hkdf-sha256,0x01",
    "17,hkdf-sha256,0x2",
    "17,hkdf-sha256,0x02",
    "17,hkdf-sha256,0x3",
    "17,hkdf-sha256,0x03",
    "17,hkdf-sha256,1",
    "17,hkdf-sha256,2",
    "17,hkdf-sha256,3",
    "17,hkdf-sha384,aes-128-gcm",
    "17,hkdf-sha384,aes-256-gcm",
    "17,hkdf-sha384,chacha20-poly1305",
    "17,hkdf-sha384,0x1",
    "17,hkdf-sha384,0x01",
    "17,hkdf-sha384,0x2",
    "17,hkdf-sha384,0x02",
    "17,hkdf-sha384,0x3",
    "17,hkdf-sha384,0x03",
    "17,hkdf-sha384,1",
    "17,hkdf-sha384,2",
    "17,hkdf-sha384,3",
    "17,hkdf-sha512,aes-128-gcm",
    "17,hkdf-sha512,aes-256-gcm",
    "17,hkdf-sha512,chacha20-poly1305",
    "17,hkdf-sha512,0x1",
    "17,hkdf-sha512,0x01",
    "17,hkdf-sha512,0x2",
    "17,hkdf-sha512,0x02",
    "17,hkdf-sha512,0x3",
    "17,hkdf-sha512,0x03",
    "17,hkdf-sha512,1",
    "17,hkdf-sha512,2",
    "17,hkdf-sha512,3",
    "17,0x1,aes-128-gcm",
    "17,0x1,aes-256-gcm",
    "17,0x1,chacha20-poly1305",
    "17,0x1,0x1",
    "17,0x1,0x01",
    "17,0x1,0x2",
    "17,0x1,0x02",
    "17,0x1,0x3",
    "17,0x1,0x03",
    "17,0x1,1",
    "17,0x1,2",
    "17,0x1,3",
    "17,0x01,aes-128-gcm",
    "17,0x01,aes-256-gcm",
    "17,0x01,chacha20-poly1305",
    "17,0x01,0x1",
    "17,0x01,0x01",
    "17,0x01,0x2",
    "17,0x01,0x02",
    "17,0x01,0x3",
    "17,0x01,0x03",
    "17,0x01,1",
    "17,0x01,2",
    "17,0x01,3",
    "17,0x2,aes-128-gcm",
    "17,0x2,aes-256-gcm",
    "17,0x2,chacha20-poly1305",
    "17,0x2,0x1",
    "17,0x2,0x01",
    "17,0x2,0x2",
    "17,0x2,0x02",
    "17,0x2,0x3",
    "17,0x2,0x03",
    "17,0x2,1",
    "17,0x2,2",
    "17,0x2,3",
    "17,0x02,aes-128-gcm",
    "17,0x02,aes-256-gcm",
    "17,0x02,chacha20-poly1305",
    "17,0x02,0x1",
    "17,0x02,0x01",
    "17,0x02,0x2",
    "17,0x02,0x02",
    "17,0x02,0x3",
    "17,0x02,0x03",
    "17,0x02,1",
    "17,0x02,2",
    "17,0x02,3",
    "17,0x3,aes-128-gcm",
    "17,0x3,aes-256-gcm",
    "17,0x3,chacha20-poly1305",
    "17,0x3,0x1",
    "17,0x3,0x01",
    "17,0x3,0x2",
    "17,0x3,0x02",
    "17,0x3,0x3",
    "17,0x3,0x03",
    "17,0x3,1",
    "17,0x3,2",
    "17,0x3,3",
    "17,0x03,aes-128-gcm",
    "17,0x03,aes-256-gcm",
    "17,0x03,chacha20-poly1305",
    "17,0x03,0x1",
    "17,0x03,0x01",
    "17,0x03,0x2",
    "17,0x03,0x02",
    "17,0x03,0x3",
    "17,0x03,0x03",
    "17,0x03,1",
    "17,0x03,2",
    "17,0x03,3",
    "17,1,aes-128-gcm",
    "17,1,aes-256-gcm",
    "17,1,chacha20-poly1305",
    "17,1,0x1",
    "17,1,0x01",
    "17,1,0x2",
    "17,1,0x02",
    "17,1,0x3",
    "17,1,0x03",
    "17,1,1",
    "17,1,2",
    "17,1,3",
    "17,2,aes-128-gcm",
    "17,2,aes-256-gcm",
    "17,2,chacha20-poly1305",
    "17,2,0x1",
    "17,2,0x01",
    "17,2,0x2",
    "17,2,0x02",
    "17,2,0x3",
    "17,2,0x03",
    "17,2,1",
    "17,2,2",
    "17,2,3",
    "17,3,aes-128-gcm",
    "17,3,aes-256-gcm",
    "17,3,chacha20-poly1305",
    "17,3,0x1",
    "17,3,0x01",
    "17,3,0x2",
    "17,3,0x02",
    "17,3,0x3",
    "17,3,0x03",
    "17,3,1",
    "17,3,2",
    "17,3,3",
    "18,hkdf-sha256,aes-128-gcm",
    "18,hkdf-sha256,aes-256-gcm",
    "18,hkdf-sha256,chacha20-poly1305",
    "18,hkdf-sha256,0x1",
    "18,hkdf-sha256,0x01",
    "18,hkdf-sha256,0x2",
    "18,hkdf-sha256,0x02",
    "18,hkdf-sha256,0x3",
    "18,hkdf-sha256,0x03",
    "18,hkdf-sha256,1",
    "18,hkdf-sha256,2",
    "18,hkdf-sha256,3",
    "18,hkdf-sha384,aes-128-gcm",
    "18,hkdf-sha384,aes-256-gcm",
    "18,hkdf-sha384,chacha20-poly1305",
    "18,hkdf-sha384,0x1",
    "18,hkdf-sha384,0x01",
    "18,hkdf-sha384,0x2",
    "18,hkdf-sha384,0x02",
    "18,hkdf-sha384,0x3",
    "18,hkdf-sha384,0x03",
    "18,hkdf-sha384,1",
    "18,hkdf-sha384,2",
    "18,hkdf-sha384,3",
    "18,hkdf-sha512,aes-128-gcm",
    "18,hkdf-sha512,aes-256-gcm",
    "18,hkdf-sha512,chacha20-poly1305",
    "18,hkdf-sha512,0x1",
    "18,hkdf-sha512,0x01",
    "18,hkdf-sha512,0x2",
    "18,hkdf-sha512,0x02",
    "18,hkdf-sha512,0x3",
    "18,hkdf-sha512,0x03",
    "18,hkdf-sha512,1",
    "18,hkdf-sha512,2",
    "18,hkdf-sha512,3",
    "18,0x1,aes-128-gcm",
    "18,0x1,aes-256-gcm",
    "18,0x1,chacha20-poly1305",
    "18,0x1,0x1",
    "18,0x1,0x01",
    "18,0x1,0x2",
    "18,0x1,0x02",
    "18,0x1,0x3",
    "18,0x1,0x03",
    "18,0x1,1",
    "18,0x1,2",
    "18,0x1,3",
    "18,0x01,aes-128-gcm",
    "18,0x01,aes-256-gcm",
    "18,0x01,chacha20-poly1305",
    "18,0x01,0x1",
    "18,0x01,0x01",
    "18,0x01,0x2",
    "18,0x01,0x02",
    "18,0x01,0x3",
    "18,0x01,0x03",
    "18,0x01,1",
    "18,0x01,2",
    "18,0x01,3",
    "18,0x2,aes-128-gcm",
    "18,0x2,aes-256-gcm",
    "18,0x2,chacha20-poly1305",
    "18,0x2,0x1",
    "18,0x2,0x01",
    "18,0x2,0x2",
    "18,0x2,0x02",
    "18,0x2,0x3",
    "18,0x2,0x03",
    "18,0x2,1",
    "18,0x2,2",
    "18,0x2,3",
    "18,0x02,aes-128-gcm",
    "18,0x02,aes-256-gcm",
    "18,0x02,chacha20-poly1305",
    "18,0x02,0x1",
    "18,0x02,0x01",
    "18,0x02,0x2",
    "18,0x02,0x02",
    "18,0x02,0x3",
    "18,0x02,0x03",
    "18,0x02,1",
    "18,0x02,2",
    "18,0x02,3",
    "18,0x3,aes-128-gcm",
    "18,0x3,aes-256-gcm",
    "18,0x3,chacha20-poly1305",
    "18,0x3,0x1",
    "18,0x3,0x01",
    "18,0x3,0x2",
    "18,0x3,0x02",
    "18,0x3,0x3",
    "18,0x3,0x03",
    "18,0x3,1",
    "18,0x3,2",
    "18,0x3,3",
    "18,0x03,aes-128-gcm",
    "18,0x03,aes-256-gcm",
    "18,0x03,chacha20-poly1305",
    "18,0x03,0x1",
    "18,0x03,0x01",
    "18,0x03,0x2",
    "18,0x03,0x02",
    "18,0x03,0x3",
    "18,0x03,0x03",
    "18,0x03,1",
    "18,0x03,2",
    "18,0x03,3",
    "18,1,aes-128-gcm",
    "18,1,aes-256-gcm",
    "18,1,chacha20-poly1305",
    "18,1,0x1",
    "18,1,0x01",
    "18,1,0x2",
    "18,1,0x02",
    "18,1,0x3",
    "18,1,0x03",
    "18,1,1",
    "18,1,2",
    "18,1,3",
    "18,2,aes-128-gcm",
    "18,2,aes-256-gcm",
    "18,2,chacha20-poly1305",
    "18,2,0x1",
    "18,2,0x01",
    "18,2,0x2",
    "18,2,0x02",
    "18,2,0x3",
    "18,2,0x03",
    "18,2,1",
    "18,2,2",
    "18,2,3",
    "18,3,aes-128-gcm",
    "18,3,aes-256-gcm",
    "18,3,chacha20-poly1305",
    "18,3,0x1",
    "18,3,0x01",
    "18,3,0x2",
    "18,3,0x02",
    "18,3,0x3",
    "18,3,0x03",
    "18,3,1",
    "18,3,2",
    "18,3,3",
    "32,hkdf-sha256,aes-128-gcm",
    "32,hkdf-sha256,aes-256-gcm",
    "32,hkdf-sha256,chacha20-poly1305",
    "32,hkdf-sha256,0x1",
    "32,hkdf-sha256,0x01",
    "32,hkdf-sha256,0x2",
    "32,hkdf-sha256,0x02",
    "32,hkdf-sha256,0x3",
    "32,hkdf-sha256,0x03",
    "32,hkdf-sha256,1",
    "32,hkdf-sha256,2",
    "32,hkdf-sha256,3",
    "32,hkdf-sha384,aes-128-gcm",
    "32,hkdf-sha384,aes-256-gcm",
    "32,hkdf-sha384,chacha20-poly1305",
    "32,hkdf-sha384,0x1",
    "32,hkdf-sha384,0x01",
    "32,hkdf-sha384,0x2",
    "32,hkdf-sha384,0x02",
    "32,hkdf-sha384,0x3",
    "32,hkdf-sha384,0x03",
    "32,hkdf-sha384,1",
    "32,hkdf-sha384,2",
    "32,hkdf-sha384,3",
    "32,hkdf-sha512,aes-128-gcm",
    "32,hkdf-sha512,aes-256-gcm",
    "32,hkdf-sha512,chacha20-poly1305",
    "32,hkdf-sha512,0x1",
    "32,hkdf-sha512,0x01",
    "32,hkdf-sha512,0x2",
    "32,hkdf-sha512,0x02",
    "32,hkdf-sha512,0x3",
    "32,hkdf-sha512,0x03",
    "32,hkdf-sha512,1",
    "32,hkdf-sha512,2",
    "32,hkdf-sha512,3",
    "32,0x1,aes-128-gcm",
    "32,0x1,aes-256-gcm",
    "32,0x1,chacha20-poly1305",
    "32,0x1,0x1",
    "32,0x1,0x01",
    "32,0x1,0x2",
    "32,0x1,0x02",
    "32,0x1,0x3",
    "32,0x1,0x03",
    "32,0x1,1",
    "32,0x1,2",
    "32,0x1,3",
    "32,0x01,aes-128-gcm",
    "32,0x01,aes-256-gcm",
    "32,0x01,chacha20-poly1305",
    "32,0x01,0x1",
    "32,0x01,0x01",
    "32,0x01,0x2",
    "32,0x01,0x02",
    "32,0x01,0x3",
    "32,0x01,0x03",
    "32,0x01,1",
    "32,0x01,2",
    "32,0x01,3",
    "32,0x2,aes-128-gcm",
    "32,0x2,aes-256-gcm",
    "32,0x2,chacha20-poly1305",
    "32,0x2,0x1",
    "32,0x2,0x01",
    "32,0x2,0x2",
    "32,0x2,0x02",
    "32,0x2,0x3",
    "32,0x2,0x03",
    "32,0x2,1",
    "32,0x2,2",
    "32,0x2,3",
    "32,0x02,aes-128-gcm",
    "32,0x02,aes-256-gcm",
    "32,0x02,chacha20-poly1305",
    "32,0x02,0x1",
    "32,0x02,0x01",
    "32,0x02,0x2",
    "32,0x02,0x02",
    "32,0x02,0x3",
    "32,0x02,0x03",
    "32,0x02,1",
    "32,0x02,2",
    "32,0x02,3",
    "32,0x3,aes-128-gcm",
    "32,0x3,aes-256-gcm",
    "32,0x3,chacha20-poly1305",
    "32,0x3,0x1",
    "32,0x3,0x01",
    "32,0x3,0x2",
    "32,0x3,0x02",
    "32,0x3,0x3",
    "32,0x3,0x03",
    "32,0x3,1",
    "32,0x3,2",
    "32,0x3,3",
    "32,0x03,aes-128-gcm",
    "32,0x03,aes-256-gcm",
    "32,0x03,chacha20-poly1305",
    "32,0x03,0x1",
    "32,0x03,0x01",
    "32,0x03,0x2",
    "32,0x03,0x02",
    "32,0x03,0x3",
    "32,0x03,0x03",
    "32,0x03,1",
    "32,0x03,2",
    "32,0x03,3",
    "32,1,aes-128-gcm",
    "32,1,aes-256-gcm",
    "32,1,chacha20-poly1305",
    "32,1,0x1",
    "32,1,0x01",
    "32,1,0x2",
    "32,1,0x02",
    "32,1,0x3",
    "32,1,0x03",
    "32,1,1",
    "32,1,2",
    "32,1,3",
    "32,2,aes-128-gcm",
    "32,2,aes-256-gcm",
    "32,2,chacha20-poly1305",
    "32,2,0x1",
    "32,2,0x01",
    "32,2,0x2",
    "32,2,0x02",
    "32,2,0x3",
    "32,2,0x03",
    "32,2,1",
    "32,2,2",
    "32,2,3",
    "32,3,aes-128-gcm",
    "32,3,aes-256-gcm",
    "32,3,chacha20-poly1305",
    "32,3,0x1",
    "32,3,0x01",
    "32,3,0x2",
    "32,3,0x02",
    "32,3,0x3",
    "32,3,0x03",
    "32,3,1",
    "32,3,2",
    "32,3,3",
    "33,hkdf-sha256,aes-128-gcm",
    "33,hkdf-sha256,aes-256-gcm",
    "33,hkdf-sha256,chacha20-poly1305",
    "33,hkdf-sha256,0x1",
    "33,hkdf-sha256,0x01",
    "33,hkdf-sha256,0x2",
    "33,hkdf-sha256,0x02",
    "33,hkdf-sha256,0x3",
    "33,hkdf-sha256,0x03",
    "33,hkdf-sha256,1",
    "33,hkdf-sha256,2",
    "33,hkdf-sha256,3",
    "33,hkdf-sha384,aes-128-gcm",
    "33,hkdf-sha384,aes-256-gcm",
    "33,hkdf-sha384,chacha20-poly1305",
    "33,hkdf-sha384,0x1",
    "33,hkdf-sha384,0x01",
    "33,hkdf-sha384,0x2",
    "33,hkdf-sha384,0x02",
    "33,hkdf-sha384,0x3",
    "33,hkdf-sha384,0x03",
    "33,hkdf-sha384,1",
    "33,hkdf-sha384,2",
    "33,hkdf-sha384,3",
    "33,hkdf-sha512,aes-128-gcm",
    "33,hkdf-sha512,aes-256-gcm",
    "33,hkdf-sha512,chacha20-poly1305",
    "33,hkdf-sha512,0x1",
    "33,hkdf-sha512,0x01",
    "33,hkdf-sha512,0x2",
    "33,hkdf-sha512,0x02",
    "33,hkdf-sha512,0x3",
    "33,hkdf-sha512,0x03",
    "33,hkdf-sha512,1",
    "33,hkdf-sha512,2",
    "33,hkdf-sha512,3",
    "33,0x1,aes-128-gcm",
    "33,0x1,aes-256-gcm",
    "33,0x1,chacha20-poly1305",
    "33,0x1,0x1",
    "33,0x1,0x01",
    "33,0x1,0x2",
    "33,0x1,0x02",
    "33,0x1,0x3",
    "33,0x1,0x03",
    "33,0x1,1",
    "33,0x1,2",
    "33,0x1,3",
    "33,0x01,aes-128-gcm",
    "33,0x01,aes-256-gcm",
    "33,0x01,chacha20-poly1305",
    "33,0x01,0x1",
    "33,0x01,0x01",
    "33,0x01,0x2",
    "33,0x01,0x02",
    "33,0x01,0x3",
    "33,0x01,0x03",
    "33,0x01,1",
    "33,0x01,2",
    "33,0x01,3",
    "33,0x2,aes-128-gcm",
    "33,0x2,aes-256-gcm",
    "33,0x2,chacha20-poly1305",
    "33,0x2,0x1",
    "33,0x2,0x01",
    "33,0x2,0x2",
    "33,0x2,0x02",
    "33,0x2,0x3",
    "33,0x2,0x03",
    "33,0x2,1",
    "33,0x2,2",
    "33,0x2,3",
    "33,0x02,aes-128-gcm",
    "33,0x02,aes-256-gcm",
    "33,0x02,chacha20-poly1305",
    "33,0x02,0x1",
    "33,0x02,0x01",
    "33,0x02,0x2",
    "33,0x02,0x02",
    "33,0x02,0x3",
    "33,0x02,0x03",
    "33,0x02,1",
    "33,0x02,2",
    "33,0x02,3",
    "33,0x3,aes-128-gcm",
    "33,0x3,aes-256-gcm",
    "33,0x3,chacha20-poly1305",
    "33,0x3,0x1",
    "33,0x3,0x01",
    "33,0x3,0x2",
    "33,0x3,0x02",
    "33,0x3,0x3",
    "33,0x3,0x03",
    "33,0x3,1",
    "33,0x3,2",
    "33,0x3,3",
    "33,0x03,aes-128-gcm",
    "33,0x03,aes-256-gcm",
    "33,0x03,chacha20-poly1305",
    "33,0x03,0x1",
    "33,0x03,0x01",
    "33,0x03,0x2",
    "33,0x03,0x02",
    "33,0x03,0x3",
    "33,0x03,0x03",
    "33,0x03,1",
    "33,0x03,2",
    "33,0x03,3",
    "33,1,aes-128-gcm",
    "33,1,aes-256-gcm",
    "33,1,chacha20-poly1305",
    "33,1,0x1",
    "33,1,0x01",
    "33,1,0x2",
    "33,1,0x02",
    "33,1,0x3",
    "33,1,0x03",
    "33,1,1",
    "33,1,2",
    "33,1,3",
    "33,2,aes-128-gcm",
    "33,2,aes-256-gcm",
    "33,2,chacha20-poly1305",
    "33,2,0x1",
    "33,2,0x01",
    "33,2,0x2",
    "33,2,0x02",
    "33,2,0x3",
    "33,2,0x03",
    "33,2,1",
    "33,2,2",
    "33,2,3",
    "33,3,aes-128-gcm",
    "33,3,aes-256-gcm",
    "33,3,chacha20-poly1305",
    "33,3,0x1",
    "33,3,0x01",
    "33,3,0x2",
    "33,3,0x02",
    "33,3,0x3",
    "33,3,0x03",
    "33,3,1",
    "33,3,2",
    "33,3,3"
};
static char *bogus_suite_strs[] = {
    "3,33,3",
    "bogus,bogus,bogus",
    "bogus,33,3,1,bogus",
    "bogus,33,3,1",
    "bogus,bogus",
    "bogus",
};

/**
 * @brief round-trips, generating keys, encrypt and decrypt
 *
 * This iterates over all mode and ciphersuite options trying
 * a key gen, encrypt and decrypt for each. The aad, info, and
 * seq inputs are randomly set or omitted each time. EVP and
 * non-EVP key generation are randomly selected.
 *
 * @return 1 for success, other otherwise
 */
static int test_hpke_modes_suites(void)
{
    int overallresult = 1;
    int mind = 0; /* index into hpke_mode_list */
    int kemind = 0; /* index into hpke_kem_list */
    int kdfind = 0; /* index into hpke_kdf_list */
    int aeadind = 0; /* index into hpke_aead_list */

    /* iterate over the different modes */
    for (mind = 0; mind != (sizeof(hpke_mode_list) / sizeof(int)); mind++) {
        int hpke_mode = hpke_mode_list[mind];
        size_t aadlen = OSSL_HPKE_MAXSIZE;
        unsigned char aad[OSSL_HPKE_MAXSIZE];
        unsigned char *aadp = NULL;
        size_t infolen = OSSL_HPKE_MAXSIZE;
        unsigned char info[OSSL_HPKE_MAXSIZE];
        unsigned char *infop = NULL;
        size_t seqlen = 12;
        unsigned char seq[12];
        unsigned char *seqp = NULL;
        size_t psklen = OSSL_HPKE_MAXSIZE;
        unsigned char psk[OSSL_HPKE_MAXSIZE];
        unsigned char *pskp = NULL;
        char pskid[OSSL_HPKE_MAXSIZE];
        char *pskidp = NULL;
        EVP_PKEY *privp = NULL;
        ossl_hpke_suite_st hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
        size_t plainlen = OSSL_HPKE_MAXSIZE;
        unsigned char plain[OSSL_HPKE_MAXSIZE];

        memset(plain, 0x00, OSSL_HPKE_MAXSIZE);
        strcpy((char *)plain, "a message not in a bottle");
        plainlen = strlen((char *)plain);
        /*
         * Randomly try with/without info, aad, seq. Given mode and suite
         * combos, and this being run even a few times, we'll exercise many
         * code paths fairly quickly. We don't really care what the values
         * are but it'll be easier to debug if they're known, so we set 'em.
         */
        if (COIN_IS_HEADS) {
            aadp = aad;
            memset(aad, 'a', aadlen);
        } else {
            aadlen = 0;
        }
        if (COIN_IS_HEADS) {
            infop = info;
            memset(info, 'i', infolen);
        } else {
            infolen = 0;
        }
        if (COIN_IS_HEADS) {
            seqp = seq;
            memset(seq, 's', seqlen);
        } else {
            seqlen = 0;
        }
        if (hpke_mode == OSSL_HPKE_MODE_PSK
            || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
            pskp = psk;
            memset(psk, 'P', psklen);
            pskidp = pskid;
            memset(pskid, 'I', OSSL_HPKE_MAXSIZE - 1);
            pskid[OSSL_HPKE_MAXSIZE - 1] = '\0';
        } else {
            psklen = 0;
        }
        /* iterate over the kems, kdfs and aeads */
        for (kemind = 0;
             overallresult == 1 &&
             kemind != (sizeof(hpke_kem_list) / sizeof(uint16_t));
             kemind++) {
            uint16_t kem_id = hpke_kem_list[kemind];
            size_t authpublen = OSSL_HPKE_MAXSIZE;
            unsigned char authpub[OSSL_HPKE_MAXSIZE];
            unsigned char *authpubp = NULL;
            size_t authprivlen = OSSL_HPKE_MAXSIZE;
            unsigned char authpriv[OSSL_HPKE_MAXSIZE];
            unsigned char *authprivp = NULL;

            hpke_suite.kem_id = kem_id;
            /* can only set AUTH key pair when we know KEM */
            if ((hpke_mode == OSSL_HPKE_MODE_AUTH) ||
                (hpke_mode == OSSL_HPKE_MODE_PSKAUTH)) {
                if (OSSL_HPKE_TEST_true(OSSL_HPKE_kg(testctx, hpke_mode,
                                                     hpke_suite, 0, NULL,
                                                     &authpublen, authpub,
                                                     &authprivlen, authpriv),
                                        "OSS_OSSL_HPKE_kg") != 1) {
                    overallresult = 0;
                }
                authpubp = authpub;
                authprivp = authpriv;
            } else {
                authpublen = 0;
                authprivlen = 0;
            }
            for (kdfind = 0;
                 overallresult == 1 &&
                 kdfind != (sizeof(hpke_kdf_list) / sizeof(uint16_t));
                 kdfind++) {
                uint16_t kdf_id = hpke_kdf_list[kdfind];

                hpke_suite.kdf_id = kdf_id;
                for (aeadind = 0;
                     overallresult == 1 &&
                     aeadind != (sizeof(hpke_aead_list) / sizeof(uint16_t));
                     aeadind++) {
                    uint16_t aead_id = hpke_aead_list[aeadind];
                    size_t publen = OSSL_HPKE_MAXSIZE;
                    unsigned char pub[OSSL_HPKE_MAXSIZE];
                    size_t privlen = OSSL_HPKE_MAXSIZE;
                    unsigned char priv[OSSL_HPKE_MAXSIZE];
                    size_t senderpublen = OSSL_HPKE_MAXSIZE;
                    unsigned char senderpub[OSSL_HPKE_MAXSIZE];
                    size_t cipherlen = OSSL_HPKE_MAXSIZE;
                    unsigned char cipher[OSSL_HPKE_MAXSIZE];
                    size_t clearlen = OSSL_HPKE_MAXSIZE;
                    unsigned char clear[OSSL_HPKE_MAXSIZE];

                    hpke_suite.aead_id = aead_id;
                    /* toss a coin to decide to use EVP variant or not */
                    if (COIN_IS_HEADS) {
                        if (OSSL_HPKE_TEST_true(OSSL_HPKE_kg(testctx, hpke_mode,
                                                             hpke_suite,
                                                             0, NULL,
                                                             &publen, pub,
                                                             &privlen, priv),
                                                "OSSL_HPKE_kg") != 1) {
                            overallresult = 0;
                        }
                    } else {
                        if (OSSL_HPKE_TEST_true(OSSL_HPKE_kg_evp(testctx,
                                                                 hpke_mode,
                                                                 hpke_suite,
                                                                 0, NULL,
                                                                 &publen,
                                                                 pub, &privp),
                                                "OSSL_HPKE_kg_evp") != 1) {
                            overallresult = 0;
                        }
                    }

                    if (OSSL_HPKE_TEST_true(OSSL_HPKE_enc(testctx, hpke_mode,
                                                          hpke_suite, pskidp,
                                                          psklen, pskp, publen,
                                                          pub, authprivlen,
                                                          authprivp, NULL,
                                                          plainlen, plain,
                                                          aadlen, aadp,
                                                          infolen, infop,
                                                          seqlen, seqp,
                                                          &senderpublen,
                                                          senderpub,
                                                          &cipherlen, cipher),
                                            "OSSL_HPKE_enc") != 1) {
                        overallresult = 0;
                    }

                    if (privp == NULL) { /* non-EVP variant */
                        if (OSSL_HPKE_TEST_true(OSSL_HPKE_dec(testctx,
                                                              hpke_mode,
                                                              hpke_suite,
                                                              pskidp,
                                                              psklen, pskp,
                                                              authpublen,
                                                              authpubp,
                                                              privlen, priv,
                                                              NULL,
                                                              senderpublen,
                                                              senderpub,
                                                              cipherlen, cipher,
                                                              aadlen, aadp,
                                                              infolen, infop,
                                                              seqlen, seqp,
                                                              &clearlen, clear),
                                                "OSSL_HPKE_dec") != 1) {
                            overallresult = 0;
                        }
                    } else { /* EVP variant */
                        if (OSSL_HPKE_TEST_true(OSSL_HPKE_dec(testctx,
                                                              hpke_mode,
                                                              hpke_suite,
                                                              pskidp,
                                                              psklen, pskp,
                                                              authpublen,
                                                              authpubp,
                                                              0, NULL, privp,
                                                              senderpublen,
                                                              senderpub,
                                                              cipherlen, cipher,
                                                              aadlen, aadp,
                                                              infolen, infop,
                                                              seqlen, seqp,
                                                              &clearlen, clear),
                                                "OSSL_HPKE_dec") != 1) {
                            overallresult = 0;
                        }
                        EVP_PKEY_free(privp);
                        privp = NULL;
                    }
                    /* check output */
                    if (clearlen != plainlen) {
                        overallresult = 0;
                    }
                    if (memcmp(clear, plain, plainlen)) {
                        overallresult = 0;
                    }
                    if (privp) {
                        EVP_PKEY_free(privp);
                        privp = NULL;
                    }
                }
            }
        }
    }
    return (overallresult);
}

/**
 * @brief Check mapping from strings to HPKE suites
 * @return 1 for success, other otherwise
 */
static int test_hpke_suite_strs(void)
{
    int overallresult = 1;
    int sind = 0;
    ossl_hpke_suite_st stirred;

    for (sind = 0; sind != (sizeof(suite_strs) / sizeof(char *)); sind++) {
        char dstr[128];

        sprintf(dstr, "str2suite: %s", suite_strs[sind]);
        if (OSSL_HPKE_TEST_true(OSSL_HPKE_str2suite(suite_strs[sind], &stirred),
                                dstr) != 1) {
            overallresult = 0;
        }
    }
    for (sind = 0;
         sind != (sizeof(bogus_suite_strs) / sizeof(char *));
         sind++) {
        char dstr[128];

        sprintf(dstr, "str2suite: %s", bogus_suite_strs[sind]);
        if (OSSL_HPKE_TEST_false(OSSL_HPKE_str2suite(bogus_suite_strs[sind],
                                                     &stirred),
                                 dstr) == 1) {
            overallresult = 0;
        }
    }
    return (overallresult);
}

/**
 * @brief try the various GREASEy APIs
 * @return 1 for success, other otherwise
 */
static int test_hpke_grease(void)
{
    int overallresult = 1;
    ossl_hpke_suite_st g_suite;
    unsigned char g_pub[OSSL_HPKE_MAXSIZE];
    size_t g_pub_len = OSSL_HPKE_MAXSIZE;
    unsigned char g_cipher[OSSL_HPKE_MAXSIZE];
    size_t g_cipher_len = 266;
    size_t clearlen = 128;
    size_t expanded = 0;

    memset(&g_suite, 0, sizeof(ossl_hpke_suite_st));
    /* GREASEing */
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_good4grease(testctx, NULL, &g_suite,
                                                  g_pub, &g_pub_len, g_cipher,
                                                  g_cipher_len),
                            "good4grease") != 1) {
        overallresult = 0;
    }
    /* expansion */
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_expansion(g_suite, clearlen, &expanded),
                            "expansion") != 1) {
        overallresult = 0;
    }
    if (expanded <= clearlen) {
        overallresult = 0;
    }
    return (overallresult);
}

/**
 * @brief try some fuzzy-ish kg, enc & dec calls
 * @return 1 for success, other otherwise
 */
static int test_hpke_badcalls(void)
{
    int overallresult = 1;
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    ossl_hpke_suite_st hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char buf1[OSSL_HPKE_MAXSIZE];
    unsigned char buf2[OSSL_HPKE_MAXSIZE];
    unsigned char buf3[OSSL_HPKE_MAXSIZE];
    unsigned char buf4[OSSL_HPKE_MAXSIZE];
    size_t aadlen = 0;
    unsigned char *aadp = NULL;
    size_t infolen = 0;
    unsigned char *infop = NULL;
    size_t seqlen = 0;
    unsigned char *seqp = NULL;
    size_t psklen = 0;
    unsigned char *pskp = NULL;
    char *pskidp = NULL;
    size_t publen = 0;
    unsigned char *pub = NULL;
    size_t privlen = 0;
    unsigned char *priv = NULL;
    size_t senderpublen = 0;
    unsigned char *senderpub = NULL;
    size_t plainlen = 0;
    unsigned char *plain = NULL;
    size_t cipherlen = 0;
    unsigned char *cipher = NULL;
    size_t clearlen = 0;
    unsigned char *clear = NULL;
    size_t authpublen = 0;
    unsigned char *authpubp = NULL;
    size_t authprivlen = 0;
    unsigned char *authprivp = NULL;

    if (OSSL_HPKE_TEST_false(OSSL_HPKE_kg(testctx, hpke_mode, hpke_suite,
                                          0, NULL,
                                          &publen, pub, &privlen, priv),
                             "OSSL_HPKE_kg") == 1) {
        overallresult = 0;
    }
    if (OSSL_HPKE_TEST_false(OSSL_HPKE_enc(testctx, hpke_mode, hpke_suite,
                                           pskidp, psklen, pskp,
                                           publen, pub,
                                           authprivlen, authprivp, NULL,
                                           plainlen, plain,
                                           aadlen, aadp,
                                           infolen, infop,
                                           seqlen, seqp,
                                           &senderpublen, senderpub,
                                           &cipherlen, cipher),
                             "OSSL_HPKE_enc") == 1) {
        overallresult = 0;
    }
    if (OSSL_HPKE_TEST_false(OSSL_HPKE_dec(testctx, hpke_mode, hpke_suite,
                                           pskidp, psklen, pskp,
                                           authpublen, authpubp,
                                           privlen, priv, NULL,
                                           senderpublen, senderpub,
                                           cipherlen, cipher,
                                           aadlen, aadp,
                                           infolen, infop,
                                           seqlen, seqp,
                                           &clearlen, clear),
                             "OSSL_HPKE_dec") == 1) {
        overallresult = 0;
    }
    /* gen a key pair to use in enc/dec fails */
    pub = buf1;
    priv = buf2;
    publen = privlen = OSSL_HPKE_MAXSIZE;
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_kg(testctx, hpke_mode, hpke_suite,
                                         0, NULL,
                                         &publen, pub, &privlen, priv),
                            "OSSL_HPKE_kg") != 1) {
        overallresult = 0;
    }
    if (OSSL_HPKE_TEST_false(OSSL_HPKE_enc(testctx, hpke_mode, hpke_suite,
                                           pskidp, psklen, pskp,
                                           publen, pub,
                                           authprivlen, authprivp, NULL,
                                           plainlen, plain,
                                           aadlen, aadp,
                                           infolen, infop,
                                           seqlen, seqp,
                                           &senderpublen, senderpub,
                                           &cipherlen, cipher),
                             "OSSL_HPKE_enc") == 1) {
        overallresult = 0;
    }

    if (overallresult != 1) {
        return (overallresult);
    }
    /*
     * I'm not sure what we want below - calls like these make
     * no real sense (two output buffers at the same place in
     * memory) but I'm not sure we should prevent it.
     * Will leave this here for now in the hope of broader input.
     */
    memset(buf1, 0x01, OSSL_HPKE_MAXSIZE);
    memset(buf2, 0x02, OSSL_HPKE_MAXSIZE);
    memset(buf3, 0x03, OSSL_HPKE_MAXSIZE);
    memset(buf4, 0x04, OSSL_HPKE_MAXSIZE);
    /* same pub & priv buffers won't make for happiness */
    pub = priv = buf1;
    publen = privlen = OSSL_HPKE_MAXSIZE;
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_kg(testctx, hpke_mode, hpke_suite,
                                         0, NULL,
                                         &publen, pub, &privlen, priv),
                            "OSSL_HPKE_kg") != 1) {
        overallresult = 0;
    }
    /* gen a usuable key pair to use in the enc/dec call below */
    pub = buf1;
    priv = buf2;
    publen = privlen = OSSL_HPKE_MAXSIZE;
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_kg(testctx, hpke_mode, hpke_suite,
                                         0, NULL,
                                         &publen, pub, &privlen, priv),
                            "OSSL_HPKE_kg") != 1) {
        overallresult = 0;
    }
    plain = buf3;
    plainlen = 30;
    /* cipher and senderpub as same buffer is.. silly, but "works" */
    cipher = buf4;
    cipherlen = OSSL_HPKE_MAXSIZE;
    senderpub = buf4;
    senderpublen = OSSL_HPKE_MAXSIZE;
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_enc(testctx, hpke_mode, hpke_suite,
                                          pskidp, psklen, pskp,
                                          publen, pub,
                                          authprivlen, authprivp, NULL,
                                          plainlen, plain,
                                          aadlen, aadp,
                                          infolen, infop,
                                          seqlen, seqp,
                                          &senderpublen, senderpub,
                                          &cipherlen, cipher),
                            "OSSL_HPKE_enc") != 1) {
        overallresult = 0;
    }
    return (overallresult);
}

/*
 * NIST p256 key pair from HPKE-07 test vectors
 */
static unsigned char n256priv[] = {
    0x03, 0xe5, 0x2d, 0x22, 0x61, 0xcb, 0x7a, 0xc9,
    0xd6, 0x98, 0x11, 0xcd, 0xd8, 0x80, 0xee, 0xe6,
    0x27, 0xeb, 0x9c, 0x20, 0x66, 0xd0, 0xc2, 0x4c,
    0xfb, 0x33, 0xde, 0x82, 0xdb, 0xe2, 0x7c, 0xf5
};
static unsigned char n256pub[] = {
    0x04, 0x3d, 0xa1, 0x6e, 0x83, 0x49, 0x4b, 0xb3,
    0xfc, 0x81, 0x37, 0xae, 0x91, 0x71, 0x38, 0xfb,
    0x7d, 0xae, 0xbf, 0x8a, 0xfb, 0xa6, 0xce, 0x73,
    0x25, 0x47, 0x89, 0x08, 0xc6, 0x53, 0x69, 0x0b,
    0xe7, 0x0a, 0x9c, 0x9f, 0x67, 0x61, 0x06, 0xcf,
    0xb8, 0x7a, 0x5c, 0x3e, 0xdd, 0x12, 0x51, 0xc5,
    0xfa, 0xe3, 0x3a, 0x12, 0xaa, 0x2c, 0x5e, 0xb7,
    0x99, 0x14, 0x98, 0xe3, 0x45, 0xaa, 0x76, 0x60,
    0x04
};

/*
 * X25519 key pair from HPKE-07 test vectors
 */
static unsigned char x25519priv[] = {
    0x6c, 0xee, 0x2e, 0x27, 0x55, 0x79, 0x07, 0x08,
    0xa2, 0xa1, 0xbe, 0x22, 0x66, 0x78, 0x83, 0xa5,
    0xe3, 0xf9, 0xec, 0x52, 0x81, 0x04, 0x04, 0xa0,
    0xd8, 0x89, 0xa0, 0xed, 0x3e, 0x28, 0xde, 0x00
};
static unsigned char x25519pub[] = {
    0x95, 0x08, 0x97, 0xe0, 0xd3, 0x7a, 0x8b, 0xdb,
    0x0f, 0x21, 0x53, 0xed, 0xf5, 0xfa, 0x58, 0x0a,
    0x64, 0xb3, 0x99, 0xc3, 0x9f, 0xbb, 0x3d, 0x01,
    0x4f, 0x80, 0x98, 0x33, 0x52, 0xa6, 0x36, 0x17
};

/*
 * @brief test generation of pair based on private key
 * @param kem_id the KEM to use (RFC9180 code point)
 * @priv is the private key buffer
 * @privlen is the length of the private key
 * @pub is the public key buffer
 * @publen is the length of the public key
 * @return 1 for good, 0 otherwise
 *
 * This calls OSSL_HPKE_prbuf2evp without specifying the
 * public key, then extracts the public key using the
 * standard EVP_PKEY_get1_encoded_public_key API and then
 * compares that public value with the already-known public
 * value that was input.
 */
static int test_hpke_one_key_gen_from_priv(uint16_t kem_id,
                                           unsigned char *priv, size_t privlen,
                                           unsigned char *pub, size_t publen)
{
    int res = 1;
    EVP_PKEY *sk = NULL;
    unsigned char *lpub = NULL;
    size_t lpublen = 1024;

    if (OSSL_HPKE_prbuf2evp(testctx, kem_id, priv, privlen, NULL, 0, &sk) != 1) {
        res = 0;
    }
    if (sk == NULL) {
        res = 0;
    }
    if (res == 1) {
        lpublen = EVP_PKEY_get1_encoded_public_key(sk, &lpub);
        if (lpub == NULL || lpublen == 0) {
            res = 0;
        } else {
            if (lpublen != publen || memcmp(lpub, pub, publen)) {
                res = 0;
            }
            OPENSSL_free(lpub);
        }
    }
    EVP_PKEY_free(sk);
    return (res);
}

/*
 * @brief call test_hpke_one_priv_gen for a couple of known test vectors
 * @return 1 for good, 0 otherwise
 */
static int test_hpke_gen_from_priv(void)
{
    int res = 0;

    /* NIST P-256 case */
    res = test_hpke_one_key_gen_from_priv(0x10,
                                          n256priv, sizeof(n256priv),
                                          n256pub, sizeof(n256pub));
    if (res != 1) { return (res); }

    /* X25519 case */
    res = test_hpke_one_key_gen_from_priv(0x20,
                                          x25519priv, sizeof(x25519priv),
                                          x25519pub, sizeof(x25519pub));
    if (res != 1) { return (res); }

    return (res);
}

/* from RFC 9180 Appendix A.1.1 */
unsigned char ikm25519[] = {
    0x72, 0x68, 0x60, 0x0d, 0x40, 0x3f, 0xce, 0x43,
    0x15, 0x61, 0xae, 0xf5, 0x83, 0xee, 0x16, 0x13,
    0x52, 0x7c, 0xff, 0x65, 0x5c, 0x13, 0x43, 0xf2,
    0x98, 0x12, 0xe6, 0x67, 0x06, 0xdf, 0x32, 0x34
};
unsigned char pub25519[] = {
    0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28,
    0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d,
    0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44,
    0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31
};

/* from RFC9180 Appendix A.3.1 */
unsigned char ikmp256[] = {
    0x42, 0x70, 0xe5, 0x4f, 0xfd, 0x08, 0xd7, 0x9d,
    0x59, 0x28, 0x02, 0x0a, 0xf4, 0x68, 0x6d, 0x8f,
    0x6b, 0x7d, 0x35, 0xdb, 0xe4, 0x70, 0x26, 0x5f,
    0x1f, 0x5a, 0xa2, 0x28, 0x16, 0xce, 0x86, 0x0e
};
unsigned char pubp256[] = {
    0x04, 0xa9, 0x27, 0x19, 0xc6, 0x19, 0x5d, 0x50,
    0x85, 0x10, 0x4f, 0x46, 0x9a, 0x8b, 0x98, 0x14,
    0xd5, 0x83, 0x8f, 0xf7, 0x2b, 0x60, 0x50, 0x1e,
    0x2c, 0x44, 0x66, 0xe5, 0xe6, 0x7b, 0x32, 0x5a,
    0xc9, 0x85, 0x36, 0xd7, 0xb6, 0x1a, 0x1a, 0xf4,
    0xb7, 0x8e, 0x5b, 0x7f, 0x95, 0x1c, 0x09, 0x00,
    0xbe, 0x86, 0x3c, 0x40, 0x3c, 0xe6, 0x5c, 0x9b,
    0xfc, 0xb9, 0x38, 0x26, 0x57, 0x22, 0x2d, 0x18,
    0xc4
};

/* from RFC9180 Appendix A.6.1 */
unsigned char ikmp521[] = {
    0x7f, 0x06, 0xab, 0x82, 0x15, 0x10, 0x5f, 0xc4,
    0x6a, 0xce, 0xeb, 0x2e, 0x3d, 0xc5, 0x02, 0x8b,
    0x44, 0x36, 0x4f, 0x96, 0x04, 0x26, 0xeb, 0x0d,
    0x8e, 0x40, 0x26, 0xc2, 0xf8, 0xb5, 0xd7, 0xe7,
    0xa9, 0x86, 0x68, 0x8f, 0x15, 0x91, 0xab, 0xf5,
    0xab, 0x75, 0x3c, 0x35, 0x7a, 0x5d, 0x6f, 0x04,
    0x40, 0x41, 0x4b, 0x4e, 0xd4, 0xed, 0xe7, 0x13,
    0x17, 0x77, 0x2a, 0xc9, 0x8d, 0x92, 0x39, 0xf7,
    0x09, 0x04
};
unsigned char pubp521[] = {
    0x04, 0x01, 0x38, 0xb3, 0x85, 0xca, 0x16, 0xbb,
    0x0d, 0x5f, 0xa0, 0xc0, 0x66, 0x5f, 0xbb, 0xd7,
    0xe6, 0x9e, 0x3e, 0xe2, 0x9f, 0x63, 0x99, 0x1d,
    0x3e, 0x9b, 0x5f, 0xa7, 0x40, 0xaa, 0xb8, 0x90,
    0x0a, 0xae, 0xed, 0x46, 0xed, 0x73, 0xa4, 0x90,
    0x55, 0x75, 0x84, 0x25, 0xa0, 0xce, 0x36, 0x50,
    0x7c, 0x54, 0xb2, 0x9c, 0xc5, 0xb8, 0x5a, 0x5c,
    0xee, 0x6b, 0xae, 0x0c, 0xf1, 0xc2, 0x1f, 0x27,
    0x31, 0xec, 0xe2, 0x01, 0x3d, 0xc3, 0xfb, 0x7c,
    0x8d, 0x21, 0x65, 0x4b, 0xb1, 0x61, 0xb4, 0x63,
    0x96, 0x2c, 0xa1, 0x9e, 0x8c, 0x65, 0x4f, 0xf2,
    0x4c, 0x94, 0xdd, 0x28, 0x98, 0xde, 0x12, 0x05,
    0x1f, 0x1e, 0xd0, 0x69, 0x22, 0x37, 0xfb, 0x02,
    0xb2, 0xf8, 0xd1, 0xdc, 0x1c, 0x73, 0xe9, 0xb3,
    0x66, 0xb5, 0x29, 0xeb, 0x43, 0x6e, 0x98, 0xa9,
    0x96, 0xee, 0x52, 0x2a, 0xef, 0x86, 0x3d, 0xd5,
    0x73, 0x9d, 0x2f, 0x29, 0xb0
};

/*
 * @brief generate a key pair from an initial string and check public
 * @param kem_id the KEM to use (RFC9180 code point)
 * @ikm is the initial key material buffer
 * @ikmlen is the length of ikm
 * @pub is the public key buffer
 * @publen is the length of the public key
 * @return 1 for good, other otherwise
 *
 * This calls OSSL_HPKE_kg specifying only the IKM, then
 * compares the key pair values with the already-known values
 * that were input.
 */
static int test_hpke_one_ikm_gen(uint16_t kem_id,
                                 unsigned char *ikm, size_t ikmlen,
                                 unsigned char *pub, size_t publen)
{
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    ossl_hpke_suite_st hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char lpub[OSSL_HPKE_MAXSIZE];
    size_t lpublen = OSSL_HPKE_MAXSIZE;
    EVP_PKEY *sk = NULL;

    hpke_suite.kem_id = kem_id;
    if (OSSL_HPKE_kg_evp(testctx, hpke_mode, hpke_suite, ikmlen, ikm,
                         &lpublen, lpub, &sk) != 1) {
        return (- __LINE__);
    }
    if (sk == NULL)
        return (- __LINE__);
    EVP_PKEY_free(sk);
    if (lpublen != publen)
        return (- __LINE__);
    if (memcmp(pub, lpub, publen))
        return (- __LINE__);

    return (1);
}

static int test_hpke_ikms(void)
{
    int res = 1;

    res = test_hpke_one_ikm_gen(0x20,
                                ikm25519, sizeof(ikm25519),
                                pub25519, sizeof(pub25519));
    if (res != 1)
        return (res);

    res = test_hpke_one_ikm_gen(0x12,
                                ikmp521, sizeof(ikmp521),
                                pubp521, sizeof(pubp521));
    if (res != 1)
        return (res);

    res = test_hpke_one_ikm_gen(0x10,
                                ikmp256, sizeof(ikmp256),
                                pubp256, sizeof(pubp256));
    if (res != 1)
        return (res);

    return (res);
}

static int test_hpke(void)
{
    int res = 1;

    res = test_hpke_modes_suites();
    if (res != 1)
        return (res);

    res = test_hpke_suite_strs();
    if (res != 1)
        return (res);

    res = test_hpke_grease();
    if (res != 1)
        return (res);

    res = test_hpke_badcalls();
    if (res != 1)
        return (res);

    res = test_hpke_gen_from_priv();
    if (res != 1)
        return (res);

    res = test_hpke_ikms();
    if (res != 1)
        return (res);

    return (res);
}
/* HPKETESTEND */
#endif

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONTEXT,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "context", OPT_CONTEXT, '-', "Explicitly use a non-default library context" },
        { NULL }
    };
    return options;
}

#ifndef OPENSSL_NO_ECX
/* Test that trying to sign with a public key errors out gracefully */
static int test_ecx_not_private_key(int tst)
{
    EVP_PKEY *pkey = NULL;

    const unsigned char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    int testresult = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *mac = NULL;
    size_t maclen = 0;
    unsigned char *pubkey;
    size_t pubkeylen;

    switch (keys[tst].type) {
    case NID_X25519:
    case NID_X448:
        return TEST_skip("signing not supported for X25519/X448");
    }

    /* Check if this algorithm supports public keys */
    if (keys[tst].pub == NULL)
        return TEST_skip("no public key present");

    pubkey = (unsigned char *)keys[tst].pub;
    pubkeylen = strlen(keys[tst].pub);

    pkey = EVP_PKEY_new_raw_public_key_ex(testctx, OBJ_nid2sn(keys[tst].type),
                                          NULL, pubkey, pubkeylen);
    if (!TEST_ptr(pkey))
        goto err;

    if (!TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1)
        goto check_err;

    if (EVP_DigestSign(ctx, NULL, &maclen, msg, sizeof(msg)) != 1)
        goto check_err;

    if (!TEST_ptr(mac = OPENSSL_malloc(maclen)))
        goto err;

    if (!TEST_int_eq(EVP_DigestSign(ctx, mac, &maclen, msg, sizeof(msg)), 0))
        goto err;

 check_err:
    /*
     * Currently only EVP_DigestSign will throw PROV_R_NOT_A_PRIVATE_KEY,
     * but we relax the check to allow error also thrown by
     * EVP_DigestSignInit and EVP_DigestSign.
     */
    if (ERR_GET_REASON(ERR_peek_error()) == PROV_R_NOT_A_PRIVATE_KEY) {
        testresult = 1;
        ERR_clear_error();
    }

 err:
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(mac);
    EVP_PKEY_free(pkey);

    return testresult;
}
#endif /* OPENSSL_NO_ECX */

static int test_sign_continuation(void)
{
    OSSL_PROVIDER *fake_rsa = NULL;
    int testresult = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mctx = NULL;
    const char sigbuf[] = "To Be Signed";
    unsigned char signature[256];
    size_t siglen = 256;
    static int nodupnum = 1;
    static const OSSL_PARAM nodup_params[] = {
        OSSL_PARAM_int("NO_DUP", &nodupnum),
        OSSL_PARAM_END
    };

    if (!TEST_ptr(fake_rsa = fake_rsa_start(testctx)))
        return 0;

    /* Construct a pkey using precise propq to use our provider */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA",
                                                    "provider=fake-rsa"))
        || !TEST_true(EVP_PKEY_fromdata_init(pctx))
        || !TEST_true(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, NULL))
        || !TEST_ptr(pkey))
        goto end;

    /* First test it continues (classic behavior) */
    if (!TEST_ptr(mctx = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestSignInit_ex(mctx, NULL, NULL, testctx,
                                            NULL, pkey, NULL))
        || !TEST_true(EVP_DigestSignUpdate(mctx, sigbuf, sizeof(sigbuf)))
        || !TEST_true(EVP_DigestSignFinal(mctx, signature, &siglen))
        || !TEST_true(EVP_DigestSignUpdate(mctx, sigbuf, sizeof(sigbuf)))
        || !TEST_true(EVP_DigestSignFinal(mctx, signature, &siglen)))
        goto end;

    EVP_MD_CTX_free(mctx);

    /* try again but failing the continuation */
    if (!TEST_ptr(mctx = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestSignInit_ex(mctx, NULL, NULL, testctx,
                                            NULL, pkey, nodup_params))
        || !TEST_true(EVP_DigestSignUpdate(mctx, sigbuf, sizeof(sigbuf)))
        || !TEST_true(EVP_DigestSignFinal(mctx, signature, &siglen))
        || !TEST_false(EVP_DigestSignUpdate(mctx, sigbuf, sizeof(sigbuf)))
        || !TEST_false(EVP_DigestSignFinal(mctx, signature, &siglen)))
        goto end;

    testresult = 1;

end:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    fake_rsa_finish(fake_rsa);
    return testresult;
}

static int aes_gcm_encrypt(const unsigned char *gcm_key, size_t gcm_key_s,
                           const unsigned char *gcm_iv, size_t gcm_ivlen,
                           const unsigned char *gcm_pt, size_t gcm_pt_s,
                           const unsigned char *gcm_aad, size_t gcm_aad_s,
                           const unsigned char *gcm_ct, size_t gcm_ct_s,
                           const unsigned char *gcm_tag, size_t gcm_tag_s)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    unsigned char outtag[16];
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_ptr(cipher = EVP_CIPHER_fetch(testctx, "AES-256-GCM", "")))
        goto err;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &gcm_ivlen);

    if (!TEST_true(EVP_EncryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params))
            || (gcm_aad != NULL
                && !TEST_true(EVP_EncryptUpdate(ctx, NULL, &outlen,
                                                gcm_aad, gcm_aad_s)))
            || !TEST_true(EVP_EncryptUpdate(ctx, outbuf, &outlen,
                                            gcm_pt, gcm_pt_s))
            || !TEST_true(EVP_EncryptFinal_ex(ctx, outbuf, &tmplen)))
        goto err;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  outtag, sizeof(outtag));

    if (!TEST_true(EVP_CIPHER_CTX_get_params(ctx, params))
            || !TEST_mem_eq(outbuf, outlen, gcm_ct, gcm_ct_s)
            || !TEST_mem_eq(outtag, gcm_tag_s, gcm_tag, gcm_tag_s))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

static int aes_gcm_decrypt(const unsigned char *gcm_key, size_t gcm_key_s,
                           const unsigned char *gcm_iv, size_t gcm_ivlen,
                           const unsigned char *gcm_pt, size_t gcm_pt_s,
                           const unsigned char *gcm_aad, size_t gcm_aad_s,
                           const unsigned char *gcm_ct, size_t gcm_ct_s,
                           const unsigned char *gcm_tag, size_t gcm_tag_s)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen;
    unsigned char outbuf[1024];
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    if ((cipher = EVP_CIPHER_fetch(testctx, "AES-256-GCM", "")) == NULL)
        goto err;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &gcm_ivlen);

    if (!TEST_true(EVP_DecryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params))
            || (gcm_aad != NULL
                && !TEST_true(EVP_DecryptUpdate(ctx, NULL, &outlen,
                                                gcm_aad, gcm_aad_s)))
            || !TEST_true(EVP_DecryptUpdate(ctx, outbuf, &outlen,
                                            gcm_ct, gcm_ct_s))
            || !TEST_mem_eq(outbuf, outlen, gcm_pt, gcm_pt_s))
        goto err;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  (void*)gcm_tag, gcm_tag_s);

    if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx, params))
            ||!TEST_true(EVP_DecryptFinal_ex(ctx, outbuf, &outlen)))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

static int test_aes_gcm_ivlen_change_cve_2023_5363(void)
{
    /* AES-GCM test data obtained from NIST public test vectors */
    static const unsigned char gcm_key[] = {
        0xd0, 0xc2, 0x67, 0xc1, 0x9f, 0x30, 0xd8, 0x0b, 0x89, 0x14, 0xbb, 0xbf,
        0xb7, 0x2f, 0x73, 0xb8, 0xd3, 0xcd, 0x5f, 0x6a, 0x78, 0x70, 0x15, 0x84,
        0x8a, 0x7b, 0x30, 0xe3, 0x8f, 0x16, 0xf1, 0x8b,
    };
    static const unsigned char gcm_iv[] = {
        0xb6, 0xdc, 0xda, 0x95, 0xac, 0x99, 0x77, 0x76, 0x25, 0xae, 0x87, 0xf8,
        0xa3, 0xa9, 0xdd, 0x64, 0xd7, 0x9b, 0xbd, 0x5f, 0x4a, 0x0e, 0x54, 0xca,
        0x1a, 0x9f, 0xa2, 0xe3, 0xf4, 0x5f, 0x5f, 0xc2, 0xce, 0xa7, 0xb6, 0x14,
        0x12, 0x6f, 0xf0, 0xaf, 0xfd, 0x3e, 0x17, 0x35, 0x6e, 0xa0, 0x16, 0x09,
        0xdd, 0xa1, 0x3f, 0xd8, 0xdd, 0xf3, 0xdf, 0x4f, 0xcb, 0x18, 0x49, 0xb8,
        0xb3, 0x69, 0x2c, 0x5d, 0x4f, 0xad, 0x30, 0x91, 0x08, 0xbc, 0xbe, 0x24,
        0x01, 0x0f, 0xbe, 0x9c, 0xfb, 0x4f, 0x5d, 0x19, 0x7f, 0x4c, 0x53, 0xb0,
        0x95, 0x90, 0xac, 0x7b, 0x1f, 0x7b, 0xa0, 0x99, 0xe1, 0xf3, 0x48, 0x54,
        0xd0, 0xfc, 0xa9, 0xcc, 0x91, 0xf8, 0x1f, 0x9b, 0x6c, 0x9a, 0xe0, 0xdc,
        0x63, 0xea, 0x7d, 0x2a, 0x4a, 0x7d, 0xa5, 0xed, 0x68, 0x57, 0x27, 0x6b,
        0x68, 0xe0, 0xf2, 0xb8, 0x51, 0x50, 0x8d, 0x3d,
    };
    static const unsigned char gcm_pt[] = {
        0xb8, 0xb6, 0x88, 0x36, 0x44, 0xe2, 0x34, 0xdf, 0x24, 0x32, 0x91, 0x07,
        0x4f, 0xe3, 0x6f, 0x81,
    };
    static const unsigned char gcm_ct[] = {
        0xff, 0x4f, 0xb3, 0xf3, 0xf9, 0xa2, 0x51, 0xd4, 0x82, 0xc2, 0xbe, 0xf3,
        0xe2, 0xd0, 0xec, 0xed,
    };
    static const unsigned char gcm_tag[] = {
        0xbd, 0x06, 0x38, 0x09, 0xf7, 0xe1, 0xc4, 0x72, 0x0e, 0xf2, 0xea, 0x63,
        0xdb, 0x99, 0x6c, 0x21,
    };

    return aes_gcm_encrypt(gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv),
                           gcm_pt, sizeof(gcm_pt), NULL, 0,
                           gcm_ct, sizeof(gcm_ct), gcm_tag, sizeof(gcm_tag))
        && aes_gcm_decrypt(gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv),
                           gcm_pt, sizeof(gcm_pt), NULL, 0,
                           gcm_ct, sizeof(gcm_ct), gcm_tag, sizeof(gcm_tag));
}

#ifndef OPENSSL_NO_RC4
static int rc4_encrypt(const unsigned char *rc4_key, size_t rc4_key_s,
                       const unsigned char *rc4_pt, size_t rc4_pt_s,
                       const unsigned char *rc4_ct, size_t rc4_ct_s)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_ptr(cipher = EVP_CIPHER_fetch(testctx, "RC4", "")))
        goto err;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN,
                                            &rc4_key_s);

    if (!TEST_true(EVP_EncryptInit_ex2(ctx, cipher, rc4_key, NULL, params))
            || !TEST_true(EVP_EncryptUpdate(ctx, outbuf, &outlen,
                                            rc4_pt, rc4_pt_s))
            || !TEST_true(EVP_EncryptFinal_ex(ctx, outbuf, &tmplen)))
        goto err;

    if (!TEST_mem_eq(outbuf, outlen, rc4_ct, rc4_ct_s))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

static int rc4_decrypt(const unsigned char *rc4_key, size_t rc4_key_s,
                       const unsigned char *rc4_pt, size_t rc4_pt_s,
                       const unsigned char *rc4_ct, size_t rc4_ct_s)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen;
    unsigned char outbuf[1024];
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    if ((cipher = EVP_CIPHER_fetch(testctx, "RC4", "")) == NULL)
        goto err;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN,
                                            &rc4_key_s);

    if (!TEST_true(EVP_DecryptInit_ex2(ctx, cipher, rc4_key, NULL, params))
            || !TEST_true(EVP_DecryptUpdate(ctx, outbuf, &outlen,
                                            rc4_ct, rc4_ct_s))
            || !TEST_mem_eq(outbuf, outlen, rc4_pt, rc4_pt_s))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

static int test_aes_rc4_keylen_change_cve_2023_5363(void)
{
    /* RC4 test data obtained from RFC 6229 */
    static const struct {
        unsigned char key[5];
        unsigned char padding[11];
    } rc4_key = {
        {   /* Five bytes of key material */
            0x83, 0x32, 0x22, 0x77, 0x2a,
        },
        {   /* Random padding to 16 bytes */
            0x80, 0xad, 0x97, 0xbd, 0xc9, 0x73, 0xdf, 0x8a, 0xaa, 0x32, 0x91
        }
    };
    static const unsigned char rc4_pt[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const unsigned char rc4_ct[] = {
        0x80, 0xad, 0x97, 0xbd, 0xc9, 0x73, 0xdf, 0x8a,
        0x2e, 0x87, 0x9e, 0x92, 0xa4, 0x97, 0xef, 0xda
    };

    if (lgcyprov == NULL)
        return TEST_skip("Test requires legacy provider to be loaded");

    return rc4_encrypt(rc4_key.key, sizeof(rc4_key.key),
                       rc4_pt, sizeof(rc4_pt), rc4_ct, sizeof(rc4_ct))
        && rc4_decrypt(rc4_key.key, sizeof(rc4_key.key),
                       rc4_pt, sizeof(rc4_pt), rc4_ct, sizeof(rc4_ct));
}
#endif

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_CONTEXT:
            /* Set up an alternate library context */
            testctx = OSSL_LIB_CTX_new();
            if (!TEST_ptr(testctx))
                return 0;
#ifdef STATIC_LEGACY
	    /*
	     * This test is always statically linked against libcrypto. We must not
	     * attempt to load legacy.so that might be dynamically linked against
	     * libcrypto. Instead we use a built-in version of the legacy provider.
	     */
	    if (!OSSL_PROVIDER_add_builtin(testctx, "legacy", ossl_legacy_provider_init))
		return 0;
#endif
            /* Swap the libctx to test non-default context only */
            nullprov = OSSL_PROVIDER_load(NULL, "null");
            deflprov = OSSL_PROVIDER_load(testctx, "default");
#ifndef OPENSSL_SYS_TANDEM
            lgcyprov = OSSL_PROVIDER_load(testctx, "legacy");
#endif
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    ADD_TEST(test_EVP_set_default_properties);
    ADD_ALL_TESTS(test_EVP_DigestSignInit, 30);
    ADD_TEST(test_EVP_DigestVerifyInit);
#ifndef OPENSSL_NO_SIPHASH
    ADD_TEST(test_siphash_digestsign);
#endif
    ADD_TEST(test_EVP_Digest);
    ADD_TEST(test_EVP_md_null);
    ADD_ALL_TESTS(test_EVP_PKEY_sign, 3);
#ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_ALL_TESTS(test_EVP_PKEY_sign_with_app_method, 2);
#endif
    ADD_ALL_TESTS(test_EVP_Enveloped, 2);
    ADD_ALL_TESTS(test_d2i_AutoPrivateKey, OSSL_NELEM(keydata));
    ADD_TEST(test_privatekey_to_pkcs8);
    ADD_TEST(test_EVP_PKCS82PKEY_wrong_tag);
#ifndef OPENSSL_NO_EC
    ADD_TEST(test_EVP_PKCS82PKEY);
#endif
#ifndef OPENSSL_NO_EC
    ADD_ALL_TESTS(test_EC_keygen_with_enc, OSSL_NELEM(ec_encodings));
#endif
#if !defined(OPENSSL_NO_SM2)
    ADD_TEST(test_EVP_SM2);
    ADD_TEST(test_EVP_SM2_verify);
#endif
    ADD_ALL_TESTS(test_set_get_raw_keys, OSSL_NELEM(keys));
#ifndef OPENSSL_NO_DEPRECATED_3_0
    custom_pmeth = EVP_PKEY_meth_new(0xdefaced, 0);
    if (!TEST_ptr(custom_pmeth))
        return 0;
    EVP_PKEY_meth_set_check(custom_pmeth, pkey_custom_check);
    EVP_PKEY_meth_set_public_check(custom_pmeth, pkey_custom_pub_check);
    EVP_PKEY_meth_set_param_check(custom_pmeth, pkey_custom_param_check);
    if (!TEST_int_eq(EVP_PKEY_meth_add0(custom_pmeth), 1))
        return 0;
#endif
    ADD_ALL_TESTS(test_EVP_PKEY_check, OSSL_NELEM(keycheckdata));
#ifndef OPENSSL_NO_CMAC
    ADD_TEST(test_CMAC_keygen);
#endif
    ADD_TEST(test_HKDF);
    ADD_TEST(test_emptyikm_HKDF);
    ADD_TEST(test_empty_salt_info_HKDF);
#ifndef OPENSSL_NO_EC
    ADD_TEST(test_X509_PUBKEY_inplace);
    ADD_TEST(test_X509_PUBKEY_dup);
    ADD_ALL_TESTS(test_invalide_ec_char2_pub_range_decode,
                  OSSL_NELEM(ec_der_pub_keys));
#endif
#ifndef OPENSSL_NO_DSA
    ADD_TEST(test_DSA_get_set_params);
    ADD_TEST(test_DSA_priv_pub);
#endif
    ADD_TEST(test_RSA_get_set_params);
    ADD_TEST(test_RSA_OAEP_set_get_params);
    ADD_TEST(test_RSA_OAEP_set_null_label);
#ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_TEST(test_RSA_legacy);
#endif
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    ADD_TEST(test_decrypt_null_chunks);
#endif
#ifndef OPENSSL_NO_DH
    ADD_TEST(test_DH_priv_pub);
# ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_TEST(test_EVP_PKEY_set1_DH);
# endif
#endif
#ifndef OPENSSL_NO_EC
    ADD_TEST(test_EC_priv_pub);
    ADD_TEST(test_evp_get_ec_pub);
# ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_TEST(test_EC_priv_only_legacy);
    ADD_TEST(test_evp_get_ec_pub_legacy);
# endif
#endif
    ADD_ALL_TESTS(test_keygen_with_empty_template, 2);
    ADD_ALL_TESTS(test_pkey_ctx_fail_without_provider, 2);

    ADD_TEST(test_rand_agglomeration);
    ADD_ALL_TESTS(test_evp_iv_aes, 12);
#ifndef OPENSSL_NO_DES
    ADD_ALL_TESTS(test_evp_iv_des, 6);
#endif
#ifndef OPENSSL_NO_BF
    ADD_ALL_TESTS(test_evp_bf_default_keylen, 4);
#endif
    ADD_TEST(test_EVP_rsa_pss_with_keygen_bits);
    ADD_TEST(test_EVP_rsa_pss_set_saltlen);
#ifndef OPENSSL_NO_EC
    ADD_ALL_TESTS(test_ecpub, OSSL_NELEM(ecpub_nids));
#endif

    ADD_TEST(test_names_do_all);

    ADD_ALL_TESTS(test_evp_init_seq, OSSL_NELEM(evp_init_tests));
    ADD_ALL_TESTS(test_evp_reset, OSSL_NELEM(evp_reset_tests));
    ADD_ALL_TESTS(test_evp_reinit_seq, OSSL_NELEM(evp_reinit_tests));
    ADD_ALL_TESTS(test_gcm_reinit, OSSL_NELEM(gcm_reinit_tests));
    ADD_ALL_TESTS(test_evp_updated_iv, OSSL_NELEM(evp_updated_iv_tests));
    ADD_ALL_TESTS(test_ivlen_change, OSSL_NELEM(ivlen_change_ciphers));
    if (OSSL_NELEM(keylen_change_ciphers) - 1 > 0)
        ADD_ALL_TESTS(test_keylen_change, OSSL_NELEM(keylen_change_ciphers) - 1);

#ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_ALL_TESTS(test_custom_pmeth, 12);
    ADD_TEST(test_evp_md_cipher_meth);
    ADD_TEST(test_custom_md_meth);
    ADD_TEST(test_custom_ciph_meth);

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
    /* Tests only support the default libctx */
    if (testctx == NULL) {
#  ifndef OPENSSL_NO_EC
        ADD_ALL_TESTS(test_signatures_with_engine, 3);
#  else
        ADD_ALL_TESTS(test_signatures_with_engine, 2);
#  endif
        ADD_TEST(test_cipher_with_engine);
    }
# endif
#endif
#ifndef OPENSSL_NO_EC
    ADD_TEST(test_hpke);
#endif

#ifndef OPENSSL_NO_ECX
    ADD_ALL_TESTS(test_ecx_short_keys, OSSL_NELEM(ecxnids));
    ADD_ALL_TESTS(test_ecx_not_private_key, OSSL_NELEM(keys));
#endif

    ADD_TEST(test_sign_continuation);

    /* Test cases for CVE-2023-5363 */
    ADD_TEST(test_aes_gcm_ivlen_change_cve_2023_5363);
#ifndef OPENSSL_NO_RC4
    ADD_TEST(test_aes_rc4_keylen_change_cve_2023_5363);
#endif

    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(nullprov);
    OSSL_PROVIDER_unload(deflprov);
#ifndef OPENSSL_SYS_TANDEM
    OSSL_PROVIDER_unload(lgcyprov);
#endif
    OSSL_LIB_CTX_free(testctx);
}
