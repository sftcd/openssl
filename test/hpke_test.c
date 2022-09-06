/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/hpke.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include "testutil.h"

#ifndef OSSL_HPKE_MAXSIZE
# define OSSL_HPKE_MAXSIZE 1024
#endif

static OSSL_LIB_CTX *testctx = NULL;
static char *testpropq = NULL;

extern int OSSL_HPKE_prbuf2evp(OSSL_LIB_CTX *libctx, const char *propq,
                               unsigned int kem_id,
                               const unsigned char *prbuf, size_t prbuf_len,
                               const unsigned char *pubuf, size_t pubuf_len,
                               EVP_PKEY **priv);

/**
 * @brief compare an EVP_PKEY to buffer representations of that
 * @param pkey is the EVP_PKEY we want to check
 * @param priv is the expected private key buffer
 * @param privlen is the length of the above
 * @param pub is the expected public key buffer
 * @param publen is the length of the above
 * @return 1 for good, 0 for bad
 */
static int cmpkey(const EVP_PKEY *pkey,
                  const unsigned char *pub, size_t publen)
{
    unsigned char pubbuf[256];
    size_t pubbuflen = 0;
    int erv = 0;

    if (!TEST_true(publen <= sizeof(pubbuf)))
        return 0;
    erv = EVP_PKEY_get_octet_string_param(pkey,
                                          OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                          pubbuf, sizeof(pubbuf), &pubbuflen);
    if (!TEST_true(erv))
        return 0;
    if (pub != NULL && !TEST_mem_eq(pubbuf, pubbuflen, pub, publen))
        return 0;
    return 1;
}

typedef struct {
    int mode;
    OSSL_HPKE_SUITE suite;
    const unsigned char *ikmE;
    size_t ikmElen;
    const unsigned char *expected_pkEm;
    size_t expected_pkEmlen;
    const unsigned char *ikmR;
    size_t ikmRlen;
    const unsigned char *expected_pkRm;
    size_t expected_pkRmlen;
    const unsigned char *expected_skRm;
    size_t expected_skRmlen;
    const unsigned char *expected_secret;
    size_t expected_secretlen;
    const unsigned char *ksinfo;
    size_t ksinfolen;
    const unsigned char *ikmAuth;
    size_t ikmAuthlen;
    const unsigned char *psk;
    size_t psklen;
    const char *pskid; /* want teminating NUL here */
} TEST_BASEDATA;

typedef struct
{
    int seq;
    const unsigned char *pt;
    size_t ptlen;
    const unsigned char *aad;
    size_t aadlen;
    const unsigned char *expected_ct;
    size_t expected_ctlen;
} TEST_AEADDATA;

typedef struct
{
    const unsigned char *context;
    size_t contextlen;
    const unsigned char *expected_secret;
    size_t expected_secretlen;
} TEST_EXPORTDATA;

static int do_testhpke(const TEST_BASEDATA *base,
                       const TEST_AEADDATA *aead, size_t aeadsz,
                       const TEST_EXPORTDATA *export, size_t exportsz)
{
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = testpropq;
    OSSL_HPKE_CTX *sealctx = NULL, *openctx = NULL;
    unsigned char ct[256];
    unsigned char enc[256];
    unsigned char ptout[256];
    size_t ptoutlen = sizeof(ptout);
    size_t enclen = sizeof(enc);
    size_t ctlen = sizeof(ct);
    unsigned char pub[OSSL_HPKE_MAXSIZE];
    size_t publen = sizeof(pub);
    EVP_PKEY *privE = NULL;
    unsigned char authpub[OSSL_HPKE_MAXSIZE];
    size_t authpublen = sizeof(authpub);
    EVP_PKEY *authpriv = NULL;
    unsigned char rpub[OSSL_HPKE_MAXSIZE];
    size_t rpublen = sizeof(pub);
    EVP_PKEY *privR = NULL;
    int ret = 0, i;

    if (!TEST_true(OSSL_HPKE_keygen(libctx, propq, base->mode, base->suite,
                                    base->ikmE, base->ikmElen,
                                    pub, &publen, &privE)))
        goto end;
    if (!TEST_true(cmpkey(privE, base->expected_pkEm, base->expected_pkEmlen)))
        goto end;
    if (!TEST_ptr(sealctx = OSSL_HPKE_CTX_new(base->mode, base->suite,
                                              libctx, propq)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_set1_senderpriv(sealctx, privE)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_AUTH
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(base->ikmAuth != NULL && base->ikmAuthlen > 0))
            goto end;
        if (!TEST_true(OSSL_HPKE_keygen(libctx, propq, base->mode, base->suite,
                                        base->ikmAuth, base->ikmAuthlen,
                                        authpub, &authpublen, &authpriv)))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_set1_authpriv(sealctx, authpriv)))
            goto end;
    }
    if (!TEST_true(OSSL_HPKE_keygen(libctx, propq, base->mode, base->suite,
                                    base->ikmR, base->ikmRlen,
                                    rpub, &rpublen, &privR)))
        goto end;
    if (!TEST_true(cmpkey(privR, base->expected_pkRm, base->expected_pkRmlen)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_PSK
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(sealctx, base->pskid,
                                              base->psk, base->psklen)))
            goto end;
    }
    for (i = 0; i < (int)aeadsz; ++i) {
        ctlen = sizeof(ct);
        OPENSSL_cleanse(ct, ctlen);
        if (!TEST_true(OSSL_HPKE_sender_seal(sealctx,
                                             enc, &enclen,
                                             ct, &ctlen,
                                             rpub, rpublen,
                                             base->ksinfo, base->ksinfolen,
                                             aead[i].aad, aead[i].aadlen,
                                             aead[i].pt, aead[i].ptlen)))
            goto end;
        if (!TEST_true(cmpkey(privE, enc, enclen)))
            goto end;
        if (!TEST_true(TEST_mem_eq(ct, ctlen,
                                   aead[i].expected_ct,
                                   aead[i].expected_ctlen)))
            goto end;
    }

    if (!TEST_ptr(openctx = OSSL_HPKE_CTX_new(base->mode, base->suite,
                                              libctx, propq)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_PSK
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(base->pskid != NULL && base->psk != NULL
                       && base->psklen > 0))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(openctx, base->pskid,
                                              base->psk, base->psklen)))
            goto end;
    }
    if (base->mode == OSSL_HPKE_MODE_AUTH
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(OSSL_HPKE_CTX_set1_authpub(openctx,
                                                  authpub, authpublen)))
            goto end;
    }

    for (i = 0; i < (int)aeadsz; ++i) {
        ptoutlen = sizeof(ptout);
        OPENSSL_cleanse(ptout, ptoutlen);
        if (!TEST_true(OSSL_HPKE_recipient_open(openctx, ptout, &ptoutlen,
                                                enc, enclen,
                                                privR,
                                                base->ksinfo, base->ksinfolen,
                                                aead[i].aad, aead[i].aadlen,
                                                aead[i].expected_ct,
                                                aead[i].expected_ctlen)))
            goto end;
        if (!TEST_mem_eq(aead[i].pt, aead[i].ptlen, ptout, ptoutlen))
            goto end;
    }
    /* reset seq in sealctx */
    for (i = 0; i < (int)exportsz; ++i) {
        size_t len = export[i].expected_secretlen;
        unsigned char eval[OSSL_HPKE_MAXSIZE];

        if (len > sizeof(eval))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_export(sealctx, eval, len,
                                            export[i].context,
                                            export[i].contextlen)))
            goto end;
        if (!TEST_true(TEST_mem_eq(eval, len, export[i].expected_secret,
                                   export[i].expected_secretlen)))
            goto end;
    }
    ret = 1;
end:
    OSSL_HPKE_CTX_free(sealctx);
    OSSL_HPKE_CTX_free(openctx);
    EVP_PKEY_free(privE);
    EVP_PKEY_free(privR);
    EVP_PKEY_free(authpriv);
    return ret;
}

const unsigned char pt[] = {
    0x42, 0x65, 0x61, 0x75, 0x74, 0x79, 0x20, 0x69,
    0x73, 0x20, 0x74, 0x72, 0x75, 0x74, 0x68, 0x2c,
    0x20, 0x74, 0x72, 0x75, 0x74, 0x68, 0x20, 0x62,
    0x65, 0x61, 0x75, 0x74, 0x79
};
const unsigned char ksinfo[] = {
    0x4f, 0x64, 0x65, 0x20, 0x6f, 0x6e, 0x20, 0x61,
    0x20, 0x47, 0x72, 0x65, 0x63, 0x69, 0x61, 0x6e,
    0x20, 0x55, 0x72, 0x6e
};

static int x25519kdfsha256_hkdfsha256_aes128gcm_psk_test(void)
{
    const unsigned char ikme[] = {
        0x78, 0x62, 0x8c, 0x35, 0x4e, 0x46, 0xf3, 0xe1,
        0x69, 0xbd, 0x23, 0x1b, 0xe7, 0xb2, 0xff, 0x1c,
        0x77, 0xaa, 0x30, 0x24, 0x60, 0xa2, 0x6d, 0xbf,
        0xa1, 0x55, 0x15, 0x68, 0x4c, 0x00, 0x13, 0x0b
    };
    const unsigned char ikmr[] = {
        0xd4, 0xa0, 0x9d, 0x09, 0xf5, 0x75, 0xfe, 0xf4,
        0x25, 0x90, 0x5d, 0x2a, 0xb3, 0x96, 0xc1, 0x44,
        0x91, 0x41, 0x46, 0x3f, 0x69, 0x8f, 0x8e, 0xfd,
        0xb7, 0xac, 0xcf, 0xaf, 0xf8, 0x99, 0x50, 0x98
    };
    const unsigned char ikmepub[] = {
        0x0a, 0xd0, 0x95, 0x0d, 0x9f, 0xb9, 0x58, 0x8e,
        0x59, 0x69, 0x0b, 0x74, 0xf1, 0x23, 0x7e, 0xcd,
        0xf1, 0xd7, 0x75, 0xcd, 0x60, 0xbe, 0x2e, 0xca,
        0x57, 0xaf, 0x5a, 0x4b, 0x04, 0x71, 0xc9, 0x1b,
    };
    const unsigned char ikmrpub[] = {
        0x9f, 0xed, 0x7e, 0x8c, 0x17, 0x38, 0x75, 0x60,
        0xe9, 0x2c, 0xc6, 0x46, 0x2a, 0x68, 0x04, 0x96,
        0x57, 0x24, 0x6a, 0x09, 0xbf, 0xa8, 0xad, 0xe7,
        0xae, 0xfe, 0x58, 0x96, 0x72, 0x01, 0x63, 0x66
    };
    const unsigned char ikmrpriv[] = {
        0xc5, 0xeb, 0x01, 0xeb, 0x45, 0x7f, 0xe6, 0xc6,
        0xf5, 0x75, 0x77, 0xc5, 0x41, 0x3b, 0x93, 0x15,
        0x50, 0xa1, 0x62, 0xc7, 0x1a, 0x03, 0xac, 0x8d,
        0x19, 0x6b, 0xab, 0xbd, 0x4e, 0x5c, 0xe0, 0xfd
    };
    const unsigned char psk[] = {
        0x02, 0x47, 0xfd, 0x33, 0xb9, 0x13, 0x76, 0x0f,
        0xa1, 0xfa, 0x51, 0xe1, 0x89, 0x2d, 0x9f, 0x30,
        0x7f, 0xbe, 0x65, 0xeb, 0x17, 0x1e, 0x81, 0x32,
        0xc2, 0xaf, 0x18, 0x55, 0x5a, 0x73, 0x8b, 0x82
    };
    const char *pskid = "Ennyn Durin aran Moria";
#if 0
    /*
     * unused ascii-hex equivalent of the above - better to
     * use the char * variant as that has the terminating
     * NUL we want
     */
    const unsigned char pskid_ascii_hex[] = {
        0x45, 0x6e, 0x6e, 0x79, 0x6e, 0x20, 0x44, 0x75,
        0x72, 0x69, 0x6e, 0x20, 0x61, 0x72, 0x61, 0x6e,
        0x20, 0x4d, 0x6f, 0x72, 0x69, 0x61
    };
#endif
    const unsigned char expected_shared_secret[] = {
        0x72, 0x76, 0x99, 0xf0, 0x09, 0xff, 0xe3, 0xc0,
        0x76, 0x31, 0x50, 0x19, 0xc6, 0x96, 0x48, 0x36,
        0x6b, 0x69, 0x17, 0x14, 0x39, 0xbd, 0x7d, 0xd0,
        0x80, 0x77, 0x43, 0xbd, 0xe7, 0x69, 0x86, 0xcd
    };

    const unsigned char aad0[] = { 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x30 };
    const unsigned char ct0[] = {
        0xe5, 0x2c, 0x6f, 0xed, 0x7f, 0x75, 0x8d, 0x0c,
        0xf7, 0x14, 0x56, 0x89, 0xf2, 0x1b, 0xc1, 0xbe,
        0x6e, 0xc9, 0xea, 0x09, 0x7f, 0xef, 0x4e, 0x95,
        0x94, 0x40, 0x01, 0x2f, 0x4f, 0xeb, 0x73, 0xfb,
        0x61, 0x1b, 0x94, 0x61, 0x99, 0xe6, 0x81, 0xf4,
        0xcf, 0xc3, 0x4d, 0xb8, 0xea
    };
    const unsigned char aad1[] = { 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x31 };
    const unsigned char ct1[] = {
        0x49, 0xf3, 0xb1, 0x9b, 0x28, 0xa9, 0xea, 0x9f,
        0x43, 0xe8, 0xc7, 0x12, 0x04, 0xc0, 0x0d, 0x4a,
        0x49, 0x0e, 0xe7, 0xf6, 0x13, 0x87, 0xb6, 0x71,
        0x9d, 0xb7, 0x65, 0xe9, 0x48, 0x12, 0x3b, 0x45,
        0xb6, 0x16, 0x33, 0xef, 0x05, 0x9b, 0xa2, 0x2c,
        0xd6, 0x24, 0x37, 0xc8, 0xba
    };
    const unsigned char aad2[] = { 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x32 };
    const unsigned char ct2[] = {
        0x25, 0x7c, 0xa6, 0xa0, 0x84, 0x73, 0xdc, 0x85,
        0x1f, 0xde, 0x45, 0xaf, 0xd5, 0x98, 0xcc, 0x83,
        0xe3, 0x26, 0xdd, 0xd0, 0xab, 0xe1, 0xef, 0x23,
        0xba, 0xa3, 0xba, 0xa4, 0xdd, 0x8c, 0xde, 0x99,
        0xfc, 0xe2, 0xc1, 0xe8, 0xce, 0x68, 0x7b, 0x0b,
        0x47, 0xea, 0xd1, 0xad, 0xc9
    };
    const unsigned char export1[] = {
        0xdf, 0xf1, 0x7a, 0xf3, 0x54, 0xc8, 0xb4, 0x16,
        0x73, 0x56, 0x7d, 0xb6, 0x25, 0x9f, 0xd6, 0x02,
        0x99, 0x67, 0xb4, 0xe1, 0xaa, 0xd1, 0x30, 0x23,
        0xc2, 0xae, 0x5d, 0xf8, 0xf4, 0xf4, 0x3b, 0xf6
    };
    const unsigned char context2[] = { 0x00 };
    const unsigned char export2[] = {
        0x6a, 0x84, 0x72, 0x61, 0xd8, 0x20, 0x7f, 0xe5,
        0x96, 0xbe, 0xfb, 0x52, 0x92, 0x84, 0x63, 0x88,
        0x1a, 0xb4, 0x93, 0xda, 0x34, 0x5b, 0x10, 0xe1,
        0xdc, 0xc6, 0x45, 0xe3, 0xb9, 0x4e, 0x2d, 0x95
    };
    const unsigned char context3[] = {
        0x54, 0x65, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x74,
        0x65, 0x78, 0x74
    };
    const unsigned char export3[] = {
        0x8a, 0xff, 0x52, 0xb4, 0x5a, 0x1b, 0xe3, 0xa7,
        0x34, 0xbc, 0x7a, 0x41, 0xe2, 0x0b, 0x4e, 0x05,
        0x5a, 0xd4, 0xc4, 0xd2, 0x21, 0x04, 0xb0, 0xc2,
        0x02, 0x85, 0xa7, 0xc4, 0x30, 0x24, 0x01, 0xcd
    };
    const TEST_BASEDATA pskdata = {
        /* "X25519", NULL, "SHA256", "SHA256", "AES-128-GCM", */
        OSSL_HPKE_MODE_PSK,
        {
            OSSL_HPKE_KEM_ID_25519,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_AES_GCM_128
        },
        ikme, sizeof(ikme),
        ikmepub, sizeof(ikmepub),
        ikmr, sizeof(ikmr),
        ikmrpub, sizeof(ikmrpub),
        ikmrpriv, sizeof(ikmrpriv),
        expected_shared_secret, sizeof(expected_shared_secret),
        ksinfo, sizeof(ksinfo),
        NULL, 0,    /* No Auth */
        psk, sizeof(psk),
        pskid
    };
    const TEST_AEADDATA aeaddata[] = {
        {
            0,
            pt, sizeof(pt),
            aad0, sizeof(aad0),
            ct0, sizeof(ct0)
        },
        {
            1,
            pt, sizeof(pt),
            aad1, sizeof(aad1),
            ct1, sizeof(ct1)
        },
        {
            2,
            pt, sizeof(pt),
            aad2, sizeof(aad2),
            ct2, sizeof(ct2)
        }
    };
    const TEST_EXPORTDATA exportdata[] = {
        { NULL, 0, export1, sizeof(export1) },
        { context2, sizeof(context2), export2, sizeof(export2) },
        { context3, sizeof(context3), export3, sizeof(export3) },
    };
    return do_testhpke(&pskdata, aeaddata, OSSL_NELEM(aeaddata),
                       exportdata, OSSL_NELEM(exportdata));
}

static int x25519kdfsha256_hkdfsha256_aes128gcm_base_test(void)
{
    const unsigned char ikme[] = {
        0x72, 0x68, 0x60, 0x0d, 0x40, 0x3f, 0xce, 0x43,
        0x15, 0x61, 0xae, 0xf5, 0x83, 0xee, 0x16, 0x13,
        0x52, 0x7c, 0xff, 0x65, 0x5c, 0x13, 0x43, 0xf2,
        0x98, 0x12, 0xe6, 0x67, 0x06, 0xdf, 0x32, 0x34
    };
    const unsigned char ikmepub[] = {
        0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28,
        0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d,
        0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44,
        0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31,
    };
    const unsigned char ikmr[] = {
        0x6d, 0xb9, 0xdf, 0x30, 0xaa, 0x07, 0xdd, 0x42,
        0xee, 0x5e, 0x81, 0x81, 0xaf, 0xdb, 0x97, 0x7e,
        0x53, 0x8f, 0x5e, 0x1f, 0xec, 0x8a, 0x06, 0x22,
        0x3f, 0x33, 0xf7, 0x01, 0x3e, 0x52, 0x50, 0x37
    };
    const unsigned char ikmrpub[] = {
        0x39, 0x48, 0xcf, 0xe0, 0xad, 0x1d, 0xdb, 0x69,
        0x5d, 0x78, 0x0e, 0x59, 0x07, 0x71, 0x95, 0xda,
        0x6c, 0x56, 0x50, 0x6b, 0x02, 0x73, 0x29, 0x79,
        0x4a, 0xb0, 0x2b, 0xca, 0x80, 0x81, 0x5c, 0x4d
    };
    const unsigned char ikmrpriv[] = {
        0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad,
        0x58, 0x37, 0x5d, 0xf3, 0xf5, 0x57, 0xaa, 0xc5,
        0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e, 0x55, 0xa9,
        0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e, 0x8a, 0xc8
    };
    const unsigned char expected_shared_secret[] = {
        0xfe, 0x0e, 0x18, 0xc9, 0xf0, 0x24, 0xce, 0x43,
        0x79, 0x9a, 0xe3, 0x93, 0xc7, 0xe8, 0xfe, 0x8f,
        0xce, 0x9d, 0x21, 0x88, 0x75, 0xe8, 0x22, 0x7b,
        0x01, 0x87, 0xc0, 0x4e, 0x7d, 0x2e, 0xa1, 0xfc
    };
    const unsigned char aead0[] = { 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x30 };
    const unsigned char ct0[] = {
        0xf9, 0x38, 0x55, 0x8b, 0x5d, 0x72, 0xf1, 0xa2,
        0x38, 0x10, 0xb4, 0xbe, 0x2a, 0xb4, 0xf8, 0x43,
        0x31, 0xac, 0xc0, 0x2f, 0xc9, 0x7b, 0xab, 0xc5,
        0x3a, 0x52, 0xae, 0x82, 0x18, 0xa3, 0x55, 0xa9,
        0x6d, 0x87, 0x70, 0xac, 0x83, 0xd0, 0x7b, 0xea,
        0x87, 0xe1, 0x3c, 0x51, 0x2a
    };
    const unsigned char aead1[] = { 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x31 };
    const unsigned char ct1[] = {
        0xaf, 0x2d, 0x7e, 0x9a, 0xc9, 0xae, 0x7e, 0x27,
        0x0f, 0x46, 0xba, 0x1f, 0x97, 0x5b, 0xe5, 0x3c,
        0x09, 0xf8, 0xd8, 0x75, 0xbd, 0xc8, 0x53, 0x54,
        0x58, 0xc2, 0x49, 0x4e, 0x8a, 0x6e, 0xab, 0x25,
        0x1c, 0x03, 0xd0, 0xc2, 0x2a, 0x56, 0xb8, 0xca,
        0x42, 0xc2, 0x06, 0x3b, 0x84
    };
    const unsigned char export1[] = {
        0x38, 0x53, 0xfe, 0x2b, 0x40, 0x35, 0x19, 0x5a,
        0x57, 0x3f, 0xfc, 0x53, 0x85, 0x6e, 0x77, 0x05,
        0x8e, 0x15, 0xd9, 0xea, 0x06, 0x4d, 0xe3, 0xe5,
        0x9f, 0x49, 0x61, 0xd0, 0x09, 0x52, 0x50, 0xee
    };
    const unsigned char context2[] = { 0x00 };
    const unsigned char export2[] = {
        0x2e, 0x8f, 0x0b, 0x54, 0x67, 0x3c, 0x70, 0x29,
        0x64, 0x9d, 0x4e, 0xb9, 0xd5, 0xe3, 0x3b, 0xf1,
        0x87, 0x2c, 0xf7, 0x6d, 0x62, 0x3f, 0xf1, 0x64,
        0xac, 0x18, 0x5d, 0xa9, 0xe8, 0x8c, 0x21, 0xa5
    };
    const unsigned char context3[] = {
        0x54, 0x65, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x74,
        0x65, 0x78, 0x74
    };
    const unsigned char export3[] = {
        0xe9, 0xe4, 0x30, 0x65, 0x10, 0x2c, 0x38, 0x36,
        0x40, 0x1b, 0xed, 0x8c, 0x3c, 0x3c, 0x75, 0xae,
        0x46, 0xbe, 0x16, 0x39, 0x86, 0x93, 0x91, 0xd6,
        0x2c, 0x61, 0xf1, 0xec, 0x7a, 0xf5, 0x49, 0x31
    };
    const TEST_BASEDATA basedata = {
        OSSL_HPKE_MODE_BASE,
        {
            OSSL_HPKE_KEM_ID_25519,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_AES_GCM_128
        },
        ikme, sizeof(ikme),
        ikmepub, sizeof(ikmepub),
        ikmr, sizeof(ikmr),
        ikmrpub, sizeof(ikmrpub),
        ikmrpriv, sizeof(ikmrpriv),
        expected_shared_secret, sizeof(expected_shared_secret),
        ksinfo, sizeof(ksinfo),
        NULL, 0, /* no auth ikm */
        NULL, 0, NULL /* no psk */
    };
    const TEST_AEADDATA aeaddata[] = {
        {
            0,
            pt, sizeof(pt),
            aead0, sizeof(aead0),
            ct0, sizeof(ct0)
        },
        {
            1,
            pt, sizeof(pt),
            aead1, sizeof(aead1),
            ct1, sizeof(ct1)
        }
    };
    const TEST_EXPORTDATA exportdata[] = {
        { NULL, 0, export1, sizeof(export1) },
        { context2, sizeof(context2), export2, sizeof(export2) },
        { context3, sizeof(context3), export3, sizeof(export3) },
    };
    return do_testhpke(&basedata, aeaddata, OSSL_NELEM(aeaddata),
                       exportdata, OSSL_NELEM(exportdata));
}

static int P256kdfsha256_hkdfsha256_aes128gcm_base_test(void)
{
    const unsigned char ikme[] = {
        0x42, 0x70, 0xe5, 0x4f, 0xfd, 0x08, 0xd7, 0x9d,
        0x59, 0x28, 0x02, 0x0a, 0xf4, 0x68, 0x6d, 0x8f,
        0x6b, 0x7d, 0x35, 0xdb, 0xe4, 0x70, 0x26, 0x5f,
        0x1f, 0x5a, 0xa2, 0x28, 0x16, 0xce, 0x86, 0x0e
    };
    const unsigned char ikmepub[] = {
        0x04, 0xa9, 0x27, 0x19, 0xc6, 0x19, 0x5d, 0x50,
        0x85, 0x10, 0x4f, 0x46, 0x9a, 0x8b, 0x98, 0x14,
        0xd5, 0x83, 0x8f, 0xf7, 0x2b, 0x60, 0x50, 0x1e,
        0x2c, 0x44, 0x66, 0xe5, 0xe6, 0x7b, 0x32, 0x5a,
        0xc9, 0x85, 0x36, 0xd7, 0xb6, 0x1a, 0x1a, 0xf4,
        0xb7, 0x8e, 0x5b, 0x7f, 0x95, 0x1c, 0x09, 0x00,
        0xbe, 0x86, 0x3c, 0x40, 0x3c, 0xe6, 0x5c, 0x9b,
        0xfc, 0xb9, 0x38, 0x26, 0x57, 0x22, 0x2d, 0x18,
        0xc4,
    };
    const unsigned char ikmr[] = {
        0x66, 0x8b, 0x37, 0x17, 0x1f, 0x10, 0x72, 0xf3,
        0xcf, 0x12, 0xea, 0x8a, 0x23, 0x6a, 0x45, 0xdf,
        0x23, 0xfc, 0x13, 0xb8, 0x2a, 0xf3, 0x60, 0x9a,
        0xd1, 0xe3, 0x54, 0xf6, 0xef, 0x81, 0x75, 0x50
    };
    const unsigned char ikmrpub[] = {
        0x04, 0xfe, 0x8c, 0x19, 0xce, 0x09, 0x05, 0x19,
        0x1e, 0xbc, 0x29, 0x8a, 0x92, 0x45, 0x79, 0x25,
        0x31, 0xf2, 0x6f, 0x0c, 0xec, 0xe2, 0x46, 0x06,
        0x39, 0xe8, 0xbc, 0x39, 0xcb, 0x7f, 0x70, 0x6a,
        0x82, 0x6a, 0x77, 0x9b, 0x4c, 0xf9, 0x69, 0xb8,
        0xa0, 0xe5, 0x39, 0xc7, 0xf6, 0x2f, 0xb3, 0xd3,
        0x0a, 0xd6, 0xaa, 0x8f, 0x80, 0xe3, 0x0f, 0x1d,
        0x12, 0x8a, 0xaf, 0xd6, 0x8a, 0x2c, 0xe7, 0x2e,
        0xa0
    };
    const unsigned char ikmrpriv[] = {
        0xf3, 0xce, 0x7f, 0xda, 0xe5, 0x7e, 0x1a, 0x31,
        0x0d, 0x87, 0xf1, 0xeb, 0xbd, 0xe6, 0xf3, 0x28,
        0xbe, 0x0a, 0x99, 0xcd, 0xbc, 0xad, 0xf4, 0xd6,
        0x58, 0x9c, 0xf2, 0x9d, 0xe4, 0xb8, 0xff, 0xd2
    };
    const unsigned char expected_shared_secret[] = {
        0xc0, 0xd2, 0x6a, 0xea, 0xb5, 0x36, 0x60, 0x9a,
        0x57, 0x2b, 0x07, 0x69, 0x5d, 0x93, 0x3b, 0x58,
        0x9d, 0xcf, 0x36, 0x3f, 0xf9, 0xd9, 0x3c, 0x93,
        0xad, 0xea, 0x53, 0x7a, 0xea, 0xbb, 0x8c, 0xb8
    };
    const unsigned char aead0[] = { 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x30 };
    const unsigned char ct0[] = {
        0x5a, 0xd5, 0x90, 0xbb, 0x8b, 0xaa, 0x57, 0x7f,
        0x86, 0x19, 0xdb, 0x35, 0xa3, 0x63, 0x11, 0x22,
        0x6a, 0x89, 0x6e, 0x73, 0x42, 0xa6, 0xd8, 0x36,
        0xd8, 0xb7, 0xbc, 0xd2, 0xf2, 0x0b, 0x6c, 0x7f,
        0x90, 0x76, 0xac, 0x23, 0x2e, 0x3a, 0xb2, 0x52,
        0x3f, 0x39, 0x51, 0x34, 0x34
    };
    const unsigned char aead1[] = { 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x31 };
    const unsigned char ct1[] = {
        0xfa, 0x6f, 0x03, 0x7b, 0x47, 0xfc, 0x21, 0x82,
        0x6b, 0x61, 0x01, 0x72, 0xca, 0x96, 0x37, 0xe8,
        0x2d, 0x6e, 0x58, 0x01, 0xeb, 0x31, 0xcb, 0xd3,
        0x74, 0x82, 0x71, 0xaf, 0xfd, 0x4e, 0xcb, 0x06,
        0x64, 0x6e, 0x03, 0x29, 0xcb, 0xdf, 0x3c, 0x3c,
        0xd6, 0x55, 0xb2, 0x8e, 0x82
    };
    const unsigned char export1[] = {
        0x5e, 0x9b, 0xc3, 0xd2, 0x36, 0xe1, 0x91, 0x1d,
        0x95, 0xe6, 0x5b, 0x57, 0x6a, 0x8a, 0x86, 0xd4,
        0x78, 0xfb, 0x82, 0x7e, 0x8b, 0xdf, 0xe7, 0x7b,
        0x74, 0x1b, 0x28, 0x98, 0x90, 0x49, 0x0d, 0x4d
    };
    const unsigned char context2[] = { 0x00 };
    const unsigned char export2[] = {
        0x6c, 0xff, 0x87, 0x65, 0x89, 0x31, 0xbd, 0xa8,
        0x3d, 0xc8, 0x57, 0xe6, 0x35, 0x3e, 0xfe, 0x49,
        0x87, 0xa2, 0x01, 0xb8, 0x49, 0x65, 0x8d, 0x9b,
        0x04, 0x7a, 0xab, 0x4c, 0xf2, 0x16, 0xe7, 0x96
    };
    const unsigned char context3[] = {
        0x54, 0x65, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x74,
        0x65, 0x78, 0x74
    };
    const unsigned char export3[] = {
        0xd8, 0xf1, 0xea, 0x79, 0x42, 0xad, 0xbb, 0xa7,
        0x41, 0x2c, 0x6d, 0x43, 0x1c, 0x62, 0xd0, 0x13,
        0x71, 0xea, 0x47, 0x6b, 0x82, 0x3e, 0xb6, 0x97,
        0xe1, 0xf6, 0xe6, 0xca, 0xe1, 0xda, 0xb8, 0x5a
    };
    const TEST_BASEDATA basedata = {
        OSSL_HPKE_MODE_BASE,
        {
            OSSL_HPKE_KEM_ID_P256,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_AES_GCM_128
        },
        ikme, sizeof(ikme),
        ikmepub, sizeof(ikmepub),
        ikmr, sizeof(ikmr),
        ikmrpub, sizeof(ikmrpub),
        ikmrpriv, sizeof(ikmrpriv),
        expected_shared_secret, sizeof(expected_shared_secret),
        ksinfo, sizeof(ksinfo),
        NULL, 0, /* no auth */
        NULL, 0, NULL /* PSK stuff */
    };
    const TEST_AEADDATA aeaddata[] = {
        {
            0,
            pt, sizeof(pt),
            aead0, sizeof(aead0),
            ct0, sizeof(ct0)
        },
        {
            1,
            pt, sizeof(pt),
            aead1, sizeof(aead1),
            ct1, sizeof(ct1)
        }
    };
    const TEST_EXPORTDATA exportdata[] = {
        { NULL, 0, export1, sizeof(export1) },
        { context2, sizeof(context2), export2, sizeof(export2) },
        { context3, sizeof(context3), export3, sizeof(export3) },
    };
    return do_testhpke(&basedata, aeaddata, OSSL_NELEM(aeaddata),
                       exportdata, OSSL_NELEM(exportdata));
}

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

/* strings that can be used, with names or IANA codepoints */
static char *kem_str_list[] = {
    "P-256", "P-384", "P-521", "x25519", "x448",
    "0x10", "0x11", "0x12", "0x20", "0x21",
    "16", "17", "18", "32", "33"
};
static char *kdf_str_list[] = {
    "hkdf-sha256", "hkdf-sha384", "hkdf-sha512",
    "0x1", "0x01", "0x2", "0x02", "0x3", "0x03",
    "1", "2", "3"
};
static char *aead_str_list[] = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
    "0x1", "0x01", "0x2", "0x02", "0x3", "0x03",
    "1", "2", "3"
};
/* table of bogus strings that better not work */
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
        unsigned char psk[OSSL_HPKE_MAXSIZE];
        unsigned char *pskp = NULL;
        char pskid[OSSL_HPKE_MAXSIZE];
        size_t psklen = OSSL_HPKE_MAXSIZE;
        char *pskidp = NULL;
        EVP_PKEY *privp = NULL;
        OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
        size_t plainlen = OSSL_HPKE_MAXSIZE;
        unsigned char plain[OSSL_HPKE_MAXSIZE];
        uint64_t startseq = 0;
        OSSL_HPKE_CTX *rctx = NULL;
        int erv = 1;
        OSSL_HPKE_CTX *ctx = NULL;

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
            EVP_PKEY *authpriv_evp = NULL;

            hpke_suite.kem_id = kem_id;
            /* can only set AUTH key pair when we know KEM */
            if ((hpke_mode == OSSL_HPKE_MODE_AUTH) ||
                (hpke_mode == OSSL_HPKE_MODE_PSKAUTH)) {
                if (TEST_true(OSSL_HPKE_keygen(testctx, NULL,
                                               hpke_mode, hpke_suite,
                                               NULL, 0,
                                               authpub, &authpublen,
                                               &authpriv_evp)) != 1) {
                    overallresult = 0;
                }
                authpubp = authpub;
            } else {
                authpublen = 0;
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
                    size_t senderpublen = OSSL_HPKE_MAXSIZE;
                    unsigned char senderpub[OSSL_HPKE_MAXSIZE];
                    size_t cipherlen = OSSL_HPKE_MAXSIZE;
                    unsigned char cipher[OSSL_HPKE_MAXSIZE];
                    size_t clearlen = OSSL_HPKE_MAXSIZE;
                    unsigned char clear[OSSL_HPKE_MAXSIZE];

                    hpke_suite.aead_id = aead_id;
                    if (!TEST_true(OSSL_HPKE_keygen(testctx, NULL,
                                                    hpke_mode, hpke_suite,
                                                    NULL, 0,
                                                    pub, &publen, &privp)))
                        overallresult = 0;

                    ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                            testctx, NULL);
                    if (ctx == NULL) {
                        overallresult = 0;
                    }
                    if (hpke_mode == OSSL_HPKE_MODE_PSK
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        erv = OSSL_HPKE_CTX_set1_psk(ctx, pskidp, pskp, psklen);
                        if (erv != 1) {
                            overallresult = 0;
                        }
                    }
                    if (hpke_mode == OSSL_HPKE_MODE_AUTH
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        erv = OSSL_HPKE_CTX_set1_authpriv(ctx, authpriv_evp);
                        if (erv != 1) {
                            overallresult = 0;
                        }
                    }
                    /* randomly use a non zero sequnce */
                    if (COIN_IS_HEADS) {
                        RAND_bytes_ex(testctx,
                                      (unsigned char *) &startseq,
                                      sizeof(startseq),
                                      RAND_DRBG_STRENGTH);
                        erv = OSSL_HPKE_CTX_set1_seq(ctx, startseq);
                        if (erv != 1) {
                            overallresult = 0;
                        }
                    } else {
                        startseq = 0;
                    }
                    erv = OSSL_HPKE_sender_seal(ctx, senderpub, &senderpublen,
                                                cipher, &cipherlen,
                                                pub, publen, infop, infolen,
                                                aadp, aadlen, plain, plainlen);
                    if (erv != 1) {
                        overallresult = 0;
                    }
                    OSSL_HPKE_CTX_free(ctx);

                    memset(clear, 0, clearlen);

                    rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                             testctx, NULL);
                    if (rctx == NULL) {
                        overallresult = 0;
                    }
                    if (hpke_mode == OSSL_HPKE_MODE_PSK
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        erv = OSSL_HPKE_CTX_set1_psk(rctx, pskidp,
                                                     pskp, psklen);
                        if (erv != 1) {
                            overallresult = 0;
                        }
                    }
                    if (hpke_mode == OSSL_HPKE_MODE_AUTH
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        erv = OSSL_HPKE_CTX_set1_authpub(rctx,
                                                         authpubp, authpublen);
                        if (erv != 1) {
                            overallresult = 0;
                        }
                    }
                    if (startseq != 0) {
                        erv = OSSL_HPKE_CTX_set1_seq(rctx, startseq);
                        if (erv != 1) {
                            overallresult = 0;
                        }
                    }
                    erv = OSSL_HPKE_recipient_open(rctx, clear, &clearlen,
                                                   senderpub, senderpublen,
                                                   privp,
                                                   infop, infolen,
                                                   aadp, aadlen,
                                                   cipher, cipherlen);
                    if (erv != 1) {
                        overallresult = 0;
                    }
                    OSSL_HPKE_CTX_free(rctx);

                    EVP_PKEY_free(privp);
                    privp = NULL;
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
            EVP_PKEY_free(authpriv_evp);
        }
    }
    return overallresult;
}

/**
 * @brief check roundtrpi for export
 * @return 1 for success, other otherwise
 */
static int test_hpke_export(void)
{
    EVP_PKEY *privp = NULL;
    unsigned char pub[OSSL_HPKE_MAXSIZE];
    size_t publen = sizeof(pub);
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *ctx = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    unsigned char exp[32];
    unsigned char rexp[32];
    unsigned char plain[] = "quick brown fox";
    size_t plainlen = sizeof(plain);
    unsigned char enc[OSSL_HPKE_MAXSIZE];
    size_t enclen = sizeof(enc);
    unsigned char cipher[OSSL_HPKE_MAXSIZE];
    size_t cipherlen = sizeof(cipher);
    unsigned char clear[OSSL_HPKE_MAXSIZE];
    size_t clearlen = sizeof(clear);
    char * estr = "foo";

    if (!TEST_true(OSSL_HPKE_keygen(testctx, NULL,
                                    hpke_mode, hpke_suite,
                                    NULL, 0,
                                    pub, &publen, &privp)))
        goto end;

    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                          testctx, NULL)))
        goto end;

    if (!TEST_true(OSSL_HPKE_sender_seal(ctx, enc, &enclen,
                                         cipher, &cipherlen, pub, publen,
                                         NULL, 0, NULL, 0, /* no add, info */
                                         plain, plainlen)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_export(ctx, exp, 32,
                                        (unsigned char *)estr, strlen(estr))))
        goto end;

    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                           testctx, NULL)))
        goto end;
    if (!TEST_true(OSSL_HPKE_recipient_open(rctx, clear, &clearlen,
                                            enc, enclen,
                                            privp,
                                            NULL, 0, NULL, 0,
                                            cipher, cipherlen)))
        goto end;

    if (!TEST_true(OSSL_HPKE_CTX_export(rctx, rexp, 32,
                                        (unsigned char *)estr, strlen(estr))))
        goto end;

    if (!TEST_true(TEST_mem_eq(exp, 32, rexp, 32)))
        goto end;

    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    EVP_PKEY_free(privp);
    return 1;
end:
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    EVP_PKEY_free(privp);
    return 0;
}

/**
 * @brief Check mapping from strings to HPKE suites
 * @return 1 for success, other otherwise
 */
static int test_hpke_suite_strs(void)
{
    int overallresult = 1;
    int kemind = 0;
    int kdfind = 0;
    int aeadind = 0;
    int sind = 0;
    char sstr[128];
    OSSL_HPKE_SUITE stirred;

    for (kemind = 0;
         kemind != (sizeof(kem_str_list) / sizeof(char *));
         kemind++) {
        for (kdfind = 0;
             kdfind != (sizeof(kdf_str_list) / sizeof(char *));
             kdfind++) {
            for (aeadind = 0;
                 aeadind != (sizeof(aead_str_list) / sizeof(char *));
                 aeadind++) {
                snprintf(sstr, 128, "%s,%s,%s",
                         kem_str_list[kemind],
                         kdf_str_list[kdfind],
                         aead_str_list[aeadind]);
                if (TEST_true(OSSL_HPKE_str2suite(sstr, &stirred)) != 1) {
                    overallresult = 0;
                }
            }
        }
    }
    for (sind = 0;
         sind != (sizeof(bogus_suite_strs) / sizeof(char *));
         sind++) {
        char dstr[128];

        sprintf(dstr, "str2suite: %s", bogus_suite_strs[sind]);
        if (TEST_false(OSSL_HPKE_str2suite(bogus_suite_strs[sind],
                                           &stirred)) != 1) {
            overallresult = 0;
        }
    }
    return overallresult;
}

/**
 * @brief try the various GREASEy APIs
 * @return 1 for success, other otherwise
 */
static int test_hpke_grease(void)
{
    int overallresult = 1;
    OSSL_HPKE_SUITE g_suite;
    unsigned char g_pub[OSSL_HPKE_MAXSIZE];
    size_t g_pub_len = OSSL_HPKE_MAXSIZE;
    unsigned char g_cipher[OSSL_HPKE_MAXSIZE];
    size_t g_cipher_len = 266;
    size_t clearlen = 128;
    size_t expanded = 0;
    size_t enclen = 0;

    memset(&g_suite, 0, sizeof(OSSL_HPKE_SUITE));
    /* GREASEing */
    if (TEST_true(OSSL_HPKE_good4grease(testctx, NULL, NULL, &g_suite,
                                        g_pub, &g_pub_len,
                                        g_cipher, g_cipher_len)) != 1) {
        overallresult = 0;
    }
    /* expansion */
    if (TEST_true(OSSL_HPKE_expansion(g_suite, &enclen,
                                      clearlen, &expanded)) != 1) {
        overallresult = 0;
    }
    if (expanded <= clearlen) {
        overallresult = 0;
    }
    return overallresult;
}

/**
 * @brief try some fuzzy-ish kg, enc & dec calls
 * @return 1 for success, other otherwise
 */
static int test_hpke_badcalls(void)
{
    int overallresult = 1;
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char buf1[OSSL_HPKE_MAXSIZE];
    unsigned char buf2[OSSL_HPKE_MAXSIZE];
    unsigned char buf3[OSSL_HPKE_MAXSIZE];
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
    EVP_PKEY *privp = NULL;
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

    /* pub is NULL now */
    if (TEST_false(OSSL_HPKE_keygen(testctx, NULL, hpke_mode, hpke_suite,
                                    NULL, 0, pub, &publen, &privp)) != 1) {
        overallresult = 0;
    }

    pub = buf1;
    publen = sizeof(buf1);
    /* bogus kem_id */
    hpke_suite.kem_id = 100;
    if (TEST_false(OSSL_HPKE_keygen(testctx, NULL, hpke_mode, hpke_suite,
                                    NULL, 0, pub, &publen, &privp)) != 1) {
        overallresult = 0;
    }

    /* a good key to tee up bad calls below */
    hpke_suite.kem_id = 0x20;
    if (TEST_true(OSSL_HPKE_keygen(testctx, NULL, hpke_mode, hpke_suite,
                                   NULL, 0, pub, &publen, &privp)) != 1) {
        overallresult = 0;
    }

    if (TEST_false(OSSL_HPKE_enc(testctx, NULL, hpke_mode, hpke_suite,
                                 pskidp, pskp, psklen,
                                 pub, publen,
                                 authprivp, authprivlen, NULL,
                                 plain, plainlen,
                                 aadp, aadlen,
                                 infop, infolen,
                                 seqp, seqlen,
                                 senderpub, &senderpublen, NULL,
                                 cipher, &cipherlen)) != 1) {
        overallresult = 0;
    }
    if (TEST_false(OSSL_HPKE_dec(testctx, NULL, hpke_mode, hpke_suite,
                                 pskidp, pskp, psklen,
                                 authpubp, authpublen,
                                 NULL, 0, privp,
                                 senderpub, senderpublen,
                                 cipher, cipherlen,
                                 aadp, aadlen,
                                 infop, infolen,
                                 seqp, seqlen,
                                 clear, &clearlen)) != 1) {
        overallresult = 0;
    }
    if (TEST_false(OSSL_HPKE_enc(testctx, NULL, hpke_mode, hpke_suite,
                                 pskidp, pskp, psklen,
                                 pub, publen,
                                 authprivp, authprivlen, NULL,
                                 plain, plainlen,
                                 aadp, aadlen,
                                 infop, infolen,
                                 seqp, seqlen,
                                 senderpub, &senderpublen, NULL,
                                 cipher, &cipherlen)) != 1) {
        overallresult = 0;
    }

    if (overallresult != 1) {
        EVP_PKEY_free(privp);
        return overallresult;
    }

    /* same cipher and senderpub buffer */
    plain = buf2;
    plainlen = sizeof(buf2) - 64; /* leave room for tag */
    memset(plain, 0, plainlen);
    cipher = buf3;
    cipherlen = sizeof(buf3);
    memset(cipher, 0, cipherlen);
    senderpub = buf3;
    senderpublen = sizeof(buf3);
    if (TEST_true(OSSL_HPKE_enc(testctx, NULL, hpke_mode, hpke_suite,
                                pskidp, pskp, psklen,
                                pub, publen,
                                authprivp, authprivlen, NULL,
                                plain, plainlen,
                                aadp, aadlen,
                                infop, infolen,
                                seqp, seqlen,
                                senderpub, &senderpublen, NULL,
                                cipher, &cipherlen)) != 1) {
        overallresult = 0;
    }
    EVP_PKEY_free(privp);
    return overallresult;
}

#ifndef OPENSSL_NO_ASM
/*
 * NIST p256 key pair from HPKE-07 test vectors
 * FIXME: I have no idea why, but as of now building
 * with "no-asm" causes a file in a call to EC_POINT_mul
 * that's used in this test. That shows up in various
 * CI builds/tests so we'll avoid that for now by
 * just not doing that test in that case. The failure
 * is also specific to using the non-default library
 * context oddly.
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
#endif

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

    if (OSSL_HPKE_prbuf2evp(testctx, NULL, kem_id, priv, privlen, NULL, 0, &sk)
        != 1) {
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
    return res;
}

/*
 * @brief call test_hpke_one_priv_gen for a couple of known test vectors
 * @return 1 for good, 0 otherwise
 */
static int test_hpke_gen_from_priv(void)
{
    int res = 0;

#ifndef OPENSSL_NO_ASM
    /*
     * NIST P-256 case
     * FIXME: I have no idea why, but as of now building
     * with "no-asm" causes a file in a call to EC_POINT_mul
     * that's used in this test. That shows up in various
     * CI builds/tests so we'll avoid that for now by
     * just not doing that test in that case. The failure
     * is also specific to using the non-default library
     * context oddly.
     */
    res = test_hpke_one_key_gen_from_priv(0x10,
                                          n256priv, sizeof(n256priv),
                                          n256pub, sizeof(n256pub));
    if (res != 1) { return res; }
#endif

    /* X25519 case */
    res = test_hpke_one_key_gen_from_priv(0x20,
                                          x25519priv, sizeof(x25519priv),
                                          x25519pub, sizeof(x25519pub));
    if (res != 1) { return res; }

    return res;
}

/* from RFC 9180 Appendix A.1.1 */
static unsigned char ikm25519[] = {
    0x72, 0x68, 0x60, 0x0d, 0x40, 0x3f, 0xce, 0x43,
    0x15, 0x61, 0xae, 0xf5, 0x83, 0xee, 0x16, 0x13,
    0x52, 0x7c, 0xff, 0x65, 0x5c, 0x13, 0x43, 0xf2,
    0x98, 0x12, 0xe6, 0x67, 0x06, 0xdf, 0x32, 0x34
};
static unsigned char pub25519[] = {
    0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28,
    0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d,
    0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44,
    0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31
};

/* from RFC9180 Appendix A.3.1 */
static unsigned char ikmp256[] = {
    0x42, 0x70, 0xe5, 0x4f, 0xfd, 0x08, 0xd7, 0x9d,
    0x59, 0x28, 0x02, 0x0a, 0xf4, 0x68, 0x6d, 0x8f,
    0x6b, 0x7d, 0x35, 0xdb, 0xe4, 0x70, 0x26, 0x5f,
    0x1f, 0x5a, 0xa2, 0x28, 0x16, 0xce, 0x86, 0x0e
};
static unsigned char pubp256[] = {
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

/*
 * A test vector that exercises the counter iteration
 * for p256. This was contributed by Ilari L. on the
 * CFRG list, see the mail archive:
 * https://mailarchive.ietf.org/arch/msg/cfrg/4zwl_y5YN6OU9oeWZOMHNOlOa2w/
 */
static unsigned char ikmiter[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x38, 0xb5, 0xec
};
static unsigned char pubiter[] = {
    0x04, 0x7d, 0x0c, 0x87, 0xff, 0xd5, 0xd1, 0x45,
    0x54, 0xa7, 0x51, 0xdf, 0xa3, 0x99, 0x26, 0xa9,
    0xe3, 0x0e, 0x7c, 0x3c, 0x65, 0x62, 0x4f, 0x4b,
    0x5f, 0xb3, 0xad, 0x7a, 0xa4, 0xda, 0xc2, 0x4a,
    0xd8, 0xf5, 0xbe, 0xd0, 0xe8, 0x6e, 0xb8, 0x84,
    0x1c, 0xe4, 0x89, 0x2e, 0x0f, 0xc3, 0x87, 0xbb,
    0xdb, 0xfe, 0x16, 0x0d, 0x58, 0x9c, 0x89, 0x2d,
    0xd4, 0xb1, 0x46, 0x4a, 0xc3, 0x51, 0xc5, 0x6f,
    0xb6
};

/* from RFC9180 Appendix A.6.1 */
static unsigned char ikmp521[] = {
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
static unsigned char pubp521[] = {
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
 * This calls OSSL_HPKE_keygen specifying only the IKM, then
 * compares the key pair values with the already-known values
 * that were input.
 */
static int test_hpke_one_ikm_gen(uint16_t kem_id,
                                 unsigned char *ikm, size_t ikmlen,
                                 unsigned char *pub, size_t publen)
{
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char lpub[OSSL_HPKE_MAXSIZE];
    size_t lpublen = OSSL_HPKE_MAXSIZE;
    EVP_PKEY *sk = NULL;

    hpke_suite.kem_id = kem_id;
    if (OSSL_HPKE_keygen(testctx, NULL, hpke_mode, hpke_suite,
                         ikm, ikmlen, lpub, &lpublen, &sk) != 1) {
        return - __LINE__;
    }
    if (sk == NULL)
        return - __LINE__;
    EVP_PKEY_free(sk);
    if (lpublen != publen)
        return - __LINE__;
    if (memcmp(pub, lpub, publen))
        return - __LINE__;

    return 1;
}

static int test_hpke_ikms(void)
{
    int res = 1;

    res = test_hpke_one_ikm_gen(0x20,
                                ikm25519, sizeof(ikm25519),
                                pub25519, sizeof(pub25519));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(0x12,
                                ikmp521, sizeof(ikmp521),
                                pubp521, sizeof(pubp521));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(0x10,
                                ikmp256, sizeof(ikmp256),
                                pubp256, sizeof(pubp256));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(0x10,
                                ikmiter, sizeof(ikmiter),
                                pubiter, sizeof(pubiter));
    if (res != 1)
        return res;

    return res;
}

static int test_hpke(void)
{
    int res = 1;

    res = test_hpke_export();
    if (res != 1)
        return res;

    res = test_hpke_modes_suites();
    if (res != 1)
        return res;

    res = test_hpke_suite_strs();
    if (res != 1)
        return res;

    res = test_hpke_grease();
    if (res != 1)
        return res;

    res = test_hpke_badcalls();
    if (res != 1)
        return res;

    res = test_hpke_gen_from_priv();
    if (res != 1)
        return res;

    res = test_hpke_ikms();
    if (res != 1)
        return res;

    return res;
}
/* don't do this yet 'till we move outta evp_extra_test */
int setup_tests(void)
{
    ADD_TEST(x25519kdfsha256_hkdfsha256_aes128gcm_base_test);
    ADD_TEST(x25519kdfsha256_hkdfsha256_aes128gcm_psk_test);
    ADD_TEST(P256kdfsha256_hkdfsha256_aes128gcm_base_test);
    ADD_TEST(test_hpke);
    return 1;
}
void cleanup_tests(void)
{
}
