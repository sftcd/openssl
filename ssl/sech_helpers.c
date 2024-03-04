/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal data structures and prototypes for handling
 * stealthy Encrypted ClientHello (SECH)
 */
#ifndef OPENSSL_NO_ECH
#define SECH_SYMMETRIC_KEY_MAX_LENGTH 1024
// int sech_function_definition_to_find(void);
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

int encrypt_symmetric(char * plain, char * key_bytes, char * cipher) {
    return 0;
}

int unsafe_encrypt_aes256cbc(char * plain, unsigned char * somekey, char * cipher) {
    unsigned char outbuf[1024];
    int outlen, tmplen;
    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    unsigned char iv[] = {1,2,3,4,5,6,7,8};
    char intext[] = "Some Crypto Text";
    EVP_CIPHER_CTX *ctx;
    FILE *out;

    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex2(ctx, EVP_idea_cbc(), key, iv, NULL)) {
        /* Error */
        fprintf(stderr, "SECH: error in EVP_EncryptInit_ex2\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    return 1;
}
//     int res = 0;
//     EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
//     if(ctx == NULL) {
//         fprintf(stderr, "SECH: cipher ctx is NULL\n");
//     }
//     EVP_CIPHER * aes256cbc = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
//     unsigned char outbuf[1024];
//     int outlen, tmplen;
//     unsigned char lkey[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
//     unsigned char iv[] = {1,2,3,4,5,6,7,8};
//     fprintf(stderr,  "SECH: aes356cbc cb: %p\n", aes256cbc);
//     if( !EVP_EncryptInit_ex2(
//           ctx,
//           EVP_idea_cbc(), // aes256cbc,
//           lkey,
//           iv,// const unsigned char * iv; initialization vector
//           NULL
//           ) ||
//       1)   
//     {
//         fprintf(stderr, "SECH: encountered error in EVP_EncryptInit_ex2\n");
//         goto end;
//     }
//     if( !EVP_EncryptUpdate(
//           ctx,
//           outbuf,
//           &outlen,
//           plain,
//           strlen(plain)) ||
//       1)   
//     {
//         fprintf(stderr, "SECH: encountered error in EVP_EncryptUpdate\n");
//         goto end;
//     }
//     if( !EVP_EncryptFinal_ex(
//           ctx, // EVP_CIPHER_CTX *ctx,
//           outbuf + outlen,
//           &tmplen) ||
//       1)   
//     {
//         fprintf(stderr, "SECH: encountered error in EVP_EncryptFinal_ex\n");
//         goto end;
//     }
//     outlen += tmplen;
//     fprintf(stderr, "SECH: inlen: %lu\n", strlen(plain));
//     fprintf(stderr, "SECH: outlen: %i\n", outlen);
//     for(int i = 0; i < outlen; ++i) {
//         fprintf(stderr, "%02X ",(unsigned char) outbuf[i]);
//     } fprintf(stderr, "\n");
// end:
//     EVP_CIPHER_CTX_free(ctx);
//     return res;
// 
// }

int do_crypt(char *outfile)
{
    unsigned char outbuf[1024];
    int outlen, tmplen;
    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    unsigned char iv[] = {1,2,3,4,5,6,7,8};
    char intext[] = "Some Crypto Text";
    EVP_CIPHER_CTX *ctx;
    FILE *out;

    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex2(ctx, EVP_idea_cbc(), key, iv, NULL)) {
        /* Error */
        fprintf(stderr, "SECH: error in EVP_EncryptInit_ex2\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, intext, strlen(intext))) {
        /* Error */
        fprintf(stderr, "SECH: error in EVP_EncryptUpdate\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    /*
     * Buffer passed to EVP_EncryptFinal() must be after data just
     * encrypted to avoid overwriting it.
     */
    if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    /*
     * Need binary mode for fopen because encrypted data is
     * binary data. Also cannot use strlen() on it because
     * it won't be NUL terminated and may contain embedded
     * NULs.
     */
    out = fopen(outfile, "wb");
    if (out == NULL) {
        /* Error */
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);
    fclose(out);
    return 1;
}

#endif
