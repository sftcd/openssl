/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file Handle error strings in libcrypto
 *
 * Not actually sure this is done the right way. Could be other/better
 * ways to handle it. 
 */

#include <openssl/err.h>
#include <openssl/esni.h>
#include <openssl/esnierr.h>

/** 
 * ESNI error function strings - inspired by crypto/ct/cterr.c
 */
static const ERR_STRING_DATA ESNI_str_functs[] = {
    {ERR_PACK(ERR_LIB_ESNI, ESNI_F_BASE64_DECODE, 0), "base64 decode"},
    {ERR_PACK(ERR_LIB_ESNI, ESNI_F_NEW_FROM_BASE64, 0), "read from RR"},
    {ERR_PACK(ERR_LIB_ESNI, ESNI_F_ENC, 0), "encrypt ESNI details"},
    {ERR_PACK(ERR_LIB_ESNI, ESNI_F_DEC, 0), "decrypt ESNI details"},
    {ERR_PACK(ERR_LIB_ESNI, ESNI_F_SERVER_ENABLE, 0), "server enable"},
    {0, NULL}
};

/** 
 * ESNI error reason strings - inspired by crypto/ct/cterr.c
 */
static const ERR_STRING_DATA ESNI_str_reasons[] = {
    {ERR_PACK(ERR_LIB_ESNI, 0, ESNI_R_BASE64_DECODE_ERROR), "base64 decode error"},
    {ERR_PACK(ERR_LIB_ESNI, 0, ESNI_R_RR_DECODE_ERROR), "DNS resource record decode error"},
    {ERR_PACK(ERR_LIB_ESNI, 0, ESNI_R_NOT_IMPL), "feature not implemented"},
    {0, NULL}
};

/**
 * Load strings into tables.
 *
 * @return 1 for success, not 1 otherwise
 */
int ERR_load_ESNI_strings(void)
{
#ifndef OPENSSL_NO_ESNI
    if (ERR_func_error_string(ESNI_str_functs[0].error) == NULL) {
        ERR_load_strings_const(ESNI_str_functs);
        ERR_load_strings_const(ESNI_str_reasons);
    }
#endif
    return 1;
}

