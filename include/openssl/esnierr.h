/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/** 
 * @file
 * Error strings for ESNI
 */

/*
 * code within here should be openssl-style
 */
#ifndef OPENSSL_NO_ESNI

#ifndef HEADER_ESNIERR_H
# define HEADER_ESNIERR_H

# include <openssl/opensslconf.h>

/* 
 * ESNI function codes for ESNIerr
 * These may need to be >100 (or might be convention)
 */
#define ESNI_F_BASE64_DECODE                            101
#define ESNI_F_NEW_FROM_BASE64                          102
#define ESNI_F_ENC                                      103
#define ESNI_F_CHECKSUM_CHECK                           104

/*
 * ESNI reason codes for ESNIerr
 * These should be >100
 */
#define ESNI_R_BASE64_DECODE_ERROR                      110
#define ESNI_R_RR_DECODE_ERROR                          111
#define ESNI_R_NOT_IMPL                                 112


/*
 * Prototypes
 */

#  ifdef  __cplusplus
extern "C"
#  endif

/**
 * Load strings into tables.
 *
 * @return 1 for success, not 1 otherwise
 */
int ERR_load_ESNI_strings(void);

 #endif
#endif
