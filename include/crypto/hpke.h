/*
 * Copyright 2019 Stephen Farrell. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file 
 * This has the data structures and prototypes (both internal and external)
 * for an OpenSSL-based HPKE implementation following draft-irtf-cfrg-hpke
 *
 * I plan to use this for my ESNI-enabled OpenSSL build when the time is 
 * right, that's: https://github.com/sftcd/openssl)
 */

#ifndef HPKE_H_INCLUDED
#define HPKE_H_INCLUDED

#include <openssl/ssl.h>

/* biggest/default buffer we use */
#define HPKE_MAXSIZE (40*1024) ///< 40k is more than enough for anyone (using this program:-)

/*
 * The HPKE modes 
 */
#define HPKE_MODE_BASE              0 ///< Base mode 
#define HPKE_MODE_PSK               1 ///< Pre-shared key mode
#define HPKE_MODE_AUTH              2 ///< Authenticated mode
#define HPKE_MODE_PSKAUTH           3 ///< PSK+authenticated mode

/*
 * The (16bit) HPKE algorithn IDs
 */
#define HPKE_KEM_ID_RESERVED         0x0000 ///< not used
#define HPKE_KEM_ID_P256             0x0010 ///< NIST P-256
#define HPKE_KEM_ID_P384             0x0011 ///< NIST P-256
#define HPKE_KEM_ID_P521             0x0012 ///< NIST P-521
#define HPKE_KEM_ID_25519            0x0020 ///< Curve25519
#define HPKE_KEM_ID_448              0x0021 ///< Curve448

#define HPKE_KDF_ID_RESERVED         0x0000 ///< not used
#define HPKE_KDF_ID_HKDF_SHA256      0x0001 ///< HKDF-SHA256
#define HPKE_KDF_ID_HKDF_SHA384      0x0002 ///< HKDF-SHA512
#define HPKE_KDF_ID_HKDF_SHA512      0x0003 ///< HKDF-SHA512
#define HPKE_KDF_ID_MAX              0x0003 ///< HKDF-SHA512

#define HPKE_AEAD_ID_RESERVED        0x0000 ///< not used
#define HPKE_AEAD_ID_AES_GCM_128     0x0001 ///< AES-GCM-128
#define HPKE_AEAD_ID_AES_GCM_256     0x0002 ///< AES-GCM-256
#define HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 ///< Chacha20-Poly1305
#define HPKE_AEAD_ID_MAX             0x0003 ///< Chacha20-Poly1305

/* strings for modes */
#define HPKE_MODESTR_BASE       "base"              ///< base mode (1), no sender auth
#define HPKE_MODESTR_PSK        "psk"               ///< psk mode (2)
#define HPKE_MODESTR_AUTH       "auth"              ///< auth (3), with a sender-key pair
#define HPKE_MODESTR_PSKAUTH    "pskauth"           ///< psk+sender-key pair (4)

/* strings for suites */
#define HPKE_KEMSTR_P256        "p256"              ///< KEM id 0x10
#define HPKE_KEMSTR_P384        "p384"              ///< KEM id 0x11
#define HPKE_KEMSTR_P521        "p521"              ///< KEM id 0x12
#define HPKE_KEMSTR_X25519      "x25519"            ///< KEM id 0x20
#define HPKE_KEMSTR_X448        "x448"              ///< KEM id 0x21
#define HPKE_KDFSTR_256         "hkdf-sha256"       ///< KDF id 1
#define HPKE_KDFSTR_384         "hkdf-sha384"       ///< KDF id 2
#define HPKE_KDFSTR_512         "hkdf-sha512"       ///< KDF id 3
#define HPKE_AEADSTR_AES128GCM  "aes128gcm"         ///< AEAD id 1
#define HPKE_AEADSTR_AES256GCM  "aes256gcm"         ///< AEAD id 2
#define HPKE_AEADSTR_CP         "chachapoly1305"    ///< AEAD id 3

/*!
 * @brief ciphersuite combination
 */
typedef struct {
    uint16_t    kem_id; ///< Key Encryption Method id
    uint16_t    kdf_id; ///< Key Derivation Function id
    uint16_t    aead_id; ///< Authenticated Encryption with Associated Data id
} hpke_suite_t;

/*!
 * Two suite constants, use this like: 
 *
 *          hpke_suite_t myvar = HPKE_SUITE_DEFAULT;
 */
#define HPKE_SUITE_DEFAULT { HPKE_KEM_ID_25519, HPKE_KDF_ID_HKDF_SHA256, HPKE_AEAD_ID_AES_GCM_128 }
#define HPKE_SUITE_TURNITUPTO11 { HPKE_KEM_ID_448, HPKE_KDF_ID_HKDF_SHA512, HPKE_AEAD_ID_CHACHA_POLY1305 }


/*!
 * @brief  Map ascii to binary - utility macro used in >1 place 
 */
#define HPKE_A2B(__c__) (__c__>='0'&&__c__<='9'?(__c__-'0'):\
                        (__c__>='A'&&__c__<='F'?(__c__-'A'+10):\
                        (__c__>='a'&&__c__<='f'?(__c__-'a'+10):0)))
/*
 * @brief HPKE single-shot encryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk 
 * @param publen is the length of the public key
 * @param pub is the encoded public key
 * @param privlen is the length of the private (authentication) key
 * @param priv is the encoded private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the lenght of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param senderpublen is the length of the input buffer for the sender's public key (length used on output)
 * @param senderpub is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext (length used on output)
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 *
 * Oddity: we're passing an hpke_suit_t directly, but 48 bits is actually
 * smaller than a 64 bit pointer, so that's grand, if odd:-)
 */
int hpke_enc(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t *senderpublen, unsigned char *senderpub,
        size_t *cipherlen, unsigned char *cipher
#ifdef TESTVECTORS
        , void *tv
#endif
        );

/*
 * @brief HPKE single-shot decryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk 
 * @param publen is the length of the public (authentication) key
 * @param pub is the encoded public (authentication) key
 * @param privlen is the length of the private key
 * @param priv is the encoded private key
 * @param evppriv is a pointer to an internal form of private key
 * @param enclen is the length of the peer's public value
 * @param enc is the peer's public value
 * @param cipherlen is the length of the ciphertext 
 * @param cipher is the ciphertext
 * @param aadlen is the lenght of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param clearlen is the length of the input buffer for cleartext (octets used on output)
 * @param clear is the encoded cleartext
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_dec(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        EVP_PKEY *evppriv,
        size_t enclen, unsigned char *enc,
        size_t cipherlen, unsigned char *cipher,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t *clearlen, unsigned char *clear);

/*!
 * @brief generate a key pair
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_kg(
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        size_t *privlen, unsigned char *priv); 

/**
 * @brief decode ascii hex to a binary buffer
 *
 * @param ahlen is the ascii hex string length
 * @param ah is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_ah_decode(size_t ahlen, const char *ah, size_t *blen, unsigned char **buf);

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not-1 otherwise
 */
int hpke_suite_check(hpke_suite_t suite);

#endif

