/*
 * Copyright 2019-2021 Stephen Farrell. All Rights Reserved.
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
 */

#ifndef HPKE_H_INCLUDED
#define HPKE_H_INCLUDED

#include <openssl/ssl.h>

/* biggest/default buffer we use */
#define HPKE_MAXSIZE (40*1024) /**< 40k is more than enough for anyone (using this program:-) */

/*
 * The HPKE modes 
 */
#define HPKE_MODE_BASE              0 /**< Base mode  */
#define HPKE_MODE_PSK               1 /**< Pre-shared key mode */
#define HPKE_MODE_AUTH              2 /**< Authenticated mode */
#define HPKE_MODE_PSKAUTH           3 /**< PSK+authenticated mode */

/*
 * The (16bit) HPKE algorithn IDs
 */
#define HPKE_KEM_ID_RESERVED         0x0000 /**< not used */
#define HPKE_KEM_ID_P256             0x0010 /**< NIST P-256 */
#define HPKE_KEM_ID_P384             0x0011 /**< NIST P-256 */
#define HPKE_KEM_ID_P521             0x0012 /**< NIST P-521 */
#define HPKE_KEM_ID_25519            0x0020 /**< Curve25519 */
#define HPKE_KEM_ID_448              0x0021 /**< Curve448 */

#define HPKE_KDF_ID_RESERVED         0x0000 /**< not used */
#define HPKE_KDF_ID_HKDF_SHA256      0x0001 /**< HKDF-SHA256 */
#define HPKE_KDF_ID_HKDF_SHA384      0x0002 /**< HKDF-SHA512 */
#define HPKE_KDF_ID_HKDF_SHA512      0x0003 /**< HKDF-SHA512 */
#define HPKE_KDF_ID_MAX              0x0003 /**< HKDF-SHA512 */

#define HPKE_AEAD_ID_RESERVED        0x0000 /**< not used */
#define HPKE_AEAD_ID_AES_GCM_128     0x0001 /**< AES-GCM-128 */
#define HPKE_AEAD_ID_AES_GCM_256     0x0002 /**< AES-GCM-256 */
#define HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 /**< Chacha20-Poly1305 */
#define HPKE_AEAD_ID_MAX             0x0003 /**< Chacha20-Poly1305 */

/* strings for modes */
#define HPKE_MODESTR_BASE       "base"              /**< base mode (1), no sender auth */
#define HPKE_MODESTR_PSK        "psk"               /**< psk mode (2) */
#define HPKE_MODESTR_AUTH       "auth"              /**< auth (3), with a sender-key pair */
#define HPKE_MODESTR_PSKAUTH    "pskauth"           /**< psk+sender-key pair (4) */

/* strings for suites */
#define HPKE_KEMSTR_P256        "p256"              /**< KEM id 0x10 */
#define HPKE_KEMSTR_P384        "p384"              /**< KEM id 0x11 */
#define HPKE_KEMSTR_P521        "p521"              /**< KEM id 0x12 */
#define HPKE_KEMSTR_X25519      "x25519"            /**< KEM id 0x20 */
#define HPKE_KEMSTR_X448        "x448"              /**< KEM id 0x21 */
#define HPKE_KDFSTR_256         "hkdf-sha256"       /**< KDF id 1 */
#define HPKE_KDFSTR_384         "hkdf-sha384"       /**< KDF id 2 */
#define HPKE_KDFSTR_512         "hkdf-sha512"       /**< KDF id 3 */
#define HPKE_AEADSTR_AES128GCM  "aes128gcm"         /**< AEAD id 1 */
#define HPKE_AEADSTR_AES256GCM  "aes256gcm"         /**< AEAD id 2 */
#define HPKE_AEADSTR_CP         "chachapoly1305"    /**< AEAD id 3 */

/*!
 * @brief ciphersuite combination
 */
typedef struct {
    uint16_t    kem_id; /**< Key Encryption Method id */
    uint16_t    kdf_id; /**< Key Derivation Function id */
    uint16_t    aead_id; /**< Authenticated Encryption with Associated Data id */
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
 *
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
 * @param senderpub is the input buffer for sender public key
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
 * @brief HPKE single-shot encryption function, with externally supplied sender key pair
 *
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
 * @param senderpublen is the length of the input buffer with the sender's public key 
 * @param senderpub is the input buffer for sender public key
 * @param senderpriv has the handle for the sender private key
 * @param cipherlen is the length of the input buffer for ciphertext (length used on output)
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 *
 * Oddity: we're passing an hpke_suit_t directly, but 48 bits is actually
 * smaller than a 64 bit pointer, so that's grand, if odd:-)
 */
int hpke_enc_evp(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t senderpublen, unsigned char *senderpub, EVP_PKEY *senderpriv,
        size_t *cipherlen, unsigned char *cipher
#ifdef TESTVECTORS
        , void *tv
#endif
        );

/*!
 * @brief Internal HPKE single-shot encryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk 
 * @param publen is the length of the recipient public key
 * @param pub is the encoded recipient public key
 * @param privlen is the length of the private (authentication) key
 * @param priv is the encoded private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the lenght of the additional data (can be zero)
 * @param aad is the encoded additional data (can be NULL)
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param senderpublen is the length of the input buffer with the sender's public key 
 * @param senderpub is the input buffer for sender public key
 * @param senderpriv has the handle for the sender private key
 * @param cipherlen is the length of the input buffer for ciphertext (length used on output)
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_enc_raw(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t extsenderpublen, unsigned char *extsenderpub, 
        size_t rawsenderprivlen,  unsigned char *rawsenderpriv,
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

/*!
 * @brief generate a key pair but keep private inside API
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key handle
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_kg_evp(
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        EVP_PKEY **priv);

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

/*
 * These are temporary and only needed for esni-draft-09
 * where we gotta call 'em from outside
 */

/*!
 * brief RFC5869 HKDF-Extract
 *
 * @param suite is the ciphersuite 
 * @param mode5869 - controls labelling specifics
 * @param salt - surprisingly this is the salt;-)
 * @param saltlen - length of above
 * @param label - label for separation
 * @param labellen - length of above
 * @param zz - the initial key material (IKM)
 * @param zzlen - length of above
 * @param secret - the result of extraction (allocated inside)
 * @param secretlen - bufsize on input, used size on output
 * @return 1 for good otherwise bad
 *
 * Mode can be:
 * - HPKE_5869_MODE_PURE meaning to ignore all the
 * HPKE-specific labelling and produce an output that's 
 * RFC5869 compliant (useful for testing and maybe
 * more)
 * - HPKE_5869_MODE_KEM meaning to follow section 4.1
 * where the suite_id is used as:
 *   concat("KEM", I2OSP(kem_id, 2))
 * - HPKE_5869_MODE_FULL meaning to follow section 5.1
 * where the suite_id is used as:
 *   concat("HPKE",I2OSP(kem_id, 2),
 *          I2OSP(kdf_id, 2), I2OSP(aead_id, 2))
 *
 * Isn't that a bit of a mess!
 */
int hpke_extract(
        const hpke_suite_t suite, const int mode5869,
        const unsigned char *salt, const size_t saltlen,
        const char *label, const size_t labellen,
        const unsigned char *ikm, const size_t ikmlen,
        unsigned char *secret, size_t *secretlen);

/*
 * 5869 modes for func below
 */
#define HPKE_5869_MODE_PURE 0 /**< Do "pure" RFC5869 */
#define HPKE_5869_MODE_KEM  1 /**< Abide by HPKE section 4.1 */
#define HPKE_5869_MODE_FULL 2 /**< Abide by HPKE section 5.1 */

/*!
 * brief RFC5869 HKDF-Expand
 *
 * @param suite is the ciphersuite 
 * @param mode5869 - controls labelling specifics
 * @param prk - the initial pseudo-random key material 
 * @param prk - length of above
 * @param label - label to prepend to info
 * @param labellen - label to prepend to info
 * @param context - the info
 * @param contextlen - length of above
 * @param L - the length of the output desired 
 * @param out - the result of expansion (allocated by caller)
 * @param outlen - buf size on input
 * @return 1 for good otherwise bad
 */
int hpke_expand(const hpke_suite_t suite, const int mode5869, 
                const unsigned char *prk, const size_t prklen,
                const char *label, const size_t labellen,
                const unsigned char *info, const size_t infolen,
                const uint32_t L,
                unsigned char *out, size_t *outlen);

/*!
 * brief: map a kem_id and a private key buffer into an EVP_PKEY
 *
 * @param kem_id is what'd you'd expect (using the HPKE registry values)
 * @param prbuf is the private key buffer
 * @param prbuf_len is the length of that buffer
 * @param pubuf is the public key buffer (if available)
 * @param pubuf_len is the length of that buffer
 * @param priv is a pointer to an EVP_PKEY * for the result
 * @return 1 for success, otherwise failure
 *
 * Note that the buffer is expected to be some form of the PEM encoded
 * private key, but could still have the PEM header or not, and might
 * or might not be base64 encoded. We'll try handle all those options.
 */
int hpke_prbuf2evp(
        unsigned int kem_id,
        unsigned char *prbuf,
        size_t prbuf_len,
        unsigned char *pubuf,
        size_t pubuf_len,
        EVP_PKEY **priv);

/*!
 * brief return a (possibly) random suite, public key and ciphertext for GREASErs
 *
 * @param suite-in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub is a random value of the appropriate length for a sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher is a random value of the appropriate length for a ciphertext
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 *
 * As usual buffers are caller allocated and lengths on input are buffer size.
 */
int hpke_good4grease(
        hpke_suite_t *suite_in,
        hpke_suite_t suite,
        unsigned char *pub,
        size_t *pub_len,
        unsigned char *cipher,
        size_t cipher_len);

/*!
 * @brief map a strin to a HPKE suite
 *
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */ 
int hpke_str2suite(char *str, hpke_suite_t *suite);

#endif

