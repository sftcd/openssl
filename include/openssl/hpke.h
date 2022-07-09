/*
 * Copyright 2022-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* APIs and data structures for HPKE (RFC9180)  */
#ifndef OSSL_HPKE_H
# define OSSL_HPKE_H
# pragma once

# include <openssl/types.h>

/* HPKE modes */
# define OSSL_HPKE_MODE_BASE              0 /* Base mode  */
# define OSSL_HPKE_MODE_PSK               1 /* Pre-shared key mode */
# define OSSL_HPKE_MODE_AUTH              2 /* Authenticated mode */
# define OSSL_HPKE_MODE_PSKAUTH           3 /* PSK+authenticated mode */

/*
 * Max for ikm, psk, pskid, info and exporter contexts.
 * RFC9180, section 7.2.1 RECOMMENDS 64 octets but we have test vectors from
 * Appendix A.6.1 with a 66 octet IKM so we'll allow that.
 */
# define OSSL_HPKE_MAX_PARMLEN        66
# define OSSL_HPKE_MIN_PSKLEN         32
# define OSSL_HPKE_MAX_INFOLEN        1024

/*
 * The (16bit) HPKE algorithm ID IANA codepoints
 * If/when new IANA codepoints are added there are tables in
 * crypto/hpke/hpke_util.c that must also be updated.
 */
# define OSSL_HPKE_KEM_ID_RESERVED         0x0000 /* not used */
# define OSSL_HPKE_KEM_ID_P256             0x0010 /* NIST P-256 */
# define OSSL_HPKE_KEM_ID_P384             0x0011 /* NIST P-384 */
# define OSSL_HPKE_KEM_ID_P521             0x0012 /* NIST P-521 */
# define OSSL_HPKE_KEM_ID_X25519           0x0020 /* Curve25519 */
# define OSSL_HPKE_KEM_ID_X448             0x0021 /* Curve448 */

# define OSSL_HPKE_KDF_ID_RESERVED         0x0000 /* not used */
# define OSSL_HPKE_KDF_ID_HKDF_SHA256      0x0001 /* HKDF-SHA256 */
# define OSSL_HPKE_KDF_ID_HKDF_SHA384      0x0002 /* HKDF-SHA384 */
# define OSSL_HPKE_KDF_ID_HKDF_SHA512      0x0003 /* HKDF-SHA512 */

# define OSSL_HPKE_AEAD_ID_RESERVED        0x0000 /* not used */
# define OSSL_HPKE_AEAD_ID_AES_GCM_128     0x0001 /* AES-GCM-128 */
# define OSSL_HPKE_AEAD_ID_AES_GCM_256     0x0002 /* AES-GCM-256 */
# define OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 /* Chacha20-Poly1305 */
# define OSSL_HPKE_AEAD_ID_EXPORTONLY      0xFFFF /* export-only fake ID */

/* strings for suite components */
# define OSSL_HPKE_KEMSTR_P256        "P-256"              /* KEM id 0x10 */
# define OSSL_HPKE_KEMSTR_P384        "P-384"              /* KEM id 0x11 */
# define OSSL_HPKE_KEMSTR_P521        "P-521"              /* KEM id 0x12 */
# define OSSL_HPKE_KEMSTR_X25519      "X25519"             /* KEM id 0x20 */
# define OSSL_HPKE_KEMSTR_X448        "X448"               /* KEM id 0x21 */
# define OSSL_HPKE_KDFSTR_256         "hkdf-sha256"        /* KDF id 1 */
# define OSSL_HPKE_KDFSTR_384         "hkdf-sha384"        /* KDF id 2 */
# define OSSL_HPKE_KDFSTR_512         "hkdf-sha512"        /* KDF id 3 */
# define OSSL_HPKE_AEADSTR_AES128GCM  "aes-128-gcm"        /* AEAD id 1 */
# define OSSL_HPKE_AEADSTR_AES256GCM  "aes-256-gcm"        /* AEAD id 2 */
# define OSSL_HPKE_AEADSTR_CP         "chacha20-poly1305"  /* AEAD id 3 */
# define OSSL_HPKE_AEADSTR_EXP        "exporter"           /* AEAD id 0xff */

/*
 * Roles for use in creating an OSSL_HPKE_CTX, most
 * important use of this is to control nonce reuse.
 */
# define OSSL_HPKE_ROLE_SENDER 0
# define OSSL_HPKE_ROLE_RECEIVER 1

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct {
    uint16_t    kem_id; /* Key Encapsulation Method id */
    uint16_t    kdf_id; /* Key Derivation Function id */
    uint16_t    aead_id; /* AEAD alg id */
} OSSL_HPKE_SUITE;

/**
<<<<<<< HEAD
 * Suite constants, use this like:
 *          OSSL_HPKE_SUITE myvar = OSSL_HPKE_SUITE_DEFAULT;
 */
# ifndef OPENSSL_NO_ECX
#  define OSSL_HPKE_SUITE_DEFAULT \
    {\
        OSSL_HPKE_KEM_ID_X25519, \
=======
 * @file
 * APIs and data structures for HPKE (RFC9180).
 *
 * There is only one significant data structure defined here
 * (ossl_hpke_suite_st) to represent the KEM, KDF and AEAD algs
 * used. Otherwise, the approach taken is to provide all the
 * API inputs using existing types (buffers, lengths and a few
 * cases of strings or EVP_PKEY pointers.
 *
 * HPKE key generation functions (``OSSL_HPKE_kg()`` and
 * ``OSSL_HPKE_kg_evp()``) require a suite as input (though
 * only the KEM is currently significant) and return
 * public and private components of the key.
 *
 * HPKE (and hence our APIs) allow the caller to choose a
 * ``mode`` that can optionally bind a pre-shared key (PSK)
 * and/or an authenticating private value, also generared via
 * ``OSSL_HPKE_kg()``, to the encryption operation -
 * ``OSSL_HPKE_MODE_BASE`` is the basic mode with neither, while
 * ``OSSL_HPKE_MODE_PSKAUTH`` calls for both.
 *
 * An ``info`` value, known to both encryptor and decryptor
 * can be combined into the key agreement operation.  Similarly,
 * additional authenticated data (``aad``) can be combined into
 * the AEAD operation. Applications/protocols using HPKE can
 * use these to bind information that wouldn't otherwise be
 * part of the encryption.
 *
 * Where non-ephemeral encryptor-chosen public/private Diffie-Hellman
 * values are used for more than one encryption operation, a
 * sequence number (``seq``) will generally need to be mixed
 * into the key agreement operation. (HPKE defines how to handle
 * mixing in the sequence.)
 *
 * Single-shot encryption (``OSSL_HPKE_enc()``), with
 * ephemeral encryptor-chosen public/private values, requires the
 * ``mode``, ``suite``, recipient's public value and cleartext inputs
 * and produces the ciphertext output. The other optional inputs
 * (``info``, ``aad``, etc.) are as described above.
 *
 * An ``OSSL_HPKE_enc_evp()`` variant allows the encryptor to
 * re-use its Diffie-Hellman public and private values used in a
 * previous call. The ``seq`` option is likely also needed
 * in such cases, e.g. as part of some protocol re-try mechanism
 * such as the TLS HelloRetryRequest (HRR) case for Encrypted Client
 * Hello.
 *
 * ``OSSL_HPKE_dec()`` supports the decryption operation and
 * takes the same kinds of inputs as for encryption with the
 * obvious role-swaps of public and private values.
 *
 * ``OSSL_HPKE_prbuf2evp()`` converts a buffer containing a
 * private value into an EVP_PKEY * pointer.
 *
 * ``OSSL_HPKE_suite_check()`` can be used to determine if
 * an HPKE suite is supported or not.
 *
 * ``OSSL_HPKE_str2suite()`` maps from comma-separated strings,
 * e.g. "x25519,hkdf-sha256,aes-128-gcm", to an ``ossl_hpke_suite_st``.
 *
 * So-called GREASEing (see RFC8701) is a protocol mechanism
 * where phoney values are sent in order to make it less likely
 * that (especially) middleboxes are deployed that only know
 * about "current" protocol options. Protocols using HPKE (such
 * as ECH) make use of this mechanism, but in that case need to
 * produce realistic-looking, though still phoney, values. The
 * ``OSSL_HPKE_good4grease()`` API can be used to generate such
 * values.
 *
 * As HPKE encryption uses an AEAD cipher, there is the usual
 * expansion of ciphertext due to the authentication tag.
 * Applications/protocols needing to know the degree of such
 * expansion (whether for GREASEing or memory management) can
 * use the ``OSSL_HPKE_expansion()`` API.
 *
 * Many of the APIs defined here also take an ``OSSL_LIB_CTX``
 * pointer as input for cases where the default library context
 * is not in use. Return values are always 1 in the case
 * of success, or something else otherwise - note that non-zero
 * failure return values will be seen by callers.
 *
 * ## Some Uses of HPKE
 *
 * ### Encrypted Client Hello (ECH)
 *
 * Based on implementing
 * [ECH](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
 * using this API, the following APIs are used for ECH:
 * the EVP flavour of key generation is used on the cilent,
 * the multi-shot variant of encryption on the client, using both
 * info and AAD, and the BASE mode (so no PSK or AUTH). In the event
 * of HRR, the seq input is also used. The AAD is mainly used to bind
 * the outer ClientHello to the ciphertext form of the inner
 * ClientHello.  ECH client-side GREASEing uses both GREASE-related
 * APIs. On the server-side the non-EVP key generation funcction is
 * used by a command line tool. Public keys are exported to the DNS
 * and private/public pairs are read (from files) by the server
 * with the private keys mapped to EVP_PKEY pointers using the
 * prbuf2evp API. HPKE decryption is used as one would expect.
 *
 * ## Message Layer Security (MLS)
 *
 * Based on a reading of the
 * [MLS](https://datatracker.ietf.org/doc/html/draft-ietf-mls-protocol)
 * specifiation draft, the following HPKE APIs would seem to be
 * required: key generation likely requires export to storage of
 * the private key (so the non-EVP key generation variant). MLS
 * also requires the deterministic DeriveKeyPair() operation
 * (implementation still *TBD*). Encryption again uses the info
 * and AAD parameters. The context.export API (from RFC9180, and
 * also still *TBD*) is used.
 *
 * ## COSE + HPKE
 *
 * A [COSE](https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-01)
 * draft (less mature than ECH or MLS) defines a way to use HPKE
 * with COSE (RFC8152). The SealBase API is used and maps to our HPKE single
 * shot encryption API.
 */

/**
 * @file APIs and data structures for HPKE (RFC9180).
 */

#ifndef OSSL_HPKE_H_INCLUDED
# define OSSL_HPKE_H_INCLUDED

# include <openssl/ssl.h>

/** biggest/default buffer for keys and internal buffers we use */
# ifndef OSSL_HPKE_MAXSIZE
#  define OSSL_HPKE_MAXSIZE (2 * 1024) /* 2k: enough for anyone :-) */
# endif

/*
 * The HPKE modes
 */
# define OSSL_HPKE_MODE_BASE              0 /**< Base mode  */
# define OSSL_HPKE_MODE_PSK               1 /**< Pre-shared key mode */
# define OSSL_HPKE_MODE_AUTH              2 /**< Authenticated mode */
# define OSSL_HPKE_MODE_PSKAUTH           3 /**< PSK+authenticated mode */

/*
 * The (16bit) HPKE algorithn IDs
 */
# define OSSL_HPKE_KEM_ID_RESERVED         0x0000 /**< not used */
# define OSSL_HPKE_KEM_ID_P256             0x0010 /**< NIST P-256 */
# define OSSL_HPKE_KEM_ID_P384             0x0011 /**< NIST P-256 */
# define OSSL_HPKE_KEM_ID_P521             0x0012 /**< NIST P-521 */
# define OSSL_HPKE_KEM_ID_25519            0x0020 /**< Curve25519 */
# define OSSL_HPKE_KEM_ID_448              0x0021 /**< Curve448 */

# define OSSL_HPKE_KDF_ID_RESERVED         0x0000 /**< not used */
# define OSSL_HPKE_KDF_ID_HKDF_SHA256      0x0001 /**< HKDF-SHA256 */
# define OSSL_HPKE_KDF_ID_HKDF_SHA384      0x0002 /**< HKDF-SHA512 */
# define OSSL_HPKE_KDF_ID_HKDF_SHA512      0x0003 /**< HKDF-SHA512 */
# define OSSL_HPKE_KDF_ID_MAX              0x0003 /**< HKDF-SHA512 */

# define OSSL_HPKE_AEAD_ID_RESERVED        0x0000 /**< not used */
# define OSSL_HPKE_AEAD_ID_AES_GCM_128     0x0001 /**< AES-GCM-128 */
# define OSSL_HPKE_AEAD_ID_AES_GCM_256     0x0002 /**< AES-GCM-256 */
# define OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 /**< Chacha20-Poly1305 */
# define OSSL_HPKE_AEAD_ID_MAX             0x0003 /**< Chacha20-Poly1305 */

/* strings for modes */
# define OSSL_HPKE_MODESTR_BASE       "base"    /**< base mode (1) */
# define OSSL_HPKE_MODESTR_PSK        "psk"     /**< psk mode (2) */
# define OSSL_HPKE_MODESTR_AUTH       "auth"    /**< sender-key pair auth (3) */
# define OSSL_HPKE_MODESTR_PSKAUTH    "pskauth" /**< psk+sender-key pair (4) */

/* strings for suite components - ideally these'd be defined elsewhere */
# define OSSL_HPKE_KEMSTR_P256        "P-256"                /**< KEM id 0x10 */
# define OSSL_HPKE_KEMSTR_P384        "P-384"                /**< KEM id 0x11 */
# define OSSL_HPKE_KEMSTR_P521        "P-521"                /**< KEM id 0x12 */
# define OSSL_HPKE_KEMSTR_X25519      SN_X25519              /**< KEM id 0x20 */
# define OSSL_HPKE_KEMSTR_X448        SN_X448                /**< KEM id 0x21 */
# define OSSL_HPKE_KDFSTR_256         "hkdf-sha256"          /**< KDF id 1 */
# define OSSL_HPKE_KDFSTR_384         "hkdf-sha384"          /**< KDF id 2 */
# define OSSL_HPKE_KDFSTR_512         "hkdf-sha512"          /**< KDF id 3 */
# define OSSL_HPKE_AEADSTR_AES128GCM  LN_aes_128_gcm         /**< AEAD id 1 */
# define OSSL_HPKE_AEADSTR_AES256GCM  LN_aes_256_gcm         /**< AEAD id 2 */
# define OSSL_HPKE_AEADSTR_CP         LN_chacha20_poly1305   /**< AEAD id 3 */

/**
 * @brief ciphersuite combination
 */
typedef struct {
    uint16_t    kem_id; /**< Key Encryption Method id */
    uint16_t    kdf_id; /**< Key Derivation Function id */
    uint16_t    aead_id; /**< AEAD alg id */
} ossl_hpke_suite_st;

/**
 * Suite constants, use this like:
 *          ossl_hpke_suite_st myvar = OSSL_HPKE_SUITE_DEFAULT;
 */
# define OSSL_HPKE_SUITE_DEFAULT \
    {\
        OSSL_HPKE_KEM_ID_25519, \
>>>>>>> 1ceae23f08 (many minor changes based on comments in the HPKE PR)
        OSSL_HPKE_KDF_ID_HKDF_SHA256, \
        OSSL_HPKE_AEAD_ID_AES_GCM_128 \
    }
# else
#  define OSSL_HPKE_SUITE_DEFAULT \
    {\
        OSSL_HPKE_KEM_ID_P256, \
        OSSL_HPKE_KDF_ID_HKDF_SHA256, \
        OSSL_HPKE_AEAD_ID_AES_GCM_128 \
    }
#endif

<<<<<<< HEAD
typedef struct ossl_hpke_ctx_st OSSL_HPKE_CTX;

OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite, int role,
                                 OSSL_LIB_CTX *libctx, const char *propq);
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);

int OSSL_HPKE_encap(OSSL_HPKE_CTX *ctx,
                    unsigned char *enc, size_t *enclen,
                    const unsigned char *pub, size_t publen,
                    const unsigned char *info, size_t infolen);
int OSSL_HPKE_seal(OSSL_HPKE_CTX *ctx,
                   unsigned char *ct, size_t *ctlen,
                   const unsigned char *aad, size_t aadlen,
                   const unsigned char *pt, size_t ptlen);

int OSSL_HPKE_keygen(OSSL_HPKE_SUITE suite,
                     unsigned char *pub, size_t *publen, EVP_PKEY **priv,
                     const unsigned char *ikm, size_t ikmlen,
                     OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_HPKE_decap(OSSL_HPKE_CTX *ctx,
                    const unsigned char *enc, size_t enclen,
                    EVP_PKEY *recippriv,
                    const unsigned char *info, size_t infolen);
int OSSL_HPKE_open(OSSL_HPKE_CTX *ctx,
                   unsigned char *pt, size_t *ptlen,
                   const unsigned char *aad, size_t aadlen,
                   const unsigned char *ct, size_t ctlen);

int OSSL_HPKE_export(OSSL_HPKE_CTX *ctx,
                     unsigned char *secret,
                     size_t secretlen,
                     const unsigned char *label,
                     size_t labellen);

int OSSL_HPKE_CTX_set1_authpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *priv);
int OSSL_HPKE_CTX_set1_authpub(OSSL_HPKE_CTX *ctx,
                               const unsigned char *pub,
                               size_t publen);
int OSSL_HPKE_CTX_set1_psk(OSSL_HPKE_CTX *ctx,
                           const char *pskid,
                           const unsigned char *psk, size_t psklen);

int OSSL_HPKE_CTX_set1_ikme(OSSL_HPKE_CTX *ctx,
                            const unsigned char *ikme, size_t ikmelen);

int OSSL_HPKE_CTX_set_seq(OSSL_HPKE_CTX *ctx, uint64_t seq);
int OSSL_HPKE_CTX_get_seq(OSSL_HPKE_CTX *ctx, uint64_t *seq);

int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite);
int OSSL_HPKE_get_grease_value(const OSSL_HPKE_SUITE *suite_in,
                               OSSL_HPKE_SUITE *suite,
                               unsigned char *enc, size_t *enclen,
                               unsigned char *ct, size_t ctlen,
                               OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite);
size_t OSSL_HPKE_get_ciphertext_size(OSSL_HPKE_SUITE suite, size_t clearlen);
size_t OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE suite);
size_t OSSL_HPKE_get_recommended_ikmelen(OSSL_HPKE_SUITE suite);
=======
/**
 * If you like your crypto turned up...
 */
# define OSSL_HPKE_SUITE_TURNITUPTO11 \
    { \
        OSSL_HPKE_KEM_ID_448, \
        OSSL_HPKE_KDF_ID_HKDF_SHA512, \
        OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 \
    }

/**
 * @brief HPKE single-shot encryption function
 *
 * This function generates an ephemeral ECDH value internally and
 * provides the public component as an output that can be sent to
 * the relevant private key holder along with the ciphertext.
 *
 * Note that the sender's public value is an output here in contrast
 * to the case of OSSL_HPKE_enc_evp where the sender's public value
 * is an input (along with the sender's private value).
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string for a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the public key
 * @param pub is the encoded public key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv is the encoded private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the length of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the length of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param senderpublen length of the input buffer for sender's public key
 * @param senderpub is the input buffer for sender public key
 * @param cipherlen is the length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_enc(OSSL_LIB_CTX *libctx,
                  unsigned int mode, ossl_hpke_suite_st suite,
                  char *pskid, size_t psklen, unsigned char *psk,
                  size_t publen, unsigned char *pub,
                  size_t authprivlen, unsigned char *authpriv,
                  EVP_PKEY *authpriv_evp,
                  size_t clearlen, unsigned char *clear,
                  size_t aadlen, unsigned char *aad,
                  size_t infolen, unsigned char *info,
                  size_t seqlen, unsigned char *seq,
                  size_t *senderpublen, unsigned char *senderpub,
                  size_t *cipherlen, unsigned char *cipher);

/**
 * @brief HPKE multi-shot encryption function
 *
 * This function generates a non-ephemeral ECDH value internally and
 * provides the public and private components as outputs. The public
 * part can be sent to the relevant private key holder along with the
 * ciphertext. The private part can be re-used in subequent calls.
 *
 * Note that the sender's public value is an input here (as is the
 * sender's private value), in contrast to the case of OSSL_HPKE_enc
 * where the sender's public value is an output.
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string for a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the public key
 * @param pub is the encoded public key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv is the encoded private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the length of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the length of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param senderpublen length of the input buffer for sender's public key
 * @param senderpub is the input buffer for sender public key
 * @param senderpriv is the EVP_PKEY* form of sender key pair
 * @param cipherlen is the length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_enc_evp(OSSL_LIB_CTX *libctx,
                      unsigned int mode, ossl_hpke_suite_st suite,
                      char *pskid, size_t psklen, unsigned char *psk,
                      size_t publen, unsigned char *pub,
                      size_t authprivlen, unsigned char *authpriv,
                      EVP_PKEY *authpriv_evp,
                      size_t clearlen, unsigned char *clear,
                      size_t aadlen, unsigned char *aad,
                      size_t infolen, unsigned char *info,
                      size_t seqlen, unsigned char *seq,
                      size_t senderpublen, unsigned char *senderpub,
                      EVP_PKEY *senderpriv,
                      size_t *cipherlen, unsigned char *cipher);

/**
 * @brief HPKE single-shot decryption function
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string for a PSK mode (can be NULL)
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
 * @param aadlen is the length of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the length of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param clearlen length of the input buffer for cleartext
 * @param clear is the encoded cleartext
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_dec(OSSL_LIB_CTX *libctx,
                  unsigned int mode, ossl_hpke_suite_st suite,
                  char *pskid, size_t psklen, unsigned char *psk,
                  size_t publen, unsigned char *pub,
                  size_t privlen, unsigned char *priv,
                  EVP_PKEY *evppriv,
                  size_t enclen, unsigned char *enc,
                  size_t cipherlen, unsigned char *cipher,
                  size_t aadlen, unsigned char *aad,
                  size_t infolen, unsigned char *info,
                  size_t seqlen, unsigned char *seq,
                  size_t *clearlen, unsigned char *clear);

/**
 * @brief generate a key pair
 *
 * Used for entities that will later receive HPKE values to
 * decrypt. Only the KEM from the suite is significant here.
 * The ``pub` output will typically be published so that
 * others can encrypt to the private key holder using HPKE.
 * The ``priv`` output contains the raw private value and
 * hence is sensitive.
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for success, other for error (error returns can be non-zero)
 *
 * TODO: need to add this for RFC9180 deterministic key gen
 * size_t ikmlen, unsigned char *ikm,
 */
int OSSL_HPKE_kg(OSSL_LIB_CTX *libctx,
                 unsigned int mode, ossl_hpke_suite_st suite,
                 size_t *publen, unsigned char *pub,
                 size_t *privlen, unsigned char *priv);

/**
 * @brief generate a key pair but keep private inside API
 *
 * Used for entities that will later receive HPKE values to
 * decrypt. Only the KEM from the suite is significant here.
 * The ``pub`` output will typically be published so that
 * others can encrypt to the private key holder using HPKE.
 * The ``priv`` output here is in the form of an EVP_PKEY and
 * so the raw private value need not be exposed to the
 * application.
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key handle
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_kg_evp(OSSL_LIB_CTX *libctx,
                     unsigned int mode, ossl_hpke_suite_st suite,
                     size_t *publen, unsigned char *pub,
                     EVP_PKEY **priv);

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_suite_check(ossl_hpke_suite_st suite);

/**
 * @brief: map a kem_id and a private key buffer into an EVP_PKEY
 *
 * Note that the buffer is expected to be some form of probably-PEM encoded
 * private key, but could be missing the PEM header or not, and might
 * or might not be base64 encoded. We try handle those options as best
 * we can.
 *
 * @param libctx is the context to use (normally NULL)
 * @param kem_id is what'd you'd expect (using the HPKE registry values)
 * @param prbuf is the private key buffer
 * @param prbuf_len is the length of that buffer
 * @param pubuf is the public key buffer (if available)
 * @param pubuf_len is the length of that buffer
 * @param priv is a pointer to an EVP_PKEY * for the result
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_prbuf2evp(OSSL_LIB_CTX *libctx,
                        unsigned int kem_id,
                        unsigned char *prbuf,
                        size_t prbuf_len,
                        unsigned char *pubuf,
                        size_t pubuf_len,
                        EVP_PKEY **priv);

/**
 * @brief get a (possibly) random suite, public key and ciphertext for GREASErs
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite_in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for a sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher is a random value of the appropriate length for a ciphertext
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_good4grease(OSSL_LIB_CTX *libctx,
                          ossl_hpke_suite_st *suite_in,
                          ossl_hpke_suite_st *suite,
                          unsigned char *pub,
                          size_t *pub_len,
                          unsigned char *cipher,
                          size_t cipher_len);

/**
 * @brief map a string to a HPKE suite
 *
 * An example good string is "x25519,hkdf-sha256,aes-128-gcm"
 * Symbols are #define'd for the relevant labels, e.g.
 * OSSL_HPKE_KEMSTR_X25519. Numeric (decimal or hex) values with
 * the relevant IANA codepoint valus may also be used,
 * e.g., "0x20,1,1" represents the same suite as the first
 * example.
 *
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_str2suite(char *str,
                        ossl_hpke_suite_st *suite);

/**
 * @brief tell the caller how big the cipertext will be
 *
 * @param suite is the suite to be used
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_expansion(ossl_hpke_suite_st suite,
                        size_t clearlen,
                        size_t *cipherlen);
>>>>>>> 1ceae23f08 (many minor changes based on comments in the HPKE PR)

# ifdef  __cplusplus
}
# endif

#endif
