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

typedef struct {
    uint16_t    kem_id; /* Key Encapsulation Method id */
    uint16_t    kdf_id; /* Key Derivation Function id */
    uint16_t    aead_id; /* AEAD alg id */
} OSSL_HPKE_SUITE;

/**
 * Suite constants, use this like:
 *          OSSL_HPKE_SUITE myvar = OSSL_HPKE_SUITE_DEFAULT;
 */
# define OSSL_HPKE_SUITE_DEFAULT \
    {\
        OSSL_HPKE_KEM_ID_X25519, \
        OSSL_HPKE_KDF_ID_HKDF_SHA256, \
        OSSL_HPKE_AEAD_ID_AES_GCM_128 \
    }

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
# ifndef OSSL_HPKE_MAXSIZE
#  define OSSL_HPKE_MAXSIZE 512
# endif

/**
 * @brief opaque type for HPKE contexts
 */
typedef struct ossl_hpke_ctx_st OSSL_HPKE_CTX;

/**
 * @brief context creator
 * @param mode is the desired HPKE mode
 * @param suite specifies the KEM, KDF and AEAD to use
 * @param libctx is the library context to use
 * @param propq is a properties string for the library
 * @return pointer to new context or NULL if error
 */
OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite,
                                 OSSL_LIB_CTX *libctx, const char *propq);

/**
 * @brief free up storage for a HPKE context
 * @param ctx is the pointer to be free'd (can be NULL)
 */
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);

/**
 * @brief set a PSK for an HPKE context
 * @param ctx is the pointer for the HPKE context
 * @param pskid is a string identifying the PSK
 * @param psk is the PSK buffer
 * @param psklen is the size of the PSK
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_psk(OSSL_HPKE_CTX *ctx,
                           const char *pskid,
                           const unsigned char *psk, size_t psklen);

int OSSL_HPKE_CTX_set1_ikme(OSSL_HPKE_CTX *ctx,
                            const unsigned char *ikme, size_t ikmelen);

int OSSL_HPKE_CTX_set_seq(OSSL_HPKE_CTX *ctx, uint64_t seq);
int OSSL_HPKE_CTX_get_seq(OSSL_HPKE_CTX *ctx, uint64_t *seq);

int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite);
int OSSL_HPKE_get_grease_value(OSSL_LIB_CTX *libctx, const char *propq,
                               const OSSL_HPKE_SUITE *suite_in,
                               OSSL_HPKE_SUITE *suite,
                               unsigned char *enc, size_t *enclen,
                               unsigned char *ct, size_t ctlen);
int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite);
size_t OSSL_HPKE_get_ciphertext_size(OSSL_HPKE_SUITE suite, size_t clearlen);
size_t OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE suite);
size_t OSSL_HPKE_get_recommended_ikmelen(OSSL_HPKE_SUITE suite);
/**
 * @brief set a sender KEM private key for HPKE
 * @param ctx is the pointer for the HPKE context
 * @param privp is an EVP_PKEY form of the private key
 * @return 1 for success, 0 for error
 *
 * If no key is set via this API an ephemeral one will be
 * generated in the first seal operation and used until the
 * context is free'd. (Or until a subsequent call to this
 * API replaces the key.) This suits senders who are typically
 * clients.
 */
int OSSL_HPKE_CTX_set1_senderpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *privp);

/**
 * @brief set a sender IKM for key DHKEM generation
 * @param ctx is the pointer for the HPKE context
 * @param ikme is a buffer for the IKM
 * @param ikmelen is the length of the above
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_ikme(OSSL_HPKE_CTX *ctx,
                            const unsigned char *ikme, size_t ikmelen);

/**
 * @brief set a sender private key for HPKE authenticated modes
 * @param ctx is the pointer for the HPKE context
 * @param privp is an EVP_PKEY form of the private key
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_authpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *privp);

/**
 * @brief set a public key for HPKE authenticated modes
 * @param ctx is the pointer for the HPKE context
 * @param pub is an buffer form of the public key
 * @param publen is the length of the above
 * @return 1 for success, 0 for error
 *
 * In all these APIs public keys are passed as buffers whereas
 * private keys as passed as EVP_PKEY pointers.
 */
int OSSL_HPKE_CTX_set1_authpub(OSSL_HPKE_CTX *ctx,
                               const unsigned char *pub,
                               size_t publen);

/**
 * @brief ask for the state of the sequence of seal/open calls
 * @param ctx is the pointer for the HPKE context
 * @param seq returns the positive integer sequence number
 * @return 1 for success, 0 for error
 *
 * The value returned is the next one to be used when sealing
 * or opening (so as we start at zero this will be 1 after the
 * first successful call to seal or open)
 *
 * seq is a uint64_t as that's what two other implementations
 * chose
 */
int OSSL_HPKE_CTX_get0_seq(OSSL_HPKE_CTX *ctx, uint64_t *seq);

/**
 * @brief set the sequence value for seal/open calls
 * @param ctx is the pointer for the HPKE context
 * @param seq set the positive integer sequence number
 * @return 1 for success, 0 for error
 *
 * The next seal or open operation will use this value.
 */
int OSSL_HPKE_CTX_set1_seq(OSSL_HPKE_CTX *ctx, uint64_t seq);

/**
 * @brief sender seal function
 * @param ctx is the pointer for the HPKE context
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @param pub is the recipient public key octets
 * @param publen is the size the above
 * @param info is the info parameter
 * @param infolen is the size the above
 * @param aad is the aad parameter
 * @param aadlen is the size the above
 * @param pt is the plaintext
 * @param ptlen is the size the above
 * @return 1 for success, 0 for error
 *
 * This can be called once, or multiple, times.
 *
 * If no KEM private key has been set in the context an ephemeral
 * key will be generated and used for the duration of the context.
 *
 * The ciphertext buffer (ct) should be big enough to include
 * the AEAD tag generated from encryptions and the ``enc`` buffer
 * (the ephemeral public key) needs to be big enough for the
 * relevant KEM. ``OSSL_HPKE_expansion`` can be used to determine
 * the sizes needed.
 */
int OSSL_HPKE_sender_seal(OSSL_HPKE_CTX *ctx,
                          unsigned char *enc, size_t *enclen,
                          unsigned char *ct, size_t *ctlen,
                          unsigned char *pub, size_t publen,
                          const unsigned char *info, size_t infolen,
                          const unsigned char *aad, size_t aadlen,
                          const unsigned char *pt, size_t ptlen);

/**
 * @brief recipient open function
 * @param ctx is the pointer for the HPKE context
 * @param pt is the plaintext
 * @param ptlen is the size the above
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param recippriv is the EVP_PKEY form of recipient private value
 * @param info is the info parameter
 * @param infolen is the size the above
 * @param aad is the aad parameter
 * @param aadlen is the size the above
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @return 1 for success, 0 for error
 *
 * This can be called once, or multiple, times.
 *
 * The recipient private key is explicitly set here as recipients
 * are likely to be servers with multiple long(ish) term private
 * keys in memory at once and that may have to e.g. do trial
 * decryptions.
 *
 * The plaintext output (pt) will be smaller than the
 * ciphertext input for all supported suites.
 */
int OSSL_HPKE_recipient_open(OSSL_HPKE_CTX *ctx,
                             unsigned char *pt, size_t *ptlen,
                             const unsigned char *enc, size_t enclen,
                             EVP_PKEY *recippriv,
                             const unsigned char *info, size_t infolen,
                             const unsigned char *aad, size_t aadlen,
                             const unsigned char *ct, size_t ctlen);


/**
 * @brief sender export-only encapsulation function
 * @param ctx is the pointer for the HPKE context
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param pub is the recipient public key octets
 * @param publen is the size the above
 * @param info is the info parameter
 * @param infolen is the size the above
 * @return 1 for success, 0 for error
 *
 * Following this, OSSL_HPKE_CTX_export can be called.
 */
int OSSL_HPKE_sender_export_encap(OSSL_HPKE_CTX *ctx,
                                  unsigned char *enc, size_t *enclen,
                                  unsigned char *pub, size_t publen,
                                  const unsigned char *info, size_t infolen);

/**
 * @brief recipient export-only encapsulation function
 * @param ctx is the pointer for the HPKE context
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param recippriv is the EVP_PKEY form of recipient private value
 * @param info is the info parameter
 * @param infolen is the size the above
 * @return 1 for success, 0 for error
 *
 * Following this, OSSL_HPKE_CTX_export can be called.
 */
int OSSL_HPKE_recipient_export_decap(OSSL_HPKE_CTX *ctx,
                                     const unsigned char *enc, size_t enclen,
                                     EVP_PKEY *recippriv,
                                     const unsigned char *info, size_t infolen);

/**
 * @brief generate a given-length secret based on context and label
 * @param ctx is the HPKE context
 * @param secret is the resulting secret that will be of length...
 * @param secretlen is the desired output length
 * @param label is a buffer to provide separation between secrets
 * @param labellen is the length of the above
 * @return 1 for good, 0 for error
 *
 * The context has to have been used already for one encryption
 * or decryption for this to work (as this is based on the negotiated
 * "exporter_secret" estabilshed via the HPKE operation).
 */
int OSSL_HPKE_CTX_export(OSSL_HPKE_CTX *ctx,
                         unsigned char *secret,
                         size_t secretlen,
                         const unsigned char *label,
                         size_t labellen);

/**
 * @brief generate a key pair
 * @param libctx is the context to use (normally NULL)
 * @param propq is a properties string
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param ikm is IKM, if supplied
 * @param ikmlen is the length of IKM, if supplied
 * @param pub is the public value
 * @param publen is the size of the public key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for success, other for error (error returns can be non-zero)
 *
 * Used for entities that will later receive HPKE values to
 * decrypt or that want a private key for an AUTH mode. Currently,
 * only the KEM from the suite is significant here.
 * The ``pub`` output will typically be published so that
 * others can encrypt to the private key holder using HPKE.
 * (Or authenticate HPKE values from that sender.)
 */
int OSSL_HPKE_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                     unsigned int mode, OSSL_HPKE_SUITE suite,
                     const unsigned char *ikm, size_t ikmlen,
                     unsigned char *pub, size_t *publen, EVP_PKEY **priv);

/**
 * @brief check if a suite is supported locally
 * @param suite is the suite to check
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite);

/**
 * @brief get a (possibly) random suite, public key and ciphertext for GREASErs
 * @param libctx is the context to use (normally NULL)
 * @param propq is a properties string
 * @param suite_in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for a sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param ciphertext is a random value of the appropriate length for ciphertext
 * @param ciphertext_len is the length of cipher
 * @return 1 for success, otherwise failure
 *
 * If suite_in is provided that will be used (if supported). If
 * suite_in is NULL, a random suite (from those supported) will
 * be selected. In all cases the output pub and cipher values
 * will be appropriate random values for the selected suite.
 */
int OSSL_HPKE_get_grease_value(OSSL_LIB_CTX *libctx, const char *propq,
                               OSSL_HPKE_SUITE *suite_in,
                               OSSL_HPKE_SUITE *suite,
                               unsigned char *pub,
                               size_t *pub_len,
                               unsigned char *ciphertext,
                               size_t ciphertext_len);

/**
 * @brief map a string to a HPKE suite
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 *
 * An example good string is "x25519,hkdf-sha256,aes-128-gcm"
 * Symbols are #define'd for the relevant labels, e.g.
 * OSSL_HPKE_KEMSTR_X25519. Numeric (decimal or hex) values with
 * the relevant IANA codepoint values from RFC9180 may be used,
 * e.g., "0x20,1,1" represents the same suite as the first
 * example.
 */
int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite);


/**
 * @brief tell the caller how big the cipertext will be
 * @param suite is the suite to be used
 * @param clearlen is the length of plaintext
 * @return the length of the related ciphertext or zero on error
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who know what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given
 * suite.
 */
size_t OSSL_HPKE_get_ciphertext_size(OSSL_HPKE_SUITE suite, size_t clearlen);

/**
 * @brief tell the caller how big the public value ``enc`` will be
 * @param suite is the suite to be used
 * @return size of public encap or zero on error
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who know what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given
 * suite.
 */
size_t OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE suite);

/**
 * @brief recommend an IKM size in octets for a given suite
 * @param suite is the suite to be used
 * @return the recommended size or zero on error
 *
 * Today, this really only uses the KEM to recommend
 * the number of random octets to use based on the
 * size of a private value. In future, it could also
 * factor in e.g. the AEAD.
 */
size_t OSSL_HPKE_recommend_ikmelen(OSSL_HPKE_SUITE suite);

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
 * @param propq is a properties string
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param ikm is IKM, if supplied
 * @param ikmlen is the length of IKM, if supplied
 * @param pub is the public value
 * @param publen is the size of the public key buffer (exact length on output)
 * @param priv is the private key
 * @param privlen is the size of the private key buffer (exact length on output)
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                     unsigned int mode, OSSL_HPKE_SUITE suite,
                     const unsigned char *ikm, size_t ikmlen,
                     unsigned char *pub, size_t *publen,
                     unsigned char *priv, size_t *privlen);

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
 * @param propq is a properties string
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param ikm is IKM, if supplied
 * @param ikmlen is the length of IKM, if supplied
 * @param pub is the public value
 * @param publen is the size of the public key buffer (exact length on output)
 * @param priv is the private key handle
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_keygen_evp(OSSL_LIB_CTX *libctx, const char *propq,
                         unsigned int mode, OSSL_HPKE_SUITE suite,
                         const unsigned char *ikm, size_t ikmlen,
                         unsigned char *pub, size_t *publen,
                         EVP_PKEY **priv);

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite);

/**
 * @brief: map a kem_id and a private key buffer into an EVP_PKEY
 *
 * Note that the buffer is expected to be some form of probably-PEM encoded
 * private key, but could be missing the PEM header or not, and might
 * or might not be base64 encoded. We try handle those options as best
 * we can.
 *
 * @param libctx is the context to use (normally NULL)
 * @param propq is a properties string
 * @param kem_id is what'd you'd expect (using the HPKE registry values)
 * @param prbuf is the private key buffer
 * @param prbuf_len is the length of that buffer
 * @param pubuf is the public key buffer (if available)
 * @param pubuf_len is the length of that buffer
 * @param priv is a pointer to an EVP_PKEY * for the result
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_prbuf2evp(OSSL_LIB_CTX *libctx, const char *propq,
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
 * @param propq is a properties string
 * @param suite_in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for a sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher is a random value of the appropriate length for a ciphertext
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_good4grease(OSSL_LIB_CTX *libctx, const char *propq,
                          OSSL_HPKE_SUITE *suite_in,
                          OSSL_HPKE_SUITE *suite,
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
int OSSL_HPKE_str2suite(const char *str,
                        OSSL_HPKE_SUITE *suite);

/**
 * @brief tell the caller how big the cipertext will be
 *
 * @param suite is the suite to be used
 * @param enclen points to what'll be enc length
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_expansion(OSSL_HPKE_SUITE suite,
                        size_t *enclen,
                        size_t clearlen,
                        size_t *cipherlen);
#endif
