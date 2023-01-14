/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * Internal data structures and prototypes
 * for handling of Encrypted ClientHello (ECH)
 */
#ifndef OPENSSL_NO_ECH

# ifndef HEADER_ECH_LOCAL_H
#  define HEADER_ECH_LOCAL_H

#  include <openssl/ssl.h>
#  include <openssl/ech.h>
#  include <openssl/hpke.h>

/*
 * Define this to get loads more lines of tracing.
 * This also needs tracing enabled at build time, e.g.:
 *          $ ./config enable-ssl-trace endable-trace
 * This will finally (mostly) disappear once the ECH RFC
 * has issued, but is very useful for interop testing so
 * some of it might be retained.
 */
#  define OSSL_ECH_SUPERVERBOSE

#  ifndef CLIENT_VERSION_LEN
/*
 * This is the legacy version length, i.e. len(0x0303). The same
 * label is used in e.g. test/sslapitest.c and elsewhere but not
 * defined in a header file I could find.
 */
#   define CLIENT_VERSION_LEN 2
#  endif

#  define OSSL_ECH_CIPHER_LEN 4 /* ECHCipher length (2 for kdf, 2 for aead) */

/* values for s->ext.ech_grease */
#  define OSSL_ECH_GREASE_UNKNOWN -1 /* when we're not yet sure */
#  define OSSL_ECH_NOT_GREASE 0 /* when decryption worked */
#  define OSSL_ECH_IS_GREASE 1 /* when decryption failed or GREASE wanted */

/* used to indicate "all" in SSL_ech_print */
#  define OSSL_ECH_SELECT_ALL -1

/* value for uninitialised GREASE ECH version */
#  define TLSEXT_TYPE_ech_unknown 0xffff

/* value for not yet set ECH config_id */
#  define TLSEXT_TYPE_ech_config_id_unset -1

#  define OSSL_ECH_OUTER_CH_TYPE 0 /* outer ECHClientHello enum */
#  define OSSL_ECH_INNER_CH_TYPE 1 /* inner ECHClientHello enum */

/* size for sgtring buffer returned via ech_cb */
#  define OSSL_ECH_PBUF_SIZE 8 * 1024

/*
 * Return values from ech_same_ext, note that the CONTINUE
 * return value might mean something new if the extension
 * handler is ECH "aware" (other than in a trivial sense)
 */
#  define OSSL_ECH_SAME_EXT_ERR 0 /* bummer something wrong */
#  define OSSL_ECH_SAME_EXT_DONE 1 /* proceed with same value in inner/outer */
#  define OSSL_ECH_SAME_EXT_CONTINUE 2 /* generate a new value for outer CH */

/*
 * Reminder of what goes in DNS for draft-13
 *
 *     opaque HpkePublicKey<1..2^16-1>;
 *     uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
 *     uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
 *     uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
 *     struct {
 *         HpkeKdfId kdf_id;
 *         HpkeAeadId aead_id;
 *     } HpkeSymmetricCipherSuite;
 *     struct {
 *         uint8 config_id;
 *         HpkeKemId kem_id;
 *         HpkePublicKey public_key;
 *         HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
 *     } HpkeKeyConfig;
 *     struct {
 *         HpkeKeyConfig key_config;
 *         uint8 maximum_name_length;
 *         opaque public_name<1..255>;
 *         Extension extensions<0..2^16-1>;
 *     } ECHConfigContents;
 *     struct {
 *         uint16 version;
 *         uint16 length;
 *         select (ECHConfig.version) {
 *           case 0xfe0d: ECHConfigContents contents;
 *         }
 */
typedef unsigned char ech_ciphersuite_t[OSSL_ECH_CIPHER_LEN];

typedef struct ech_config_st {
    unsigned int version; /* 0xff0d for draft-13 */
    unsigned int public_name_len;
    unsigned char *public_name;
    unsigned int kem_id;
    unsigned int pub_len;
    unsigned char *pub;
    unsigned int nsuites;
    ech_ciphersuite_t *ciphersuites;
    unsigned int maximum_name_length;
    unsigned int nexts;
    unsigned int *exttypes;
    unsigned int *extlens;
    unsigned char **exts;
    size_t encoding_length; /* used for OSSL_ECH_INFO output */
    unsigned char *encoding_start; /* used for OSSL_ECH_INFO output */
    uint8_t config_id;
} ECHConfig;

typedef struct ech_configs_st {
    unsigned int encoded_len; /* length of overall encoded content */
    unsigned char *encoded; /* overall encoded content */
    int nrecs; /* Number of records  */
    ECHConfig *recs; /* array of individual records */
} ECHConfigs;

/**
 * What we send in the ech CH extension:
 *
 * For draft-13:
 *     enum { outer(0), inner(1) } ECHClientHelloType;
 *     struct {
 *        ECHClientHelloType type;
 *        select (ECHClientHello.type) {
 *            case outer:
 *                HpkeSymmetricCipherSuite cipher_suite;
 *                uint8 config_id;
 *                opaque enc<0..2^16-1>;
 *                opaque payload<1..2^16-1>;
 *            case inner:
 *                Empty;
 *        };
 *     } ECHClientHello;
 *
 */
typedef struct ech_encch_st {
    uint16_t kdf_id; /* ciphersuite  */
    uint16_t aead_id; /* ciphersuite  */
    uint8_t config_id; /* (maybe) identifies DNS RR value used */
    size_t enc_len; /* public share */
    unsigned char *enc; /* public share for sender */
    size_t payload_len; /* ciphertext  */
    unsigned char *payload; /* ciphertext  */
} OSSL_ECH_ENCCH;

/**
 * @brief The ECH data structure that's part of the SSL structure
 *
 * On the client-side, one of these is part of the SSL structure.
 * On the server-side, an array of these is part of the SSL_CTX
 * structure, and we match one of 'em to be part of the SSL
 * structure when a handshake is in progress. (Well, hopefully:-)
 *
 * Note that SSL_ECH_dup copies all these fields (when values are
 * set), so if you add, change or remove a field here, you'll also
 * need to modify that (in ssl/ech.c)
 */
typedef struct ssl_ech_st {
    ECHConfigs *cfg; /* ptr to underlying ECHConfigs */
    /* API input names, or, set on server from CH if ECH worked */
    char *inner_name;
    char *outer_name;
    int no_outer;
    /*
     * File load information - if identical filenames not modified since
     * loadtime are added via SSL_ech_server_enable_file then we ignore the new
     * data. If identical file names that are more recently modified are loaded
     * to a server we'll overwrite this entry.
     */
    char *pemfname; /* name of PEM file from which this was loaded */
    time_t loadtime; /* time public and private key were loaded from file */
    EVP_PKEY *keyshare; /* long(ish) term ECH private keyshare on a server */
} SSL_ECH;

/**
 * @brief Free an SSL_ECH
 * @param echkeys is an SSL_ECH structure
 *
 * Free everything within an SSL_ECH. Note that the
 * caller has to also free the top level SSL_ECH, IOW the
 * pattern here is:
 *      SSL_ECH_free(echkeys);
 *      OPENSSL_free(echkeys);
 */
void SSL_ECH_free(SSL_ECH *tbf);

/**
 * @brief Free an ECHConfigs
 * @param tbf is the thing to be free'd
 */
void ECHConfigs_free(ECHConfigs *tbf);

/**
 * @brief Free an ECHConfig structure's internals
 * @param tbf is the thing to be free'd
 */
void ECHConfig_free(ECHConfig *tbf);

/**
 * @brief Free an OSSL_ECH_ENCCH
 * @param tbf is a ptr to an SSL_ECH structure
 */
void OSSL_ECH_ENCCH_free(OSSL_ECH_ENCCH *ev);

/**
 * @brief Duplicate the configuration related fields of an SSL_ECH
 * @param orig is the input array of SSL_ECH to be partly deep-copied
 * @param nech is the number of elements in the array
 * @param selector pick all (ECH_SELECT_ALL==-1) or one of the values
 * @return a partial deep-copy array or NULL if errors occur
 *
 * This is needed to handle the SSL_CTX->SSL factory model in the
 * server. Clients don't need this.  There aren't too many fields
 * populated when this is called - essentially just the ECHConfigs and
 * the server private value.
 */
SSL_ECH *SSL_ECH_dup(SSL_ECH *orig, size_t nech, int selector);

/*
 * @brief After "normal" 1st pass client CH handling, encode that
 * @param s is the SSL session
 * @return 1 for success, error otherwise
 *
 * Make up ClientHelloInner and EncodedClientHelloInner buffers
 */
int ech_encode_inner(SSL_CONNECTION *s);

/*
 * @brief Replicate ext value from inner ch into outer ch
 * @param s is the SSL session
 * @param pkt is the packet containing extensions
 * @param depth is 0 for outer CH, 1 for inner
 * @return 0: error, 1: copied existing and done, 2: ignore existing
 *
 * This also sets us up for later outer compression.
 * Return value is one of OSSL_ECH_SAME_EXT_ERR_*
 */
int ech_same_ext(SSL_CONNECTION *s, WPACKET *pkt, int depth);

/*
 * @brief Calculate ECH acceptance signal.
 * @param s is the SSL inner context
 * @oaram for_hrr is 1 if this is for an HRR, otherwise for SH
 * @param ac is (preallocated) 8 octet buffer
 * @param shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * @param shlen is the length of the SH buf
 * @return: 1 for success, 0 otherwise
 *
 * Handling for the ECH accept_confirmation (see
 * spec, section 7.2) - this is a magic value in
 * the ServerHello.random lower 8 octets that is
 * used to signal that the inner worked. As per
 * the draft-09 spec:
 *
 * accept_confirmation =
 *          Derive-Secret(Handshake Secret,
 *                        "ech accept confirmation",
 *                        ClientHelloInner...ServerHelloECHConf)
 */
int ech_calc_ech_confirm(SSL_CONNECTION *s, int for_hrr, unsigned char *acbuf,
                         const unsigned char *shbuf, const size_t shlen);

/*
 * @brief Swap the inner and outer CH structures as needed..
 * @param s is the SSL struct
 * @return 1 for success, other value otherwise
 *
 * This swaps the inner CH to the outer CH without the
 * calling code knowing the SSL * struct content has
 * changed. The ECH callback will also be called from
 * within here as we only do this on clients after we
 * have confirmed ECH worked.
 */
int ech_swaperoo(SSL_CONNECTION *s);

/*
 * @brief send a GREASy ECH
 * @param s is the SSL connection
 * @param pkt is the in-work CH packet
 * @return 1 for success, 0 otherwise
 *
 * We send some random stuff that we hope looks like a real ECH
 * The unused parameters are just to match tls_construct_ctos_ech
 * which calls this - that's in case we need 'em later.
 */
int ech_send_grease(SSL_CONNECTION *s, WPACKET *pkt);

/*
 * @brief Calculate AAD and then do ECH encryption
 * @param s is the SSL connection
 * @param pkt is the packet to send
 * @return 1 for success, other otherwise
 *
 * 1. Make up the AAD:
 *      - the HPKE suite
 *      - my HPKE ephemeral public key
 *      - the encoded outer, minus the ECH
 * 2. Do the encryption
 * 3. Put the ECH back into the encoding
 * 4. Encode the outer (again!)
 */
int ech_aad_and_encrypt(SSL_CONNECTION *s, WPACKET *pkt);

/*
 * @brief reset the handshake buffer for transcript after ECH is good
 * @param s is the session
 * @param buf is the data to put into the transcript (usuallhy inner CH)
 * @param blen is the length of buf
 * @return 1 for success
 */
int ech_reset_hs_buffer(SSL_CONNECTION *s, const unsigned char *buf,
                        size_t blen);

/*
 * @brief If an ECH is present, attempt decryption
 * @param s: SSL session stuff
 * @param pkt: the received CH that might include an ECH
 * @param newpkt: the plaintext from ECH
 */
int ech_early_decrypt(SSL *s, PACKET *pkt, PACKET *newpkt);

/*
 * @brief say if extension at index i in ext_defs is to be ECH compressed
 * @param ind is the index of this extension in ext_defs (and ech_outer_config)
 * @return 1 if this one is to be compressed, 0 if not, -1 for error
 */
int ech_2bcompressed(int ind);

/*
 * @brief Given a CH find the offsets of the session id, extensions and ECH
 * @param: s is the SSL session
 * @param: pkt is the CH
 * @param: sessid points to offset of session_id length
 * @param: exts points to offset of extensions
 * @param: echoffset points to offset of ECH
 * @param: echtype points to the ext type of the ECH
 * @param: inner 1 if the ECH is marked as an inner, 0 for outer
 * @param: snioffset points to offset of (outer) SNI
 * @return 1 for success, other otherwise
 *
 * Offsets are set to zero if relevant thing not found.
 * Offsets are returned to the type or length field in question.
 */
int ech_get_ch_offsets(SSL_CONNECTION *s, PACKET *pkt, size_t *sessid,
                       size_t *exts, size_t *echoffset, uint16_t *echtype,
                       int *inner, size_t *snioffset);

/*
 * @brief Print the content of an SSL_ECH (for callback logging)
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param s is an SSL session strucutre
 * @param selector allows picking all (ECH_SELECT_ALL==-1) or just one RR value
 * @return 1 for success, anything else for failure
 */
int SSL_ech_print(BIO *out, SSL *s, int selector);

/*
 * @brief pick an ECHConfig to use
 * @param s is the SSL connection
 * @param tc is the ECHConfig to use (if found)
 * @param suite is the HPKE suite to use (if found)
 *
 * Search through the ECHConfigs for one that's a best
 * match in terms of outer_name vs. public_name.
 * If no public_name was set via API then we
 * just take the 1st match where we locally support
 * the HPKE suite.
 * If OTOH, a public_name was provided via API then
 * we prefer the first that matches that. We only try
 * for case-insensitive exact matches.
 * If no outer was provided, any will do.
 */
int ech_pick_matching_cfg(SSL_CONNECTION *s, ECHConfig **tc,
                          OSSL_HPKE_SUITE *suite);

#  ifdef OSSL_ECH_SUPERVERBOSE
/*
 * @brief Used in tracing
 */
void ech_pbuf(const char *msg, const unsigned char *buf, const size_t blen);
void ech_ptranscript(const char *msg, SSL_CONNECTION *s);
#  endif
# endif
#endif
