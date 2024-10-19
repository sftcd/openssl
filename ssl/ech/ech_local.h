/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal data structures and prototypes for handling
 * Encrypted ClientHello (ECH)
 */
#ifndef OPENSSL_NO_ECH

# ifndef HEADER_ECH_LOCAL_H
#  define HEADER_ECH_LOCAL_H

#  include <openssl/ssl.h>
#  include <openssl/ech.h>
#  include <openssl/hpke.h>

/*
 * Define this to get loads more lines of tracing which is
 * very useful for interop.
 * This needs tracing enabled at build time, e.g.:
 *          $ ./config enable-ssl-trace enable-trace
 * This added tracing will finally (mostly) disappear once the ECH RFC
 * has issued, but is very useful for interop testing so some of it might
 * be retained.
 */
#  define OSSL_ECH_SUPERVERBOSE

/* values for s->ext.ech.grease */
#  define OSSL_ECH_GREASE_UNKNOWN -1 /* when we're not yet sure */
#  define OSSL_ECH_NOT_GREASE 0 /* when decryption worked */
#  define OSSL_ECH_IS_GREASE 1 /* when decryption failed or GREASE wanted */

/* max values used when GREASEing */
#  define OSSL_ECH_MAX_GREASE_PUB 0x100 /* max peer key share we'll decode */
#  define OSSL_ECH_MAX_GREASE_CT 0x200 /* max GREASEy ciphertext we'll emit */

/*
 * When including a different key_share in the inner CH, 256 is the
 * size we produce for a real ECH when including padding in the inner
 * CH with the default/current client hello padding code.
 * This value doesn't vary with at least minor changes to inner SNI
 * length. The 272 is 256 of padded cleartext plus a 16-octet AEAD
 * tag.
 *
 * If we compress the key_share then that brings us down to 128 for
 * the padded inner CH and 144 for the ciphertext including AEAD
 * tag.
 *
 * We'll adjust the GREASE number below to match whatever
 * key_share handling we do.
 */
# define OSSL_ECH_DEF_CIPHER_LEN_SMALL 144
# define OSSL_ECH_DEF_CIPHER_LEN_LARGE 272

/*
 * We can add/subtract a few octets if jitter is desirable - if set then
 * we'll add or subtract a random number of octets less than the max jitter
 * setting. If the default value is set to zero, we won't bother. It is
 * probably better for now at least to not bother with jitter at all but
 * keeping the compile-time capability for now is probably worthwhile in
 * case experiments indicate such jitter is useful. To turn off jitter
 * just set the default to zero, as is currently done below.
 */
# define OSSL_ECH_MAX_CIPHER_LEN_JITTER 32 /* max jitter in cipher len */
# define OSSL_ECH_DEF_CIPHER_LEN_JITTER 0 /* default jitter in cipher len */

/* value for uninitialised ECH version */
#  define TLSEXT_TYPE_ech_unknown 0xffff
/* value for not yet set ECH config_id */
#  define TLSEXT_TYPE_ech_config_id_unset -1

#  define OSSL_ECH_OUTER_CH_TYPE 0 /* outer ECHClientHello enum */
#  define OSSL_ECH_INNER_CH_TYPE 1 /* inner ECHClientHello enum */

#  define OSSL_ECH_CIPHER_LEN 4 /* ECHCipher length (2 for kdf, 2 for aead) */

#  ifndef CLIENT_VERSION_LEN
/*
 * This is the legacy version length, i.e. len(0x0303). The same
 * label is used in e.g. test/sslapitest.c and elsewhere but not
 * defined in a header file I could find.
 */
#   define CLIENT_VERSION_LEN 2
#  endif

/*
 * To control the number of zeros added after a draft-13
 * EncodedClientHello - we pad to a target number of octets
 * or, if there are naturally more, to a number divisible by
 * the defined increment (we also do the draft-13 recommended
 * SNI padding thing first)
 */
# define OSSL_ECH_PADDING_TARGET 128 /* ECH cleartext padded to at least this */
# define OSSL_ECH_PADDING_INCREMENT 32 /* ECH padded to a multiple of this */

/* size of string buffer returned via ECH callback */
#  define OSSL_ECH_PBUF_SIZE 8 * 1024

/*
 * Reminder of what goes in DNS for ECH RFC XXXX
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
 *     } ECHConfig;
 *     ECHConfig ECHConfigList<1..2^16-1>;
 */

typedef struct ossl_echext_st {
    uint16_t type;
    uint16_t len;
    unsigned char *val;
} OSSL_ECHEXT;

DEFINE_STACK_OF(OSSL_ECHEXT)

typedef struct ossl_echstore_entry_st {
    uint16_t version; /* 0xff0d for draft-13 */
    char *public_name;
    size_t pub_len;
    unsigned char *pub;
    unsigned int nsuites;
    OSSL_HPKE_SUITE *suites;
    uint8_t max_name_length;
    uint8_t config_id;
    STACK_OF(OSSL_ECHEXT) *exts;
    time_t loadtime; /* time public and private key were loaded from file */
    EVP_PKEY *keyshare; /* long(ish) term ECH private keyshare on a server */
    int for_retry; /* whether to use this ECHConfigList in a retry */
    size_t encoded_len; /* length of overall encoded content */
    unsigned char *encoded; /* overall encoded content */
} OSSL_ECHSTORE_ENTRY;

DEFINE_STACK_OF(OSSL_ECHSTORE_ENTRY)

struct ossl_echstore_st {
    STACK_OF(OSSL_ECHSTORE_ENTRY) *entries;
    OSSL_LIB_CTX *libctx;
    const char *propq;
};

/* ECH details associated with an SSL_CTX */
typedef struct ossl_ctx_ech_st {
    OSSL_ECHSTORE *es;
    unsigned char *alpn_outer;
    size_t alpn_outer_len;
    SSL_ech_cb_func cb; /* callback function for when ECH "done" */
} OSSL_CTX_ECH;

/* ECH details associated with an SSL_CONNECTION */
typedef struct ossl_ech_conn_st {
    OSSL_ECHSTORE *es; /* ECHConfigList details */
    int no_outer; /* set to 1 if we should send no outer SNI at all */
    char *outer_hostname;
    unsigned char *alpn_outer;
    size_t alpn_outer_len;
    SSL_ech_cb_func cb; /* callback function for when ECH "done" */
    /*
     * If ECH fails, then we switch to verifying the cert for the
     * outer_hostname, meanwhile we still want to be able to trace
     * the value we tried as the inner SNI for debug purposes
     */
    char *former_inner;
    /*
     * TODO(ECH): The next 4 buffers (and lengths) may change later
     * if a better way to handle the mutiple transcripts needed is
     * suggested/invented. I'd suggest we review these when that code
     * is part of a PR (which won't be for a few PR's yet.)
     */
    /*
     * encoded inner ClientHello before/after ECH compression, which`
     * is nitty/complex (to avoid repeating the same extenstion value
     * in outer and inner, thus saving bandwidth) but (re-)calculating
     * the compression is a pain, so we'll store those as we make them
     */
    unsigned char *innerch; /* before compression */
    size_t innerch_len;
    unsigned char *encoded_innerch; /* after compression */
    size_t encoded_innerch_len;
    /*
     * in case of HRR, we need to record the 1st inner client hello, and
     * the first server hello (aka the HRR) so we can independently
     * generate the trancsript and accept confirmation when making the
     * 2nd server hello
     */
    unsigned char *innerch1;
    size_t innerch1_len;
    unsigned char *kepthrr;
    size_t kepthrr_len;
    /*
     * Extensions are "outer-only" if the value is only sent in the
     * outer CH and only the type is sent in the inner CH.
     * We use this array to keep track of the extension types that
     * with values only in the outer CH
     * Currently, this is basically contolled at compile time, but
     * in a way that could be varied, or, in future, put under
     * run-time control, so having this isn't so much an overhead.
     */
    uint16_t outer_only[OSSL_ECH_OUTERS_MAX];
    size_t n_outer_only; /* the number of outer_only extensions so far */
    /*
     * Index of the current extension's entry in ext_defs - this is
     * to avoid the need to change a couple of extension APIs.
     * TODO(ECH): check if there's another way to get that value
     */
    size_t ext_ind;
    /* ECH status vars */
    int ch_depth; /* set during CH creation, 0: doing outer, 1: doing inner */
    int attempted; /* 1 if ECH was or is being attempted, 0 otherwise */
    int done; /* 1 if we've finished ECH calculations, 0 otherwise */
    uint16_t attempted_type; /* ECH version used */
    int attempted_cid; /* ECH config id sent/rx'd */
    int backend; /* 1 if we're a server backend in split-mode, 0 otherwise */
    /*
     * success is 1 if ECH succeeded, 0 otherwise, on the server this
     * is known early, on the client we need to wait for the ECH confirm
     * calculation based on the SH (or 2nd SH in case of HRR)
     */
    int success;
    int grease; /* 1 if we're GREASEing, 0 otherwise */
    char *grease_suite; /* HPKE suite string for GREASEing */
    unsigned char *sent; /* GREASEy ECH value sent, in case needed for re-tx */
    size_t sent_len;
    unsigned char *returned; /* binary ECHConfigList retry-configs value */
    size_t returned_len;
    unsigned char *pub; /* client ephemeral public kept by server in case HRR */
    size_t pub_len;
    OSSL_HPKE_CTX *hpke_ctx; /* HPKE context, needed for HRR */
    /*
     * Fields that differ on client between inner and outer that we need to
     * keep and swap over IFF ECH has succeeded. Same names chosen as are
     * used in SSL_CONNECTION
     */
    EVP_PKEY *tmp_pkey; /* client's key share for inner */
    int group_id; /*  key share group */
    unsigned char client_random[SSL3_RANDOM_SIZE]; /* CH random */
} OSSL_ECH_CONN;

/* Return values from ech_same_ext */
#  define OSSL_ECH_SAME_EXT_ERR 0 /* bummer something wrong */
#  define OSSL_ECH_SAME_EXT_DONE 1 /* proceed with same value in inner/outer */
#  define OSSL_ECH_SAME_EXT_CONTINUE 2 /* generate a new value for outer CH */

/*
 * During extension construction (in extensions_clnt.c and surprisingly also in
 * extensions.c), we need to handle inner/outer CH cloning - ech_same_ext will
 * (depending on compile time handling options) copy the value from CH.inner to
 * CH.outer or else processing will continue, for a 2nd call, likely generating
 * a fresh value for the outer CH. The fresh value could well be the same as in
 * the inner.
 *
 * This macro should be called in each _ctos_ function that doesn't explicitly
 * have special ECH handling.
 *
 * Note that the placement of this macro needs a bit of thought - it has to go
 * after declarations (to keep the ansi-c compile happy) and also after any
 * checks that result in the extension not being sent but before any relevant
 * state changes that would affect a possible 2nd call to the constructor.
 * Luckily, that's usually not to hard, but it's not mechanical.
 */
#  define ECH_IOSAME(s, pkt) \
    if (s->ext.ech.es != NULL && s->ext.ech.grease == 0) { \
        int __rv = ech_same_ext(s, pkt); \
        \
        if (__rv == OSSL_ECH_SAME_EXT_ERR) \
            return EXT_RETURN_FAIL; \
        if (__rv == OSSL_ECH_SAME_EXT_DONE) \
            return EXT_RETURN_SENT; \
        /* otherwise continue as normal */ \
    }

/* Internal ECH APIs */

int ossl_echstore_dup(OSSL_ECHSTORE **new, OSSL_ECHSTORE *old);
void ossl_echstore_entry_free(OSSL_ECHSTORE_ENTRY *ee);
void ossl_ctx_ech_free(OSSL_CTX_ECH *ce);
int ossl_ech_conn_init(SSL_CONNECTION *s, SSL_CTX *ctx,
                       const SSL_METHOD *method);
void ossl_ech_conn_free(OSSL_ECH_CONN *ec);
int ech_get_retry_configs(SSL_CONNECTION *s, unsigned char **rcfgs,
                          size_t *rcfgslen);
int ech_send_grease(SSL_CONNECTION *s, WPACKET *pkt);
int ech_pick_matching_cfg(SSL_CONNECTION *s, OSSL_ECHSTORE_ENTRY **ee,
                          OSSL_HPKE_SUITE *suite);
# ifdef OSSL_ECH_SUPERVERBOSE
void ech_pbuf(const char *msg, const unsigned char *buf, const size_t blen);
void ech_ptranscript(const char *msg, SSL_CONNECTION *s);
# endif
int ech_encode_inner(SSL_CONNECTION *s);
int ech_find_confirm(SSL_CONNECTION *s, int hrr, unsigned char *acbuf,
                     const unsigned char *shbuf, const size_t shlen);
int ech_make_transcript_buffer(SSL_CONNECTION *s, int for_hrr,
                               const unsigned char *shbuf, size_t shlen,
                               unsigned char **tbuf, size_t *tlen,
                               size_t *chend, size_t *fixedshbuf_len);
int ech_reset_hs_buffer(SSL_CONNECTION *s, const unsigned char *buf,
                        size_t blen);
int ech_aad_and_encrypt(SSL_CONNECTION *s, WPACKET *pkt);
int ech_swaperoo(SSL_CONNECTION *s);
int ech_calc_confirm(SSL_CONNECTION *s, int for_hrr, unsigned char *acbuf,
                     const unsigned char *shbuf, const size_t shlen);

/* these are internal but located in ssl/statem/extensions.c */
int ech_same_ext(SSL_CONNECTION *s, WPACKET *pkt);
int ech_same_key_share(void);
size_t ech_num_builtins(void);
int ech_2bcompressed(int ind);

# endif
#endif
