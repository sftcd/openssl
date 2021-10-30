/*
 * Copyright 2020,2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file
 * This has the externally-visible data structures and prototypes
 * for handling Encrypted ClientHello (ECH)
 */


#ifndef OPENSSL_ECH_H
#define OPENSSL_ECH_H

#ifndef OPENSSL_NO_ECH

# include <openssl/ssl.h>

/*
 * Default for HPKE_MAXSIZE is in hpke.h (40KB) but can be overridden so
 * let's do that, since we don't need such large buffers. (HPKE uses
 * a bunch of such stack buffers for keys and .)
 * If this were 0x300 (768) it'd not be big enough for larger curves
 * when doing session resumption. If some server's tickets are
 * much bigger then we might need to revisit using stack buffers
 * for this.
 */
#define HPKE_MAXSIZE 1280

/*
 * The minimum lengths to which to pad the Certificate, CertificateVerify and
 * EncryptedExtensions handshake messages from a server if the ECH specific
 * padding option is enabled.
 */
#define ECH_CERTSPECIFIC_MIN 1808
#define ECH_CERTVERSPECIFIC_MIN 480
#define ECH_ENCEXTSPECIFIC_MIN 32

/*
 * Various externally visible length limits
 */
#define ECH_MAX_RRVALUE_LEN 2000 /**< Max RR value size, as given to API */
#define ECH_MAX_ECHCONFIGEXT_LEN 100 /**< Max for an ECHConfig extension */
#define ECH_PBUF_SIZE 8*1024 /**<  buffer for string returned via ech_cb */
#define ECH_MIN_ECHCONFIG_LEN 32 /**< just for a sanity check */
#define ECH_MAX_ECHCONFIG_LEN ECH_MAX_RRVALUE_LEN /**< for a sanity check */
#define ECH_OUTERS_MAX 10 /**< max TLS extensions we compress via outer-exts */
#define ECH_MAX_ECH_LEN 0x100 /**< max ENC-CH peer key share we'll decode */
#define ECH_MAX_PAYLOAD_LEN HPKE_MAXSIZE /**< max ECH ciphertext we'll decode */
#define ECH_MAX_MAXNAMELEN 255 /**< max ECHConfig max name length */
#define ECH_MAX_PUBLICNAME 255 /**< max ECHConfig public name */

/*
 * Supported input formats for ECHConfigList input (usually from RR value)
 * - can be a binary (wireform) HTTPS/SVCB RRVALUE or just the ECHConfigList
 * - can be base64 encoded version of the above
 * - can be ascii-hex encoded version of the above
 * - can be (a guess at) the presentation format from a zone file
 * - can indicate the caller would like the library to guess which
 *   of the above applies
 */
#define ECH_FMT_GUESS     0  /**< implementation will try guess type */
#define ECH_FMT_BIN       1  /**< one or more catenated binary ECHConfigs */
#define ECH_FMT_B64TXT    2  /**< base64 ECHConfigs (';' separated if >1) */
#define ECH_FMT_ASCIIHEX  3  /**< ascii-hex ECHConfigs (';' separated if >1) */
#define ECH_FMT_HTTPSSVC  4  /**< presentation form of HTTPSSVC */

/*
 * Draft version values. We only really support draft-13 as of now.
 * Draft-10 was supported in earlier version (see commit history).
 * Draft-09 was supported in earlier version (see commit history).
 */
#define ECH_DRAFT_09_VERSION 0xfe09 /**< ECHConfig version from draft-09 */
#define ECH_DRAFT_10_VERSION 0xfe0a /**< ECHConfig version from draft-10 */
#define ECH_DRAFT_13_VERSION 0xfe0d /**< ECHConfig version from draft-13 */

/*
 * The wire-format type code for ECH/ECHConfiGList within an SVCB or HTTPS RR
 * value
 */
#define ECH_PCODE_ECH            0x0005

/*
 * To control the number of zeros added after a draft-13
 * EncodedClientHello - we pad to a target number of octets
 * or, if there are naturally more, to a number divisible by
 * the defined increment (we also do the draft-13 recommended
 * SNI padding thing first)
 */
#define ECH_PADDING_TARGET 256 /**< all ECH cleartext padded to at least this */
#define ECH_PADDING_INCREMENT 32 /**< all ECH's padded to a multiple of this */

/*
 * A failure return value from SSL_CTX_ech_server_enable for the
 * case where the input file can't be read. We have a separate
 * return value as that could happen due to a disk error but
 * perhaps the application could continue if some keys were
 * previously loaded
 */
#define ECH_FILEMISSING 2

/*
 * used to indicate "all" in SSL_ech_print etc. 
 */
#define ECH_SELECT_ALL -1 

/*
 * Possible return codes from SSL_ech_get_status
 */
#define SSL_ECH_STATUS_BACKEND    4 /**< ECH backend: saw an ech_is_inner */
#define SSL_ECH_STATUS_GREASE_ECH 3 /**< We GREASEd and got an ECH in return */
#define SSL_ECH_STATUS_GREASE     2 /**< ECH GREASE happened  */
#define SSL_ECH_STATUS_SUCCESS    1 /**< Success */
#define SSL_ECH_STATUS_FAILED     0 /**< Some internal or protocol error */
#define SSL_ECH_STATUS_BAD_CALL   -100 /**< Some in/out arguments were NULL */
#define SSL_ECH_STATUS_NOT_TRIED  -101 /**< ECH wasn't attempted  */
#define SSL_ECH_STATUS_BAD_NAME   -102 /**< ECH ok but server cert mis-match */
#define SSL_ECH_STATUS_NOT_CONFIGURED  -103 /**< ECH wasn't configured */
#define SSL_ECH_STATUS_FAILED_ECH -105 /**< We tried, failed and got an ECH */

/**
 * Exterally visible form of an ECHConfigList from an RR value
 *
 * The middle four values are associated with the SSL data structure
 * and not the more static ECHConfigList (or SVCB/HTTPS RR value).
 */
typedef struct ech_dets_st {
    int index; /**< externally re-usable reference to this value */
    char *public_name; /**< public_name from API */
    char *inner_name; /**< server-name for inner CH */
    char *outer_alpns; /**< outer ALPN string */
    char *inner_alpns; /**< inner ALPN string */
    char *echconfig; /**< a JSON-like version of the associated ECHConfig */
} ECH_DETS;


/*
 * This is a special marker value. If set in a call to any of our 
 * external APIs that allow setting SNI, then we'll override use of the
 * ECHConfig.public_name and send no outer SNI.
 * This is also mentioned in util/libssl.num as an
 * extern variable.
 */
extern char *ech_public_name_override_null;
#define ECH_PUBLIC_NAME_OVERRIDE_NULL  ech_public_name_override_null

/*
 * Externally visible Prototypes
 */

/**
 * @brief ingest SVCB/HTTPS RR value provided as (binary or ascii-hex encoded)
 *
 * rrval may be the catenation of multiple encoded ECHConfigList's.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g.
 * ECH_FMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param rrlen is the length of the rrval
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_CTX_svcb_add(
        SSL_CTX *ctx,
        short rrfmt,
        size_t rrlen,
        char *rrval,
        int *num_echs);

/**
 * @brief ingest SVCB/HTTPS RR value provided as (binary or ascii-hex encoded)
 *
 * rrval may be the catenation of multiple encoded ECHConfigList's.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g.
 * ECH_FMT_ASCII_HEX
 *
 * @param con is the SSL connection
 * @param rrlen is the length of the rrval
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_svcb_add(
        SSL *con,
        int rrfmt,
        size_t rrlen,
        char *rrval,
        int *num_echs);

/**
 * @brief ingest ECHConfigList'ss provided as (binary, base64 or ascii-hex
 * encoded)
 *
 * ekval may be the catenation of multiple encoded ECHConfigList's.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g.
 * ECH_FMT_ASCII_HEX
 *
 * @param con is the SSL connection
 * @param eklen is the length of the ekval
 * @param ekval is the binary, base64 or ascii-hex encoded ECHConfigs
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_ech_add(
        SSL *con,
        int ekfmt,
        size_t eklen,
        char *echkeys,
        int *num_echs);

/**
 * @brief ingest ECHConfigs provided as (binary, base64 or ascii-hex encoded)
 *
 * ekval may be the catenation of multiple encoded ECHConfigList's.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g.
 * ECH_FMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param eklen is the length of the ekval
 * @param ekval is the binary, base64 or ascii-hex encoded ECHConfigs
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_CTX_ech_add(
        SSL_CTX *ctx,
        short ekfmt,
        size_t eklen,
        char *echkeys,
        int *num_echs);

/**
 * @brief Set the inner and outer SNI
 *
 * @param s is the SSL context
 * @param inner_name is the (to be) hidden service name
 * @param outer_name is the cleartext SNI name to use
 * @return 1 for success, error otherwise
 *
 * Providing a NULL outer_name has a special effect - that means we send the
 * ECHConfig.public_name (which is the default).  If you supply a non-NULL 
 * value and do ECH then the value supplied here will override the
 * ECHConfig.public_name If you supply ECH_PUBLIC_NAME_OVERRIDE_NULL then no
 * outer name will be sent, regardless of the ECHConfig.public_name value.
 */
int SSL_ech_server_name(
        SSL *s,
        const char *inner_name,
        const char *outer_name);

/**
 * @brief Set the outer SNI
 *
 * @param s is the SSL_CTX
 * @param outer_name is the (to be) hidden service name
 * @return 1 for success, error otherwise
 *
 * Providing a NULL outer_name has a special effect - that means we send the
 * ECHConfig.public_name (which is the default).  If you supply a non-NULL 
 * value and do ECH then the value supplied here will override the
 * ECHConfig.public_name If you supply ECH_PUBLIC_NAME_OVERRIDE_NULL then no
 * outer name will be sent, regardless of the ECHConfig.public_name value.
 */
int SSL_CTX_ech_set_outer_server_name(SSL_CTX *s, const char *outer_name);

/**
 * @brief Set the outer SNI
 *
 * @param s is the SSL context
 * @param outer_name is the (to be) hidden service name
 * @return 1 for success, error otherwise
 *
 * Providing a NULL outer_name has a special effect - that means we send the
 * ECHConfig.public_name (which is the default).  If you supply a non-NULL 
 * value and do ECH then the value supplied here will override the
 * ECHConfig.public_name If you supply ECH_PUBLIC_NAME_OVERRIDE_NULL then no
 * outer name will be sent, regardless of the ECHConfig.public_name value.
 */
int SSL_ech_set_outer_server_name(SSL *s, const char *outer_name);

/**
 * @brief set the ALPN values for the outer ClientHello
 *
 * @param s is the SSL_CTX
 * @param protos encodes the ALPN values
 * @param protos_len is the length of protos
 * @return 1 for success, error otherwise
 */
int SSL_CTX_ech_set_outer_alpn_protos(
        SSL_CTX *ctx,
        const unsigned char *protos,
        const size_t protos_len);

/**
 * @brief set the ALPN values for the outer ClientHello
 *
 * @param s is the SSL session
 * @param protos encodes the ALPN values
 * @param protos_len is the length of protos
 * @return 1 for success, error otherwise
 */
int SSL_ech_set_outer_alpn_protos(
        SSL *ssl,
        const unsigned char *protos,
        unsigned int protos_len);

/**
 * @brief query the content of an SSL_ECH structure
 *
 * @param in is the SSL session
 * @param out returned externally visible detailed form of the SSL_ECH structure
 * @param nindices says how many indices are in the ECH_DETS structure
 * @return 1 for success, error otherwise
 *
 * This function allows the application to examine some internals of an SSL_ECH
 * structure so that it can then down-select those to be used, if desired.  In
 * particular, the caller can see the public_name associated with each
 * ECHConfig value (after decoding and initial checking within the library),
 * which allows the application to choose which it would prefer to use.
 */
int SSL_ech_query(SSL *in, ECH_DETS **out, int *nindices);

/**
 * @brief free up memory for an ECH_DETS
 *
 * @param in is the structure to free up
 * @param size says how many indices are in in
 */
void SSL_ECH_DETS_free(ECH_DETS *in, int size);

/**
 * @brief utility fnc for application that wants to print an ECH_DETS
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param se is a pointer to an ECH_DETS struture
 * @param count is the number of elements in se
 * @return 1 for success, error othewise
 */
int SSL_ECH_DETS_print(BIO* out, ECH_DETS *se, int count);

/**
 * @brief down-select to use of one ECHConfig with an SSL_ECH
 *
 * @param in is an SSL structure with possibly multiple RR values
 * @param index is the index value from an ECH_DETS produced from the 'in'
 * @return 1 for success, error otherwise
 *
 * This allows the caller to select one of the SSL_ECH to use
 * for a TLS session.
 */
int SSL_ech_reduce(SSL *in, int index);

/**
 * Report on the number of ECHConfig values currently loaded
 *
 * @param s is the SSL server context
 * @param numkeys returns the number currently loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_key_status(SSL_CTX *s, int *numkeys);

/**
 * @brief remove one/some stored ECH Keys to allow clean re-loads
 *
 * @param s is the SSL server context
 * @param age don't flush keys loaded in the last age seconds
 * @return 1 for success, other otherwise
 *
 * Supply a zero or negative age to delete all keys. Providing age=3600 will
 * keep keys loaded in the last hour.
 */
int SSL_CTX_ech_server_flush_keys(SSL_CTX *s, int age);

/**
 * @brief Turn on ECH server-side
 *
 * @param s is the SSL server context
 * @param echcfgfile the relevant ECHConfig plus private key file name
 * @return 1 for success, other otherwise
 *
 * When this works, the server will try decrypt ECH's from ClientHellos.
 * There's a special return value for the case where the input file can't
 * be read, as that could happen in a way that allows the server to
 * continue anyway if an earlier call had loaded a key pair.
 */
int SSL_CTX_ech_server_enable(SSL_CTX *s, const char *echcfgfile);

/**
 * @brief Turn on ECH server-side, with input a buffer rather than file
 *
 * @param s is the SSL server context
 * @param buf ECHConfig(s) and private key in PEM format in a buffer
 * @param blen is the length of buf
 * @return 1 for success, other otherwise
 *
 * When this works, the server will try decrypt ECH's from ClientHellos.
 */
int SSL_CTX_ech_server_enable_buffer(
        SSL_CTX *s,
        const unsigned char *buf,
        const size_t blen);

/*!
 * @brief try load all the keys in PEM files found in a directory
 *
 * @param ctx is an SSL_CTX
 * @param echdir is the directory name
 * @oaram number_loaded returns the number of key pairs successfully loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_readpemdir(
        SSL_CTX *ctx,
        const char *echdir,
        int *number_loaded);

/**
 * Print the content of an SSL_ECH
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param con is an SSL session strucutre
 * @param selector allows picking all (ECH_SELECT_ALL==-1) or just one RR value
 * @return 1 for success, anything else for failure
 */
int SSL_ech_print(BIO* out, SSL *con, int selector);

/**
 * @brief API to allow calling code know ECH outcome, post-handshake
 *
 * @param s The SSL context (if that's the right term)
 * @param inner_sni will be set to the SNI from the inner CH (if any)
 * @param outer_sni will be set to the SNI from the outer CH (if any)
 * @return 1 for success, other otherwise
 *
 * This is intended to be called by applications after the TLS handshake
 * is complete. This works for both client and server. The caller does
 * not have to (and shouldn't) free the inner_sni or outer_sni strings.
 */
int SSL_ech_get_status(SSL *s, char **inner_sni, char **outer_sni);

/**
 * @brief allow clients to set a preferred HPKE suite to use when GREASEing
 *
 * @param s is the SSL context
 * @param suite is the relevant suite string
 * @return 1 for success, other otherwise
 */
int SSL_ech_set_grease_suite(SSL *s,const char* suite);

/**
 * @brief allow clients to set a preferred HPKE suite to use when GREASEing
 *
 * @param s is the SSL context
 * @param type is the relevant ECH extension type
 * @return 1 for success, other otherwise
 *
 * There may be a (short-term or long-term) need to use different
 * TLS extension types for GREASEing ECH. Short-term, applications
 * may need to deal with pre-RFC versions. Longer-term, if the ECH
 * extension type evolves (which it may) then applications might
 * need to use a non-default extension type for ECH GREASE.
 */
int SSL_ech_set_grease_type(SSL *s, uint16_t type);

/**
 * @brief provide a way to do raw ECH decryption for split-mode frontends
 *
 * @param ctx is an SSL_CTX
 * @param outer_ch is the entire client hello (possibly incl. ECH)
 * @param outer_len is the length of the above (on input the buffer size)
 * @param inner is the resulting plaintext CH, if all went well
 * @param inner_len is the length of the above (on input the buffer size)
 * @param inner_sni is the inner SNI (if present)
 * @param outer_sni is the outer SNI (if present)
 * @param decrypted_ok is 0 on return if decryption failed, 1 if it worked
 * @return 1 for success (incl. failed decrypt) or 0 on error
 *
 * Note that the outer_ch's length is inside the TLV data
 */
int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len,
                            char **inner_sni, char **outer_sni,
                            int *decrypted_ok);

/**
 * @brief prototype for an ECH callback
 *
 * @param ssl is the SSL session
 * @param str is a string representation of the ECH details
 * @return 1 for success, other otherwise
 */
typedef unsigned int (*SSL_ech_cb_func)(SSL *ssl, char *str);

/**
 * @brief set an ECH callback for the SSL session
 *
 * @param s is the SSL session
 * @param f is the callback function
 *
 * This will be called once an ECH value has been processed.
 * At that point, e.g. SSL_ech_get_status() could be called
 * so the application can find out what happened.
 */
void SSL_ech_set_callback(SSL *s, SSL_ech_cb_func f);

/**
 * @brief set an ECH callback for the SSL session
 *
 * @param s is the SSL_CTX
 * @param f is the callback function
 *
 * This will be called once an ECH value has been processed.
 * At that point, e.g. SSL_ech_get_status() could be called
 * so the application can find out what happened.
 */
void SSL_CTX_ech_set_callback(SSL_CTX *s, SSL_ech_cb_func f);

/**
 * @brief provide access to a returned ECHConfig value
 *
 * @param s is the SSL session
 * @param eclen is a pointer to the length of the ECHConfig (zero if none)
 * @param ec is a pointer to the ECHConfig
 * @return 1 for success, other othewise
 *
 * If we GREASEd, or tried and failed, and we got an ECHConfig in 
 * return, the application can access the ECHConfig returned via this
 * API.
 */
int SSL_ech_get_returned(SSL *s, size_t *eclen, const unsigned char **ec);

#endif
#endif
