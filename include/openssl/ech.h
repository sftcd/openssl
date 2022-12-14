/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
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
# define OPENSSL_ECH_H

# ifndef OPENSSL_NO_ECH

#  include <openssl/ssl.h>
#  include <openssl/hpke.h>

/*
 * Some externally visible limits - most used for sanity checks that could be
 * bigger if needed, but that work for now
 */
#  define OSSL_ECH_MAX_PAYLOAD_LEN 1500 /* max ECH ciphertext to en/decode */
#  define OSSL_ECH_MIN_ECHCONFIG_LEN 32 /* min for all encodings */
#  define OSSL_ECH_MAX_ECHCONFIG_LEN 1500 /* max for all encodings */
#  define OSSL_ECH_MAX_ECHCONFIGEXT_LEN 100 /* ECHConfig extension max */
#  define OSSL_ECH_MAX_MAXNAMELEN 255 /* ECHConfig max for max name length */
#  define OSSL_ECH_MAX_PUBLICNAME 255 /* max ECHConfig public name length */

/*
 * To meet the needs of script-based tools (likely to deal with
 * base64 or ascii-hex encodings) and of libraries that might
 * handle binary values we supported various input formats for
 * encoded ECHConfigList API inputs:
 * - a binary (wireform) HTTPS/SVCB RRVALUE or just the ECHConfigList
 *   set of octets from that
 * - base64 encoded version of the above
 * - ascii-hex encoded version of the above
 * - DNS zone-file presentation-like format containing "ech=<b64-stuff>"
 * - we ccan also indicate the caller would like the library to guess
 *   which ecoding is being used
 *
 * This code supports catenated lists of such values (to make it easier
 * to feed values from scripts). Catenated binary values need no separator
 * as there is internal length information. Catenated ascii-hex or
 * base64 values need a separator semi-colon.
 *
 * All catenated values passed in a single call must use the same
 * encoding method.
 */
#  define OSSL_ECH_FMT_GUESS     0  /* implementation will guess */
#  define OSSL_ECH_FMT_BIN       1  /* catenated binary ECHConfigs */
#  define OSSL_ECH_FMT_B64TXT    2  /* base64 ECHConfigs (';' separated) */
#  define OSSL_ECH_FMT_ASCIIHEX  3  /* ascii-hex ECHConfigs (';' separated */
#  define OSSL_ECH_FMT_HTTPSSVC  4  /* presentation form with "ech=<b64>" */

#  define OSSL_ECH_FMT_SEPARATOR ";" /* separator str for catenation  */

/*
 * ECH version. We only support draft-13 as of now.  As/if new versions
 * are added, those will be noted here.
 * This isn't directly used in APIs (but is present/checked-for in some
 * encoded values), so is only made visible here as it has changed with
 * each substantive revision of the draft specification (and will likely
 * change at the last moment when an RFC is issued).
 */
#  define OSSL_ECH_DRAFT_13_VERSION 0xfe0d /* version from draft-13 */

/*
 * Return codes from SSL_ech_get_status
 */
#  define SSL_ECH_STATUS_BACKEND    4 /* ECH backend: saw an ech_is_inner */
#  define SSL_ECH_STATUS_GREASE_ECH 3 /* GREASEd and got an ECH in return */
#  define SSL_ECH_STATUS_GREASE     2 /* ECH GREASE happened  */
#  define SSL_ECH_STATUS_SUCCESS    1 /* Success */
#  define SSL_ECH_STATUS_FAILED     0 /* Some internal or protocol error */
#  define SSL_ECH_STATUS_BAD_CALL   -100 /* Some in/out arguments were NULL */
#  define SSL_ECH_STATUS_NOT_TRIED  -101 /* ECH wasn't attempted  */
#  define SSL_ECH_STATUS_BAD_NAME   -102 /* ECH ok but server cert bad */
#  define SSL_ECH_STATUS_NOT_CONFIGURED -103 /* ECH wasn't configured */
#  define SSL_ECH_STATUS_FAILED_ECH -105 /* We tried, failed and got an ECH */

/*
 * Application-visible form of ECH information from the DNS, from config
 * files, or from earlier API calls. APIs produce/process an array of these.
 */
typedef struct ossl_ech_dets_st {
    int index; /* externally re-usable reference to this value */
    char *public_name; /* public_name from API or ECHConfig */
    char *inner_name; /* server-name (for inner CH if doing ECH) */
    char *outer_alpns; /* outer ALPN string */
    char *inner_alpns; /* inner ALPN string */
    char *echconfig; /* a JSON-like version of the associated ECHConfig */
} OSSL_ECH_DETS;

/*
 * API calls based around SSL* values - basically for clients
 */

/**
 * @brief ingest binary or ascii-hex encoded SVCB/HTTPS RR value
 *
 * rrval may be the catenation of multiple encoded SVCB/HTPS RR
 * values.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g.
 * OSSL_ECH_FMT_ASCII_HEX
 *
 * @param s is the SSL connection
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param rrfmt is the provided format or OSSL_ECH_FMT_GUESS
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param rrlen is the length of the rrval
 * @return is 1 for success, error otherwise
 */
int SSL_ech_set1_svcb(SSL *s, int *num_echs,
                      int rrfmt, char *rrval, size_t rrlen);

/**
 * @brief ingest ECHConfig values provided as (binary or ascii-hex encoded)
 *
 * ekval may be the catenation of multiple encoded ECHConfigList's.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g.
 * OSSL_ECH_FMT_ASCII_HEX
 *
 * @param s is the SSL connection
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param ekfmt is the provided format or OSSL_ECH_FMT_GUESS
 * @param ekval is the binary, base64 or ascii-hex encoded ECHConfigs
 * @param eklen is the length of the ekval
 * @return is 1 for success, error otherwise
 */
int SSL_ech_set1_echconfig(SSL *s, int *num_echs,
                           int ekfmt, char *ekval, size_t eklen);

/**
 * @brief Set the inner and outer SNI
 * @param s is the SSL context
 * @param inner_name is the (to be) hidden service name
 * @param outer_name is the cleartext SNI name to use
 * @param no_outer set to 1 to send no outer SNI
 * @return 1 for success, error otherwise
 *
 * Providing a NULL outer_name has a special effect - that means we send the
 * ECHConfig.public_name (which is the default).  If you supply a non-NULL
 * value and do ECH then the value supplied here will override the
 * ECHConfig.public_name If you supply a NULL outer_name and no_outer has
 * the value 1, then no outer name will be sent, regardless of the
 * ECHConfig.public_name value.
 */
int SSL_ech_server_name(SSL *s, const char *inner_name, const char *outer_name,
                        int no_outer);

/**
 * @brief Set the outer SNI
 * @param s is the SSL connection
 * @param outer_name is the (to be) hidden service name
 * @param no_outer set to 1 to send no outer SNI
 * @return 1 for success, error otherwise
 *
 * Providing a NULL outer_name has a special effect - that means we send the
 * ECHConfig.public_name (which is the default).  If you supply a non-NULL
 * value and do ECH then the value supplied here will override the
 * ECHConfig.public_name If you supply NULL and no_outer is 1 then no
 * outer name will be sent, regardless of the ECHConfig.public_name value.
 */
int SSL_ech_set_outer_server_name(SSL *s, const char *outer_name, int no_outer);

/**
 * @brief set the ALPN values for the outer ClientHello
 * @param s is the SSL session
 * @param protos encodes the ALPN values
 * @param protos_len is the length of protos
 * @return 1 for success, error otherwise
 */
int SSL_ech_set_outer_alpn_protos(SSL *s, const unsigned char *protos,
                                  unsigned int protos_len);

/**
 * @brief free up memory for an OSSL_ECH_DETS
 *
 * @param dets is the structure to free up
 * @param count says how many indices are in dets
 */
void OSSL_ECH_DETS_free(OSSL_ECH_DETS *dets, int count);

/**
 * @brief utility fnc for application that wants to print an OSSL_ECH_DETS
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param dets is a pointer to an OSSL_ECH_DETS struture
 * @param count is the number of elements in dets
 * @return 1 for success, error othewise
 */
int OSSL_ECH_DETS_print(BIO *out, OSSL_ECH_DETS *dets, int count);

/**
 * @brief query the content of an SSL_ECH structure
 * @param s is the SSL session
 * @param dets returned array of visible form of the ECH details
 * @param count says how many indices are in the OSSL_ECH_DETS structure
 * @return 1 for success, error otherwise
 *
 * This function allows the application to examine some internals of an SSL_ECH
 * structure so that it can then down-select those to be used, if desired.  In
 * particular, the caller can see the public_name associated with each
 * ECHConfig value (after decoding and initial checking within the library),
 * which allows the application to choose which it would prefer to use.
 */
int SSL_ech_query(SSL *s, OSSL_ECH_DETS **dets, int *count);

/**
 * @brief down-select to choose a specific ECHConfig
 * @param s is an SSL structure with possibly multiple SSL_ECH values
 * @param index is the index value from an OSSL_ECH_DETS
 * @return 1 for success, error otherwise
 *
 * This allows the caller to select one of the loaded ECHConfig values
 * to use for the TLS session.
 */
int SSL_ech_reduce(SSL *s, int index);

/**
 * @brief API to allow calling code know ECH outcome, post-handshake
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
 * @param s is the SSL context
 * @param suite is the relevant suite string
 * @return 1 for success, other otherwise
 */
int SSL_ech_set_grease_suite(SSL *s, const char *suite);

/**
 * @brief allow clients to set a preferred ECH extension type when GREASEing
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
 * @brief prototype for an ECH callback
 * @param s is the SSL connection
 * @param str is for a string representation of the ECH details
 * @return 1 for success, other otherwise
 */
typedef unsigned int (*SSL_ech_cb_func)(SSL *s, char *str);

/**
 * @brief set an ECH callback for the SSL connection
 * @param s is the SSL session
 * @param f is the callback function
 *
 * This will be called once an ECH value has been processed.
 * At that point, e.g. SSL_ech_get_status() can be called
 * so the application can find out what happened.
 */
void SSL_ech_set_callback(SSL *s, SSL_ech_cb_func f);

/**
 * @brief provide access to a returned ECHConfig value
 * @param s is the SSL connection
 * @param ec is a pointer to the ECHConfig
 * @param eclen is a pointer to the length of the ECHConfig (zero if none)
 * @return 1 for success, other othewise
 *
 * If we GREASEd, or tried ECH and failed, and we got an ECHConfig in
 * return, the application can access the ECHConfig returned via this
 * API.
 */
int SSL_ech_get_returned(SSL *s, const unsigned char **ec, size_t *eclen);

/*
 * API calls based around SSL_CTX* values - basically for servers
 */

/**
 * @brief ingest SVCB/HTTPS RR value provided as (binary or ascii-hex encoded)
 * ekval may be the catenation of multiple encoded ECHConfigList's.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g.
 * OSSL_ECH_FMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param ekfmt is the provided format or OSSL_ECH_FMT_GUESS
 * @param eklen is the length of the ekval
 * @param ekval is the binary, base64 or ascii-hex encoded ECHConfigs
 * @return is 1 for success, error otherwise
 */
int SSL_CTX_ech_set1_echconfig(SSL_CTX *ctx, int *num_echs,
                               int ekfmt, size_t eklen, char *ekval);

/**
 * @brief report on the number of ECHConfig values currently loaded
 * @param ctx is the SSL server context
 * @param numkeys returns the number currently loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_key_status(SSL_CTX *ctx, int *numkeys);

/**
 * @brief remove some or all stored ECH Keys to allow clean re-loads
 * @param ctx is the SSL server context
 * @param age keep keys loaded in the last age seconds
 * @return 1 for success, other otherwise
 *
 * Supply a zero value for age to delete all keys. Providing age=3600 will
 * keep all keys loaded in the last hour.
 */
int SSL_CTX_ech_server_flush_keys(SSL_CTX *ctx, time_t age);

/**
 * @brief turn on ECH server-side
 * @param ctx is the SSL server context
 * @param echcfgfile the relevant ECHConfig plus private key file name
 * @return 1 for success, other otherwise
 *
 * When this works, the server will try decrypt ECH's from ClientHellos.
 * There's a special return value (SSL_R_FILE_OPEN_FAILED) for the case
 * where the input file can't be read, as that could happen in a way
 * that allows the server to continue anyway if an earlier call had
 * loaded a key pair.
 */
int SSL_CTX_ech_server_enable(SSL_CTX *ctx, const char *echcfgfile);

/**
 * @brief Turn on ECH server-side, with input a buffer rather than file
 * @param ctx is the SSL server context
 * @param buf ECHConfig(s) and private key in PEM format in a buffer
 * @param blen is the length of buf
 * @return 1 for success, other otherwise
 *
 * This is needed for e.g. rekeying haproxy, which doesn't like to
 * read from disk after start up.
 */
int SSL_CTX_ech_server_enable_buffer(SSL_CTX *ctx, const unsigned char *buf,
                                     const size_t blen);

/*!
 * @brief try load all the keys in PEM files found in a directory
 * @param ctx is an SSL_CTX
 * @oaram loaded returns the number of key pairs successfully loaded
 * @param echdir is the directory name
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_readpemdir(SSL_CTX *ctx, int *loaded, const char *echdir);

/**
 * @brief provide a way to do raw ECH decryption for split-mode frontends
 * @param ctx is an SSL_CTX
 * @param decrypted_ok is 0 on return if decryption failed, 1 if it worked
 * @param inner_sni is the inner SNI (if present)
 * @param outer_sni is the outer SNI (if present)
 * @param outer_ch is the entire client hello (possibly incl. ECH)
 * @param outer_len is the length of the above (on input the buffer size)
 * @param inner is the resulting plaintext CH, if all went well
 * @param inner_len is the length of the above (on input the buffer size)
 * @return 1 for success (incl. failed decrypt) or 0 on error
 */
int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            int *decrypted_ok,
                            char **inner_sni, char **outer_sni,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len);

/**
 * @brief set an ECH callback for the SSL context
 * @param ctx is the SSL_CTX
 * @param f is the callback function
 *
 * This will be called once an ECH value has been processed.
 * At that point, e.g. SSL_ech_get_status() can be called
 * so the application can find out what happened.
 */
void SSL_CTX_ech_set_callback(SSL_CTX *ctx, SSL_ech_cb_func f);

/*
 * API calls for management tools, mostly for server tooling
 */

/**
 * @brief Make an ECH key pair and ECHConfigList structure
 * @param echconfig is the ECHConfigList buffer
 * @param echconfiglen is size of that buffer (used on output)
 * @param priv is the private key buffer
 * @param privlen is size of that buffer (used on output)
 * @param ekversion is the version to make
 * @param max_name_length is the maximum name length
 * @param public_name is for inclusion within the ECHConfig
 * @param extlen is the length of extension
 * @param extvals is the encoded extensions
 * @return 1 for success, error otherwise
 */
int ossl_ech_make_echconfig(unsigned char *echconfig, size_t *echconfiglen,
                            unsigned char *priv, size_t *privlen,
                            uint16_t ekversion, uint16_t max_name_length,
                            const char *public_name, OSSL_HPKE_SUITE suite,
                            const unsigned char *extvals, size_t extlen);

# endif
#endif
