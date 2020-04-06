/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file 
 * This has the externally-visible data structures and prototypes 
 * for handling Encrypted ClientHello (ECHO)
 */

#ifndef OPENSSL_NO_ECHO

#ifndef HEADER_ECHO_H
# define HEADER_ECHO_H

# include <openssl/ssl.h>

#define MAX_ECHOCONFIGS_BUFLEN 2000  ///< max PEM encoded ESNIConfigs we'll emit

#define ECHO_MAX_RRVALUE_LEN 2000 ///< Max size of a collection of ECHO RR values

#define ECHO_SELECT_ALL -1 ///< used to duplicate all RRs in SSL_ECHO_dup

#define ECHO_PBUF_SIZE 8*1024 ///<  8K buffer used for print string sent to application via echo_cb

/*
 * Known text input formats for ECHOKeys RR values
 * - can be TXT containing base64 encoded value (draft-02)
 * - can be TYPE65439 containing ascii-hex string(s)
 * - can be TYPE65439 formatted as output from dig +short (multi-line)
 */
#define ECHO_RRFMT_GUESS     0  ///< try guess which it is
#define ECHO_RRFMT_BIN       1  ///< binary encoded
#define ECHO_RRFMT_ASCIIHEX  2  ///< draft-03 ascii hex value(s catenated)
#define ECHO_RRFMT_B64TXT    3  ///< draft-02 (legacy) base64 encoded TXT

#define ECHO_GREASE_VERSION 0xffff ///< Fake ECHOKeys version to indicate grease
#define ECHO_DRAFT_06_VERSION 0xff04 ///< ECHOConfig version from draft-06 


/**
 * Exterally visible form of an ECHOKeys RR value
 */
typedef struct ssl_echo_ext_st {
    int index; ///< externally re-usable reference to this RR value
    char *public_name; ///< public_name from ECHOKeys
    char *prefixes;  ///< comma separated list of IP address prefixes, in CIDR form
    uint64_t not_before; ///< from ECHOKeys (not currently used)
    uint64_t not_after; ///< from ECHOKeys (not currently used)
} SSL_ECHO_ext; 


/*
 * Externally visible Prototypes
 */

/**
 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 *
 * The esnnikeys value here may be the catenation of multiple encoded ECHOKeys RR values 
 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECHO_RRFMT_ASCII_HEX
 *
 * @param con is the SSL connection 
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param echokeys is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echos says how many SSL_ECHO structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_add_ECHO(SSL *con, const short ekfmt, const size_t eklen, const char *echokeys, int *num_echos);

/**
 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 *
 * The esnnikeys value here may be the catenation of multiple encoded ECHOKeys RR values 
 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECHO_RRFMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param echokeys is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echos says how many SSL_ECHO structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_CTX_add_ECHO(SSL_CTX *ctx, const short ekfmt, const size_t eklen, const char *echokeys, int *num_echos);

/**
 * @brief Turn on SNI encryption for an (upcoming) TLS session
 * 
 * @param s is the SSL context
 * @param hidden_name is the hidden service name
 * @param public_name is the cleartext SNI name to use
 * @return 1 for success, error otherwise
 * 
 */
int SSL_echo_server_name(SSL *s, const char *hidden_name, const char *public_name);

/**
 * @brief Turn on ALPN encryption for an (upcoming) TLS session
 * 
 * @param s is the SSL context
 * @param hidden_alpns is the hidden service alpns
 * @param public_alpns is the cleartext SNI alpns to use
 * @return 1 for success, error otherwise
 * 
 */
int SSL_echo_alpns(SSL *s, const char *hidden_alpns, const char *public_alpns);

/**
 * @brief query the content of an SSL_ECHO structure
 *
 * This function allows the application to examine some internals
 * of an SSL_ECHO structure so that it can then down-select some
 * options. In particular, the caller can see the public_name and
 * IP address related information associated with each ECHOKeys
 * RR value (after decoding and initial checking within the
 * library), and can then choose which of the RR value options
 * the application would prefer to use.
 *
 * @param in is the SSL session
 * @param out is the returned externally visible detailed form of the SSL_ECHO structure
 * @param nindices is an output saying how many indices are in the SSL_ECHO_ext structure 
 * @return 1 for success, error otherwise
 */
int SSL_echo_query(SSL *in, SSL_ECHO_ext **out, int *nindices);

/** 
 * @brief free up memory for an SSL_ECHO_ext
 *
 * @param in is the structure to free up
 * @param size says how many indices are in in
 */
void SSL_ECHO_ext_free(SSL_ECHO_ext *in, int size);

/**
 * @brief utility fnc for application that wants to print an SSL_ECHO_ext
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param se is a pointer to an SSL_ECHO_ext struture
 * @param count is the number of elements in se
 * @return 1 for success, error othewise
 */
int SSL_ECHO_ext_print(BIO* out, SSL_ECHO_ext *se, int count);

/**
 * @brief down-select to use of one option with an SSL_ECHO
 *
 * This allows the caller to select one of the RR values 
 * within an SSL_ECHO for later use.
 *
 * @param in is an SSL structure with possibly multiple RR values
 * @param index is the index value from an SSL_ECHO_ext produced from the 'in'
 * @return 1 for success, error otherwise
 */
int SSL_ECHO_reduce(SSL *in, int index);

/**
 * Report on the number of ECHO key RRs currently loaded
 *
 * @param s is the SSL server context
 * @param numkeys returns the number currently loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_echo_server_key_status(SSL_CTX *s, int *numkeys);

/**
 * Zap the set of stored ECHO Keys to allow a re-load without hogging memory
 *
 * Supply a zero or negative age to delete all keys. Providing age=3600 will
 * keep keys loaded in the last hour.
 *
 * @param s is the SSL server context
 * @param age don't flush keys loaded in the last age seconds
 * @return 1 for success, other otherwise
 */
int SSL_CTX_echo_server_flush_keys(SSL_CTX *s, int age);

/**
 * Turn on ECHO server-side
 *
 * When this works, the server will decrypt any ECHO seen in ClientHellos and
 * subsequently treat those as if they had been send in cleartext SNI.
 *
 * @param s is the SSL server context
 * @param con is the SSL connection (can be NULL)
 * @param echokeyfile has the relevant (X25519) private key in PEM format, or both keys
 * @param echopubfile has the relevant (binary encoded, not base64) ECHOKeys structure, or is NULL
 * @return 1 for success, other otherwise
 */
int SSL_CTX_echo_server_enable(SSL_CTX *s, const char *echokeyfile, const char *echopubfile);

/** 
 * Print the content of an SSL_ECHO
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param con is an SSL session strucutre
 * @param selector allows for picking all (ECHO_SELECT_ALL==-1) or just one of the RR values in orig
 * @return 1 for success, anything else for failure
 * 
 */
int SSL_ECHO_print(BIO* out, SSL *con, int selector);

/* 
 * Possible return codes from SSL_get_echo_status
 */

#define SSL_ECHO_STATUS_GREASE                  2 ///< ECHO GREASE happened (if you care:-)
#define SSL_ECHO_STATUS_SUCCESS                 1 ///< Success
#define SSL_ECHO_STATUS_FAILED                  0 ///< Some internal error
#define SSL_ECHO_STATUS_BAD_CALL             -100 ///< Required in/out arguments were NULL
#define SSL_ECHO_STATUS_NOT_TRIED            -101 ///< ECHO wasn't attempted 
#define SSL_ECHO_STATUS_BAD_NAME             -102 ///< ECHO succeeded but the server cert didn't match the hidden service name
#define SSL_ECHO_STATUS_TOOMANY              -103 ///< ECHO succeeded can't figure out which one!

/**
 * @brief API to allow calling code know ECHO outcome, post-handshake
 *
 * This is intended to be called by applications after the TLS handshake
 * is complete. This works for both client and server. The caller does
 * not have to (and shouldn't) free the hidden or clear_sni strings.
 * TODO: Those are pointers into the SSL struct though so maybe better
 * to allocate fresh ones.
 *
 * Note that the PR we sent to curl will include a check that this
 * function exists (something like "AC_CHECK_FUNCS( SSL_get_echo_status )"
 * so don't change this name without co-ordinating with that.
 * The curl PR: https://github.com/curl/curl/pull/4011
 *
 * @param s The SSL context (if that's the right term)
 * @param hidden will be set to the address of the hidden service
 * @param clear_sni will be set to the address of the hidden service
 * @return 1 for success, other otherwise
 */
int SSL_get_echo_status(SSL *s, char **hidden, char **clear_sni);

#endif
#endif
