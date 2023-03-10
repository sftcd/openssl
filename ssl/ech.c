/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "ssl_local.h"
#include "ech_local.h"
#include "statem/statem_local.h"
#include <openssl/rand.h>
#include <openssl/trace.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* Needed to use stat for file status below in ech_check_filenames */
#include <sys/types.h>
#include <sys/stat.h>
#if !defined(OPENSSL_SYS_WINDOWS)
# include <unistd.h>
#endif
#include "internal/o_dir.h"

#ifndef OPENSSL_NO_ECH

# ifndef PATH_MAX
#  define PATH_MAX 4096
# endif

/* For ossl_assert */
# include "internal/cryptlib.h"

/* For HPKE APIs */
# include <openssl/hpke.h>

/* SECTION: Macros */

/* a size for some crypto vars */
# define OSSL_ECH_CRYPTO_VAR_SIZE 2048

# define OSSL_ECH_MAX_GREASE_PUB 0x100 /* max peer key share we'll decode */
# define OSSL_ECH_MAX_GREASE_CT 0x200 /* max GREASEy ciphertext we'll emit */
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

# ifndef TLSEXT_MINLEN_host_name
/*
 * the shortest DNS name we allow, e.g. "a.bc" - maybe that should be defined
 * elsewhere?
 */
#  define TLSEXT_MINLEN_host_name 4
# endif

/*
 * To control the number of zeros added after a draft-13
 * EncodedClientHello - we pad to a target number of octets
 * or, if there are naturally more, to a number divisible by
 * the defined increment (we also do the draft-13 recommended
 * SNI padding thing first)
 */
# define OSSL_ECH_PADDING_TARGET 128 /* ECH cleartext padded to at least this */
# define OSSL_ECH_PADDING_INCREMENT 32 /* ECH padded to a multiple of this */

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
# define OSSL_ECH_FMT_GUESS     0  /* implementation will guess */
# define OSSL_ECH_FMT_BIN       1  /* catenated binary ECHConfigList */
# define OSSL_ECH_FMT_B64TXT    2  /* base64 ECHConfigList (';' separated) */
# define OSSL_ECH_FMT_ASCIIHEX  3  /* ascii-hex ECHConfigList (';' separated */
# define OSSL_ECH_FMT_HTTPSSVC  4  /* presentation form with "ech=<b64>" */
# define OSSL_ECH_FMT_DIG_UNK   5  /* dig unknown format (mainly ascii-hex) */
# define OSSL_ECH_FMT_DNS_WIRE  6  /* DNS wire format (binary + other) */
/* special case: HTTPS RR presentation form with no "ech=<b64>" */
# define OSSL_ECH_FMT_HTTPSSVC_NO_ECH 7

# define OSSL_ECH_B64_SEPARATOR " "    /* separator str for b64 decode  */
# define OSSL_ECH_FMT_LINESEP   "\r\n" /* separator str for lines  */

/*
 * The wire-format type code for ECH/ECHConfiGList within an SVCB or HTTPS RR
 * value
 */
# define OSSL_ECH_PCODE_ECH 0x0005

/*
 * return values from ech_check_filenames() used to decide if a keypair
 * needs reloading or not
 */
# define OSSL_ECH_KEYPAIR_ERROR          0
# define OSSL_ECH_KEYPAIR_NEW            1
# define OSSL_ECH_KEYPAIR_UNMODIFIED     2
# define OSSL_ECH_KEYPAIR_MODIFIED       3
# define OSSL_ECH_KEYPAIR_FILEMISSING    4

/* Copy old->f (with length flen) to new->f (used in ECHConfig_dup() */
# define ECHFDUP(__f__, __flen__, __type__) \
    if (old->__flen__ != 0) { \
        new->__f__ = (__type__)ech_len_field_dup((__type__)old->__f__, \
                                                 old->__flen__); \
        if (new->__f__ == NULL) \
            return 0; \
    }

/* Map ascii to binary - utility macro used in ah_decode() */
# define LOCAL_A2B(__c__) (__c__ >= '0' && __c__ <= '9'  \
                           ? (__c__ - '0') \
                           : (__c__ >= 'A' && __c__ <= 'F' \
                              ? (__c__ - 'A' + 10) \
                              : (__c__ >= 'a' && __c__ <= 'f' \
                                 ? (__c__ - 'a' + 10) \
                                 : 0)))

/* SECTION: local vars */

/*
 * Strings used in ECH crypto derivations (odd format for EBCDIC goodness)
 */
/* "tls ech" */
static const char OSSL_ECH_CONTEXT_STRING[] = "\x74\x6c\x73\x20\x65\x63\x68";
/* "ech accept confirmation" */
static char OSSL_ECH_ACCEPT_CONFIRM_STRING[] = "\x65\x63\x68\x20\x61\x63\x63\x65\x70\x74\x20\x63\x6f\x6e\x66\x69\x72\x6d\x61\x74\x69\x6f\x6e";
/* "hrr ech accept confirmation" */
static const char OSSL_ECH_HRR_CONFIRM_STRING[] = "\x68\x72\x72\x20\x65\x63\x68\x20\x61\x63\x63\x65\x70\x74\x20\x63\x6f\x6e\x66\x69\x72\x6d\x61\x74\x69\x6f\x6e";

/*
 * When doing ECH, this table specifies how we handle the encoding of
 * each extension type in the inner and outer ClientHello.
 *
 * If an extension constructor has side-effects then it is (in general)
 * unsafe to call twice. For others, we need to be able to call twice,
 * if we do want possibly different values in inner and outer, of if
 * the extension constructor is ECH-aware and handles side-effects
 * specially for inner and outer. If OTOH we want the inner to contain
 * a compressed form of the value in the outer we also need to signal
 * that.
 *
 * In general, if an extension constructor is ECH-aware then you ought
 * use the CALL_BOTH option. That currently (and perhaps unexpectedly)
 * includes early_data due to some side-effects of the first call being
 * specially handled in the 2nd. You should be able to select between
 * COMPRESS or DUPLICATE for any extension that's not CALL_BOTH below.
 *
 * Note that the set of COMPRESSed extensions in use for this TLS session
 * will be emitted first, in the order below, followed by those not
 * using COMPRESS, also in the order below. That means that changing
 * to/from COMPRESS for extensions will affect fingerprinting based on
 * the outer ClientHello. (That's because the compression mechanism for
 * ECH requires the compressed extensions to be a contiguous set in the
 * outer encoding.)
 *
 * The above applies to built-in extensions - all custom extensions
 * use COMPRESS handling, but that's not table-driven.
 *
 * As with ext_defs in extensions.c: NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the
 * indexes ( TLSEXT_IDX_* ) defined in ssl_local.h.
 *
 * These values may be better added as a field in ext_defs (in extensions.c).
 * TODO: merge those tables or not.
 */

/* defined in statem_local.h but also wanted here */
# ifndef TLSEXT_TYPE_cryptopro_bug
#  define TLSEXT_TYPE_cryptopro_bug 0xfde8
# endif

typedef struct {
    uint16_t type; /* the extension code point to record for compression */
    int handling; /* the handling to apply */
} ECH_EXT_HANDLING_DEF;

static const ECH_EXT_HANDLING_DEF ech_ext_handling[] = {
    { TLSEXT_TYPE_renegotiate, OSSL_ECH_HANDLING_COMPRESS },
    { TLSEXT_TYPE_server_name, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_max_fragment_length, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_srp, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_ec_point_formats, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_supported_groups, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_session_ticket, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_status_request, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_next_proto_neg, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_application_layer_protocol_negotiation,
      OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_use_srtp, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_encrypt_then_mac, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_signed_certificate_timestamp, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_extended_master_secret, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_signature_algorithms_cert, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_post_handshake_auth, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_signature_algorithms, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_supported_versions, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_psk_kex_modes, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_key_share, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_cookie, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_cryptopro_bug, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_compress_certificate, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_early_data, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_certificate_authorities, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_ech13, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_outer_extensions, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_padding, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_psk, OSSL_ECH_HANDLING_CALL_BOTH }
};

/*
 * Telltales we use when guessing which form of encoded input we've
 * been given for an RR value or ECHConfig.
 * We give these the EBCDIC treatment as well - why not? :-)
 */

/*
 * ascii hex with either case allowed, plus a semi-colon separator
 * "0123456789ABCDEFabcdef;"
 */
static const char *AH_alphabet =
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x61\x62"
    "\x63\x64\x65\x66\x3b";
/*
 * b64 plus a semi-colon - we accept multiple semi-colon separated values
 * "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=;"
 */
static const char *B64_alphabet =
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52"
    "\x53\x54\x55\x56\x57\x58\x59\x5a\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a"
    "\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x30\x31"
    "\x32\x33\x34\x35\x36\x37\x38\x39\x2b\x2f\x3d\x3b";
/*
 * telltales for ECH HTTPS/SVCB in presentation format, as per svcb spec
 * 1: "ech=" 2: "alpn=" 3: "ipv4hint=" 4: "ipv6hint="
 */
static const char *httpssvc_telltale1 = "\x65\x63\x68\x3d";
static const char *httpssvc_telltale2 = "\x61\x6c\x70\x6e\x3d";
static const char *httpssvc_telltale3 = "\x69\x70\x76\x34\x68\x69\x6e\x74\x3d";
static const char *httpssvc_telltale4 = "\x69\x70\x76\x36\x68\x69\x6e\x74\x3d";

/*
 * telltale for ECH HTTPS/SVCB in dig unknownformat (i.e. ascii-hex with a
 * header and some spaces
 * "\# " is the telltale
 */
static const char *unknownformat_telltale = "\x5c\x23\x20";

/* SECTION: Local functions */

/*
 * @brief Check if a key pair needs to be (re-)loaded or not
 * @param ctx is the SSL server context
 * @param pemfname is the PEM key filename
 * @param index is the index if we find a match
 * @return OSSL_ECH_KEYPAIR_*
 */
static int ech_check_filenames(SSL_CTX *ctx, const char *pemfname, int *index)
{
    struct stat pemstat;
    time_t pemmod;
    int ind = 0;
    size_t pemlen = 0;

    if (ctx == NULL || pemfname == NULL || index == NULL)
        return OSSL_ECH_KEYPAIR_ERROR;
    /* if we have none, then it is new */
    if (ctx->ext.ech == NULL || ctx->ext.nechs == 0)
        return OSSL_ECH_KEYPAIR_NEW;
    /*
     * if no file info, exit. That could happen if the disk fails hence
     * special return value - the application may be able to continue
     * anyway...
     */
    if (stat(pemfname, &pemstat) < 0)
        return OSSL_ECH_KEYPAIR_FILEMISSING;

    /* check the time info - we're only doing 1s precision on purpose */
# if defined(__APPLE__)
    pemmod = pemstat.st_mtimespec.tv_sec;
# elif defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
    pemmod = pemstat.st_mtime;
# else
    pemmod = pemstat.st_mtim.tv_sec;
# endif

    /*
     * search list of already loaded keys to see if we have
     * a macthing one already
     */
    pemlen = strlen(pemfname);
    for (ind = 0; ind != ctx->ext.nechs; ind++) {
        if (ctx->ext.ech[ind].pemfname == NULL)
            return OSSL_ECH_KEYPAIR_ERROR;
        if (pemlen == strlen(ctx->ext.ech[ind].pemfname)
            && !strncmp(ctx->ext.ech[ind].pemfname, pemfname, pemlen)) {
            /* matching files! */
            if (ctx->ext.ech[ind].loadtime < pemmod) {
                /* aha! load it up so */
                *index = ind;
                return OSSL_ECH_KEYPAIR_MODIFIED;
            } else {
                /* tell caller no need to bother */
                *index = -1; /* just in case:-> */
                return OSSL_ECH_KEYPAIR_UNMODIFIED;
            }
        }
    }
    *index = -1; /* just in case:-> */
    return OSSL_ECH_KEYPAIR_NEW;
}

/*
 * @brief Decode from TXT RR to binary buffer
 * @param in is the base64 encoded string
 * @param inlen is the length of in
 * @param out is the binary equivalent
 * @return is the number of octets in |out| if successful, <=0 for failure
 */
static int ech_base64_decode(char *in, size_t inlen, unsigned char **out)
{
    int i = 0;
    int outlen = 0;
    unsigned char *outbuf = NULL;

    if (in == NULL || out == NULL)
        return 0;
    if (inlen == 0) {
        *out = NULL;
        return 0;
    }
    /* overestimate of space but easier */
    outbuf = OPENSSL_malloc(inlen);
    if (outbuf == NULL)
        goto err;
    /* For ECH we'll never see this but just so we have bounds */
    if (inlen <= OSSL_ECH_MIN_ECHCONFIG_LEN
        || inlen > OSSL_ECH_MAX_ECHCONFIG_LEN)
        goto err;
    /* Check padding bytes in input.  More than 2 is malformed. */
    i = 0;
    while (in[inlen - i - 1] == '=') {
        if (++i > 2)
            goto err;
    }
    outlen = EVP_DecodeBlock(outbuf, (unsigned char *)in, inlen);
    outlen -= i; /* subtract padding */
    if (outlen < 0)
        goto err;
    *out = outbuf;
    return outlen;

err:
    OPENSSL_free(outbuf);
    *out = NULL;
    return 0;
}

/*
 * @brief Try figure out ECHConfig encodng by looking for telltales
 * @param eklen is the length of rrval
 * @param rrval is encoded thing
 * @param guessedfmt is our returned guess at the format
 * @return 1 for success, 0 for error
 *
 * We try check from most to least restrictive  to avoid wrong
 * answers. IOW we try from most constrained to least in that
 * order.
 *
 * The wrong answer could be derived with a low probability.
 * If the application can't handle that, then it ought not use
 * ossl_ech_find_echconfigs()
 */
static int ech_guess_fmt(size_t eklen, const unsigned char *rrval,
                         int *guessedfmt)
{
    size_t span = 0;

    /*
     * This could be more terse, but this is better for
     * debugging corner cases for now
     */
    if (guessedfmt == NULL || eklen == 0 || rrval == NULL)
        return 0;
    if (eklen < strlen(unknownformat_telltale))
        return 0;
    if (!strncmp((char *)rrval, unknownformat_telltale,
                 strlen(unknownformat_telltale))) {
        *guessedfmt = OSSL_ECH_FMT_DIG_UNK;
        return 1;
    }
    if (strstr((char *)rrval, httpssvc_telltale1)) {
        *guessedfmt = OSSL_ECH_FMT_HTTPSSVC;
        return 1;
    }
    if (strstr((char *)rrval, httpssvc_telltale2)
        || strstr((char *)rrval, httpssvc_telltale3)
        || strstr((char *)rrval, httpssvc_telltale4)) {
        *guessedfmt = OSSL_ECH_FMT_HTTPSSVC_NO_ECH;
        return 1;
    }
    span = strspn((char *)rrval, AH_alphabet);
    if (eklen <= span) {
        *guessedfmt = OSSL_ECH_FMT_ASCIIHEX;
        return 1;
    }
    span = strspn((char *)rrval, B64_alphabet);
    if (eklen <= span) {
        *guessedfmt = OSSL_ECH_FMT_B64TXT;
        return 1;
    }
    /* fallback - try binary */
    *guessedfmt = OSSL_ECH_FMT_BIN;
    return 1;
}

/*
 * @brief decode ascii hex to a binary buffer
 * @param ahlen is the ascii hex string length
 * @param ah is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return 1 for good otherwise bad
 *
 * We skip spaces in the input, 'cause dig might put 'em there
 * We require that the input has an even number of nibbles i.e.
 * do left justify with a zero nibble if needed
 */
static int ah_decode(size_t ahlen, const char *ah,
                     size_t *blen, unsigned char **buf)
{
    size_t i = 0, j = 0;
    unsigned char *lbuf = NULL;

    if (ahlen < 2 || ah == NULL || blen == NULL || buf == NULL)
        return 0;
    lbuf = OPENSSL_malloc(ahlen / 2 + 1);
    if (lbuf == NULL)
        return 0;
    for (i = 0; i <= (ahlen - 1); i += 2) {
        if (ah[i] == ' ') {
            i--; /* because we increment by 2 */
            continue;
        }
        if (j >= (ahlen / 2 + 1)) {
            OPENSSL_free(lbuf);
            return 0;
        }
        lbuf[j++] = LOCAL_A2B(ah[i]) * 16 + LOCAL_A2B(ah[i + 1]);
    }
    *blen = j;
    *buf = lbuf;
    return 1;
}

/*
 * @brief encode binary buffer as ascii hex
 * @param out is an allocated buffer for the ascii hex string
 * @param outsize is the size of the buffer
 * @param in is the input binary buffer
 * @param inlen is the size of the binary buffer
 * @return 1 for good otherwise bad
 */
static int ah_encode(char *out, size_t outsize,
                     const unsigned char *in, size_t inlen)
{
    size_t i;

    if (outsize < 2 * inlen + 1)
        return 0;
    for (i = 0; i != inlen; i++) {
        uint8_t tn = (in[i] >> 4) & 0x0f;
        uint8_t bn = (in[i] & 0x0f);

        out[2 * i] = (tn < 10 ? tn + '0' : (tn - 10 + 'A'));
        out[2 * i + 1] = (bn < 10 ? bn + '0' : (bn - 10 + 'A'));
    }
    out[2 * i] = '\0';
    return 1;
}

/*
 * @brief Decode the first ECHConfigList from a binary buffer
 * @param binbuf is the buffer with the encoding
 * @param binblen is the length of binbunf
 * @param ret_er NULL on error or no ECHConfig found, or a pointer to
 *         an ECHConfigList structure
 * @param new_echs returns the number of ECHConfig's found
 * @param leftover is the number of unused octets from the input
 * @return 1 for success, zero for error
 *
 * Note that new_echs can be zero at the end and that's not an error
 * if we got a well-formed ECHConfigList but that contained no
 * ECHConfig versions that we support
 */
static int ECHConfigList_from_binary(unsigned char *binbuf, size_t binblen,
                                     ECHConfigList **ret_er, int *new_echs,
                                     int *leftover)
{
    ECHConfigList *er = NULL; /* ECHConfigList record */
    ECHConfig *te = NULL; /* Array of ECHConfig to be embedded in that */
    int rind = 0;
    size_t remaining = 0;
    PACKET pkt;
    unsigned int olen = 0;
    size_t not_to_consume = 0;
    int rv = 0;

    if (ret_er == NULL || new_echs == NULL || leftover == NULL
        || binbuf == NULL || binblen == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (binblen < OSSL_ECH_MIN_ECHCONFIG_LEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (binblen >= OSSL_ECH_MAX_ECHCONFIG_LEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Overall length of this ECHConfigList (olen) still could be
     * less than the input buffer length, (binblen) if the caller has been
     * given a catenated set of binary buffers, which could happen
     * and which we will support
     */
    if (PACKET_buf_init(&pkt, binbuf, binblen) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!PACKET_get_net_2(&pkt, &olen)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (olen < (OSSL_ECH_MIN_ECHCONFIG_LEN - 2)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (olen > (binblen - 2)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    not_to_consume = binblen - olen;
    remaining = PACKET_remaining(&pkt);
    while (remaining > not_to_consume) {
        ECHConfig *ec = NULL;
        unsigned int ech_content_length = 0;
        unsigned char *tmpecstart = NULL;
        const unsigned char *tmpecp = NULL;
        size_t tmpeclen = 0;

        te = OPENSSL_realloc(te, (rind + 1) * sizeof(ECHConfig));
        if (te == NULL)
            goto err;
        ec = &te[rind];
        memset(ec, 0, sizeof(ECHConfig));
        rind++;
        /*
         * note start of encoding of this ECHConfig, so we can make a copy
         * later
         */
        tmpeclen = PACKET_remaining(&pkt);
        if (PACKET_peek_bytes(&pkt, &tmpecp, tmpeclen) != 1) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* Version */
        if (!PACKET_get_net_2(&pkt, &ec->version)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /*
         * Grab length of contents, needed in case we
         * want to skip over it, if it's a version we
         * don't support, or if >1 ECHConfig is in the
         * list.
         */
        if (!PACKET_get_net_2(&pkt, &ech_content_length)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        remaining = PACKET_remaining(&pkt);
        if ((ech_content_length - 2) > remaining) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* check version, store and skip-over raw octets if not supported */
        switch (ec->version) {
        case OSSL_ECH_DRAFT_13_VERSION:
            break;
        default:
            /* skip over in case we get something we can handle later */
            {
                unsigned char *foo = OPENSSL_malloc(ech_content_length);

                if (foo == NULL)
                    goto err;
                if (!PACKET_copy_bytes(&pkt, foo, ech_content_length)) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    OPENSSL_free(foo);
                    goto err;
                }
                OPENSSL_free(foo);
                remaining = PACKET_remaining(&pkt);
                /* unallocate that one */
                rind--;
                continue;
            }
        }

        /*
         * This check's a bit redundant at the moment with only one version
         * But, when we (again) support >1 version, the indentation will end
         * up like this anyway so may as well keep it.
         */
        if (ec->version == OSSL_ECH_DRAFT_13_VERSION) {
            PACKET pub_pkt;
            PACKET cipher_suites;
            int suiteoctets = 0;
            unsigned char cipher[OSSL_ECH_CIPHER_LEN];
            int ci = 0;
            PACKET public_name_pkt;
            PACKET exts;
            unsigned char max_name_len;

            /* read config_id - a fixed single byte */
            if (!PACKET_copy_bytes(&pkt, &ec->config_id, 1)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* Kem ID */
            if (!PACKET_get_net_2(&pkt, &ec->kem_id)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* read HPKE public key - just a blob */
            if (!PACKET_get_length_prefixed_2(&pkt, &pub_pkt)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ec->pub_len = PACKET_remaining(&pub_pkt);
            ec->pub = OPENSSL_malloc(ec->pub_len);
            if (ec->pub == NULL)
                goto err;
            if (PACKET_copy_bytes(&pub_pkt, ec->pub, ec->pub_len) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /*
             * List of ciphersuites - 2 byte len + 2 bytes per ciphersuite
             * Code here inspired by ssl/ssl_lib.c:bytes_to_cipher_list
             */
            if (!PACKET_get_length_prefixed_2(&pkt, &cipher_suites)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            suiteoctets = PACKET_remaining(&cipher_suites);
            if (suiteoctets <= 0 || (suiteoctets % 2) == 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ec->nsuites = suiteoctets / OSSL_ECH_CIPHER_LEN;
            ec->ciphersuites = OPENSSL_malloc(ec->nsuites
                                              * sizeof(ech_ciphersuite_t));
            if (ec->ciphersuites == NULL)
                goto err;

            while (PACKET_copy_bytes(&cipher_suites, cipher,
                                     OSSL_ECH_CIPHER_LEN))
                memcpy(ec->ciphersuites[ci++], cipher, OSSL_ECH_CIPHER_LEN);

            if (PACKET_remaining(&cipher_suites) > 0) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* Maximum name length */
            if (!PACKET_copy_bytes(&pkt, &max_name_len, 1)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ec->maximum_name_length = max_name_len;
            /* read public_name */
            if (!PACKET_get_length_prefixed_1(&pkt, &public_name_pkt)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ec->public_name_len = PACKET_remaining(&public_name_pkt);
            if (ec->public_name_len != 0) {
                if (ec->public_name_len < TLSEXT_MINLEN_host_name ||
                    ec->public_name_len > TLSEXT_MAXLEN_host_name) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                ec->public_name = OPENSSL_malloc(ec->public_name_len + 1);
                if (ec->public_name == NULL)
                    goto err;
                if (PACKET_copy_bytes(&public_name_pkt,
                                      ec->public_name,
                                      ec->public_name_len) != 1) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                ec->public_name[ec->public_name_len] = '\0';
            }
            /*
             * Extensions: we'll just store 'em for now and maybe parse any
             * we understand later (there are no well defined extensions
             * as of now).
             */
            if (!PACKET_get_length_prefixed_2(&pkt, &exts)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            while (PACKET_remaining(&exts) > 0) {
                unsigned int exttype = 0;
                unsigned int extlen = 0;
                unsigned char *extval = NULL;
                unsigned int *tip = NULL;
                unsigned int *lip = NULL;
                unsigned char **vip = NULL;

                ec->nexts += 1;
                /*
                 * a two-octet length prefixed list of:
                 * two octet extension type
                 * two octet extension length
                 * length octets
                 */
                if (!PACKET_get_net_2(&exts, &exttype)) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                if (!PACKET_get_net_2(&exts, &extlen)) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                if (extlen >= OSSL_ECH_MAX_ECHCONFIGEXT_LEN) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                if (extlen != 0) {
                    extval = (unsigned char *)OPENSSL_malloc(extlen);
                    if (extval == NULL)
                        goto err;
                    if (!PACKET_copy_bytes(&exts, extval, extlen)) {
                        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                        OPENSSL_free(extval);
                        goto err;
                    }
                }
                /* assign fields to lists, have to realloc */
                tip = (unsigned int *)OPENSSL_realloc(ec->exttypes,
                                                      ec->nexts
                                                      * sizeof(ec->exttypes[0])
                                                      );
                if (tip == NULL) {
                    OPENSSL_free(extval);
                    goto err;
                }
                ec->exttypes = tip;
                ec->exttypes[ec->nexts - 1] = exttype;
                lip = (unsigned int *)OPENSSL_realloc(ec->extlens,
                                                      ec->nexts
                                                      * sizeof(ec->extlens[0]));
                if (lip == NULL) {
                    OPENSSL_free(extval);
                    goto err;
                }
                ec->extlens = lip;
                ec->extlens[ec->nexts - 1] = extlen;
                vip = (unsigned char **)OPENSSL_realloc(ec->exts,
                                                        ec->nexts
                                                        * sizeof(unsigned
                                                                 char *));
                if (vip == NULL) {
                    OPENSSL_free(extval);
                    goto err;
                }
                ec->exts = vip;
                ec->exts[ec->nexts - 1] = extval;
            }
        }
        /* set length of encoding of this ECHConfig */
        ec->encoding_start = (unsigned char *)tmpecp;
        tmpeclen = PACKET_remaining(&pkt);
        if (PACKET_peek_bytes(&pkt, &tmpecp, tmpeclen) != 1) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ec->encoding_length = tmpecp - ec->encoding_start;
        /* copy encoding_start as it might get free'd if a reduce happens */
        tmpecstart = OPENSSL_malloc(ec->encoding_length);
        if (tmpecstart == NULL) {
            ec->encoding_start = NULL; /* don't free twice in this case */
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(tmpecstart, ec->encoding_start, ec->encoding_length);
        ec->encoding_start = tmpecstart;
        remaining = PACKET_remaining(&pkt);
    }
    if (PACKET_remaining(&pkt) > binblen) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Success - make up return value */
    *new_echs = rind;
    *leftover = PACKET_remaining(&pkt);
    if (rind == 0) {
        rv = 1; /* return success but free stuff */
        goto err;
    }
    er = (ECHConfigList *)OPENSSL_malloc(sizeof(ECHConfigList));
    if (er == NULL)
        goto err;
    memset(er, 0, sizeof(ECHConfigList));
    er->nrecs = rind;
    er->recs = te;
    te = NULL;
    er->encoded_len = binblen;
    er->encoded = OPENSSL_malloc(binblen);
    if (er->encoded == NULL)
        goto err;
    memcpy(er->encoded, binbuf, binblen);
    *ret_er = er;
    return 1;
err:
    ECHConfigList_free(er);
    OPENSSL_free(er);
    if (te != NULL) {
        int teind;

        for (teind = 0; teind != rind; teind++)
            ECHConfig_free(&te[teind]);
        OPENSSL_free(te);
    }
    return rv;
}

/*
 * @brief decode the DNS name in a binary RRData
 * @param buf points to the buffer (in/out)
 * @param remaining points to the remaining buffer length (in/out)
 * @param dnsname returns the string form name on success
 * @return is 1 for success, error otherwise
 *
 * The encoding here is defined in
 * https://tools.ietf.org/html/rfc1035#section-3.1
 *
 * The input buffer pointer will be modified so it points to
 * just after the end of the DNS name encoding on output. (And
 * that's why it's an "unsigned char **" :-)
 */
static int local_decode_rdata_name(unsigned char **buf, size_t *remaining,
                                   char **dnsname)
{
    unsigned char *cp = NULL;
    size_t rem = 0;
    char *thename = NULL, *tp = NULL;
    unsigned char clen = 0; /* chunk len */

    if (buf == NULL || remaining == NULL || dnsname == NULL)
        return 0;
    rem = *remaining;
    thename = OPENSSL_malloc(TLSEXT_MAXLEN_host_name);
    if (thename == NULL)
        return 0;
    cp = *buf;
    tp = thename;
    clen = *cp++;
    if (clen == 0) {
        /* special case - return "." as name */
        thename[0] = '.';
        thename[1] = 0x00;
    }
    while (clen != 0) {
        if (clen > rem) {
            OPENSSL_free(thename);
            return 0;
        }
        if (((tp - thename) + clen) > TLSEXT_MAXLEN_host_name) {
            OPENSSL_free(thename);
            return 0;
        }
        memcpy(tp, cp, clen);
        tp += clen;
        *tp++ = '.';
        cp += clen;
        rem -= (clen + 1);
        clen = *cp++;
    }
    *buf = cp;
    *remaining = rem - 1;
    *dnsname = thename;
    return 1;
}

/*
 * @brief decode and flatten a binary encoded ECHConfigList
 * @param nechs_in in/out number of ECHConfig's in play
 * @param retech_in in/out array of SSL_ECH
 * @param binbuf binary encoded ECHConfigList (we hope)
 * @param binlen length of binbuf
 * @return 1 for success, 0 for error
 *
 * We may only get one ECHConfig, per list, but there can be more.
 * We want each element of the output SSL_ECH array to contain
 * exactly one ECHConfig so that a client could sensibly down
 * select to the one they prefer later, and so that we have the
 * specific encoded value of that ECHConfig for inclusion in the
 * HPKE info parameter when finally encrypting or decrypting an
 * inner ClientHello.
 */
static int ech_decode_and_flatten(int *nechs_in, SSL_ECH **retech_in,
                                  unsigned char *binbuf, size_t binlen)
{
    ECHConfigList *er = NULL;
    SSL_ECH *ts = NULL;
    int new_echs = 0;
    int leftover = 0;
    int cfgind;
    size_t nechs = *nechs_in;
    SSL_ECH *retech = *retech_in;

    if (ECHConfigList_from_binary(binbuf, binlen,
                                  &er, &new_echs, &leftover) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (new_echs == 0) {
        return 1;
    }
    ts = OPENSSL_realloc(retech, (nechs + er->nrecs) * sizeof(SSL_ECH));
    if (ts == NULL)
        goto err;
    retech = ts;
    for (cfgind = 0; cfgind != er->nrecs; cfgind++) {
        ECHConfig *ec = NULL;

        /*
         * inner and/or outer name and no_outer could have been set
         * via API as ECHConfigList values are being accumulated, e.g.
         * from a multivalued DNS RRset - that'd not be clever, or
         * common, but is possible, so we better copy such
         */
        if (nechs > 0 && retech[nechs - 1].inner_name != NULL) {
            retech[nechs + cfgind].inner_name =
                OPENSSL_strdup(retech[nechs - 1].inner_name);
            if (retech[nechs + cfgind].inner_name == NULL)
                goto err;
        } else {
            retech[nechs + cfgind].inner_name = NULL;
        }
        if (nechs > 0 && retech[nechs - 1].outer_name != NULL) {
            retech[nechs + cfgind].outer_name =
                OPENSSL_strdup(retech[nechs - 1].outer_name);
            if (retech[nechs + cfgind].outer_name == NULL)
                goto err;
        } else {
            retech[nechs + cfgind].outer_name = NULL;
        }
        if (nechs > 0) {
            retech[nechs + cfgind].no_outer = retech[nechs - 1].no_outer;
        } else {
            retech[nechs + cfgind].no_outer = 0;
        }
        /* next 3 fields are really only used when private key present */
        retech[nechs + cfgind].pemfname = NULL;
        retech[nechs + cfgind].loadtime = 0;
        retech[nechs + cfgind].keyshare = NULL;
        retech[nechs + cfgind].cfg =
            OPENSSL_malloc(sizeof(ECHConfigList));
        if (retech[nechs + cfgind].cfg == NULL)
            goto err;
        retech[nechs + cfgind].cfg->nrecs = 1;
        ec = OPENSSL_malloc(sizeof(ECHConfig));
        if (ec == NULL)
            goto err;
        *ec = er->recs[cfgind];
        /* avoid double free */
        memset(&er->recs[cfgind], 0, sizeof(ECHConfig));
        /* shallow copy is correct on next line */
        retech[nechs + cfgind].cfg->recs = ec;
        retech[nechs + cfgind].cfg->encoded_len =
            er->encoded_len;
        retech[nechs + cfgind].cfg->encoded =
            OPENSSL_malloc(er->encoded_len);
        if (retech[nechs + cfgind].cfg->encoded == NULL)
            goto err;
        memcpy(retech[nechs + cfgind].cfg->encoded,
               er->encoded, er->encoded_len);
    }
    *nechs_in += er->nrecs;
    *retech_in = retech;
    ECHConfigList_free(er);
    OPENSSL_free(er);
    return 1;
err:
    ECHConfigList_free(er);
    OPENSSL_free(er);
    return 0;
}

/*
 * @brief Decode/check the value from DNS (binary, base64 or ascii-hex encoded)
 * @param len length of the binary, base64 or ascii-hex encoded value from DNS
 * @param val is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param echs is a pointer to an array of decoded SSL_ECH
 * @return is 1 for success, error otherwise
 */
static int local_ech_add(int ekfmt, size_t len, const unsigned char *val,
                         int *num_echs, SSL_ECH **echs)
{
    int detfmt = OSSL_ECH_FMT_GUESS;
    int rv = 0;
    unsigned char *outbuf = NULL; /* sequence of ECHConfigList (binary) */
    size_t declen = 0; /* length of the above */
    char *ekptr = NULL;
    unsigned char *ekcpy = NULL;
    int nlens = 0;
    SSL_ECH *retechs = NULL;
    const unsigned char *ekval = val;
    size_t eklen = len;

    if (len == 0 || val == NULL || num_echs == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (eklen >= OSSL_ECH_MAX_ECHCONFIG_LEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    switch (ekfmt) {
    case OSSL_ECH_FMT_GUESS:
        rv = ech_guess_fmt(eklen, ekval, &detfmt);
        if (rv == 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        break;
    case OSSL_ECH_FMT_ASCIIHEX:
    case OSSL_ECH_FMT_B64TXT:
    case OSSL_ECH_FMT_BIN:
        detfmt = ekfmt;
        break;
        /* not supported here */
    case OSSL_ECH_FMT_HTTPSSVC:
    case OSSL_ECH_FMT_HTTPSSVC_NO_ECH:
    case OSSL_ECH_FMT_DIG_UNK:
    default:
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Do the various decodes on a copy of ekval */
    ekcpy = OPENSSL_malloc(eklen + 1);
    if (ekcpy == NULL)
        return 0;
    memcpy(ekcpy, ekval, eklen);
    ekcpy[eklen] = 0x00; /* a NUL in case of string value */
    ekptr = (char *)ekcpy;

    if (detfmt == OSSL_ECH_FMT_B64TXT) {
        int tdeclen = 0;

        if (strlen((char *)ekcpy) != eklen) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* need an int to get -1 return for failure case */
        tdeclen = ech_base64_decode(ekptr, eklen, &outbuf);
        if (tdeclen <= 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        declen = tdeclen;
    }
    if (detfmt == OSSL_ECH_FMT_ASCIIHEX) {
        int adr = 0;

        if (strlen((char *)ekcpy) != eklen) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        adr = ah_decode(eklen, ekptr, &declen, &outbuf);
        if (adr == 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (detfmt == OSSL_ECH_FMT_BIN) {
        /* just copy over the input to where we'd expect it */
        declen = eklen;
        outbuf = OPENSSL_malloc(declen);
        if (outbuf == NULL)
            goto err;
        memcpy(outbuf, ekptr, declen);
    }

    if (ech_decode_and_flatten(&nlens, &retechs, outbuf, declen) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (nlens > 0 && *num_echs == 0) {
        *num_echs = nlens;
        *echs = retechs;
    } else if (nlens > 0) {
        SSL_ECH *tech = NULL;

        tech = OPENSSL_realloc(*echs, (nlens + *num_echs) * sizeof(SSL_ECH));
        if (tech == NULL)
            goto err;
        memcpy(*echs + *num_echs * sizeof(SSL_ECH),
               retechs, nlens * sizeof(SSL_ECH));
        *num_echs += nlens;
    }

    OPENSSL_free(ekcpy);
    OPENSSL_free(outbuf);
    ekcpy = NULL;
    return 1;

err:
    OPENSSL_free(outbuf);
    OPENSSL_free(ekcpy);
    SSL_ECH_free(retechs);
    OPENSSL_free(retechs);
    return 0;
}
/*
 * @brief find ECH values inside various encodings
 * @param num_echs (ptr to) number of ECHConfig values found
 * @param echs (ptr to) array if ECHConfig values
 * @param len is the length of the encoding
 * @param val is the encoded value
 *
 * We support the various OSSL_ECH_FMT_* type formats
 */
static int ech_finder(int *num_echs, SSL_ECH **echs,
                      size_t len, const unsigned char *val)
{
    int rv = 0;
    int detfmt = OSSL_ECH_FMT_GUESS, origfmt;
    int multiline = 0;
    int linesdone = 0;
    unsigned char *lval = (unsigned char *)val;
    size_t llen = len;
    unsigned char *binbuf = NULL;
    size_t binlen = 0;
    SSL_ECH *retech = NULL;
    int nechs = 0;
    char *dnsname = NULL;
    int nonehere = 0;

    /* figue out what format we're dealing with */
    if (ech_guess_fmt(len, val, &detfmt) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return rv;
    }
    if (detfmt == OSSL_ECH_FMT_HTTPSSVC_NO_ECH) {
        return 1;
    }
    origfmt = detfmt;
    if (detfmt == OSSL_ECH_FMT_HTTPSSVC || detfmt == OSSL_ECH_FMT_DIG_UNK)
        multiline = 1;
    while (linesdone == 0) {
        /* if blank line, then skip */
        if (multiline == 1
            && strchr(OSSL_ECH_FMT_LINESEP, lval[0]) != NULL) {
            if (llen > 1) {
                lval++;
                llen -= 1;
                continue;
            } else {
                /* we're done */
                break;
            }
        }
        /* sanity check */
        if (llen >= OSSL_ECH_MAX_ECHCONFIG_LEN) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        detfmt = origfmt; /* restore format from before loop */
        /* if we already have a binary format then copy buffer */
        if (detfmt == OSSL_ECH_FMT_BIN
            || detfmt == OSSL_ECH_FMT_DNS_WIRE) {
            binbuf = OPENSSL_malloc(len);
            if (binbuf == NULL)
                goto err;
            memcpy(binbuf, val, len);
            binlen = len;
        }
        /* do decodes, some of these fall through to others */
        if (detfmt == OSSL_ECH_FMT_DIG_UNK) {
            /* decode asii-hex and fall through to DNS wire */
            char *tmp = NULL, *lstr = NULL;
            size_t ldiff = 0;

            /* chew up header and length, e.g. "\\# 232 " */
            if (llen < strlen(unknownformat_telltale) + 3) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            lstr = (char *)(lval + strlen(unknownformat_telltale));
            tmp = strstr(lstr, " ");
            if (tmp == NULL) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ldiff = tmp - (char *)lval;
            if (ldiff >= llen) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (ah_decode(llen - ldiff, (char *)lval + ldiff,
                          &binlen, &binbuf) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            detfmt = OSSL_ECH_FMT_DNS_WIRE;
        }
        if (detfmt == OSSL_ECH_FMT_ASCIIHEX) {
            /* AH decode and fall throught to DNS wire or binary */
            if (ah_decode(llen, (char *)lval, &binlen, &binbuf) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /*
             * ECHConfigList maybe can't be deterministically
             * distinguished from a DNS wire format HTTPS/SVCB
             * RR, but the former starts with a 2-octet length
             * whereas the latter starts with a 2-octet
             * SvcPriority field. The probability that the
             * priority is the same as the remaining length
             * for an otherwise valid DNS wire encoding that
             * contains an ECHConfigList should be small
             * enough to bear, but is non-zero. (I'd guess
             * well below 1/256, but that's still somewhat high
             * so this deserves more consideration.)
             * TODO: consider! We may be able to improve
             * on this once the final ECH RFC issues with
             * it's version set in stone - that version will
             * be octets 3 & 4 of the ECHConfigList.
             */
            if (binlen < 2) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if ((size_t)(binbuf[0] * 256 + binbuf[1]) == (binlen - 2))
                detfmt = OSSL_ECH_FMT_BIN;
            else
                detfmt = OSSL_ECH_FMT_DNS_WIRE;
        }

        if (detfmt == OSSL_ECH_FMT_DNS_WIRE) {
            /* decode DNS wire and fall through to binary */
            size_t remaining = binlen;
            unsigned char *cp = binbuf;
            unsigned char *ekval = NULL;
            size_t eklen = 0;
            uint16_t pcode = 0;
            uint16_t plen = 0;
            int done = 0;

            if (remaining <= 2) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            cp += 2;
            remaining -= 2;
            rv = local_decode_rdata_name(&cp, &remaining, &dnsname);
            if (rv != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            OPENSSL_free(dnsname);
            dnsname = NULL;
            while (done != 1 && remaining >= 4) {
                pcode = (*cp << 8) + (*(cp + 1));
                cp += 2;
                plen = (*cp << 8) + (*(cp + 1));
                cp += 2;
                remaining -= 4;
                if (pcode == OSSL_ECH_PCODE_ECH) {
                    eklen = (size_t)plen;
                    ekval = cp;
                    done = 1;
                }
                if (plen != 0 && plen <= remaining) {
                    cp += plen;
                    remaining -= plen;
                }
            }
            if (done == 0) {
                /* not an error just didn't find an ECH here */
                nonehere = 1;
            } else {
                unsigned char *tmp = NULL;

                tmp = OPENSSL_malloc(eklen);
                if (tmp == NULL) {
                    goto err;
                }
                memcpy(tmp, ekval, eklen);
                OPENSSL_free(binbuf);
                binbuf = tmp;
                binlen = eklen;
                detfmt = OSSL_ECH_FMT_BIN;
            }
        }

        if (detfmt == OSSL_ECH_FMT_HTTPSSVC) {
            /* find telltale and fall through to b64 */
            char *ekstart = NULL;

            ekstart = strstr((char *)lval, httpssvc_telltale1);
            if (ekstart == NULL) {
                nonehere = 1;
            } else {
                /* point ekstart at b64 encoded value */
                if (strlen(ekstart) <= strlen(httpssvc_telltale1)) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                ekstart += strlen(httpssvc_telltale1);
                llen = strcspn(ekstart, " \n");
                lval = (unsigned char *)ekstart;
                detfmt = OSSL_ECH_FMT_B64TXT;
            }
        }

        if (detfmt == OSSL_ECH_FMT_B64TXT) {
            /* b64 decode and fall through to binary */
            int tdeclen = 0;

            /* need an int to get -1 return for failure case */
            tdeclen = ech_base64_decode((char *)lval, llen, &binbuf);
            if (tdeclen <= 0) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            binlen = tdeclen;
            detfmt = OSSL_ECH_FMT_BIN;
        }

        if (nonehere != 1 && detfmt != OSSL_ECH_FMT_BIN) {
            /* error! */
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (nonehere == 0) {
            if (ech_decode_and_flatten(&nechs, &retech, binbuf, binlen) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        OPENSSL_free(binbuf);
        binbuf = NULL;

        /* check at end if more lines to do */
        if (multiline == 0) {
            linesdone = 1;
        } else {
            size_t linelen = 0;
            size_t slen = 0;

            /* is there a next line? only applies for char * formats */
            slen = strlen((char *)lval);
            linelen = strcspn((char *)lval, OSSL_ECH_FMT_LINESEP);
            if (linelen >= slen) {
                linesdone = 1;
            } else {
                lval = lval + linelen + 1;
                llen = slen - linelen - 1;
            }
        }
    }

    if (*num_echs == 0) {
        *num_echs = nechs;
        *echs = retech;
    } else {
        SSL_ECH *tech = NULL;

        tech = OPENSSL_realloc(*echs, (nechs + *num_echs) * sizeof(SSL_ECH));
        if (tech == NULL) {
            goto err;
        }
        memcpy(*echs + *num_echs * sizeof(SSL_ECH),
               retech, nechs * sizeof(SSL_ECH));
        *num_echs += nechs;
    }
    rv = 1;
err:
    OPENSSL_free(dnsname);
    OPENSSL_free(binbuf);
    if (rv == 0) {
        SSL_ECH_free_arr(retech, nechs);
        OPENSSL_free(retech);
    }
    return rv;
}

/*
 * @brief read ECHConfigList (with only 1 entry) and private key from a file
 * @param pemfile is the name of the file
 * @param ctx is the SSL context
 * @param inputIsFile is 1 if input a filename, 0 if a buffer
 * @param input is the filename or buffer
 * @param inlen is the length of input
 * @param sechs an (output) pointer to the SSL_ECH output
 * @return 1 for success, otherwise error
 *
 * The file content should look as below. Note that as github barfs
 * if I provide an actual private key in PEM format, I've reversed
 * the string PRIVATE in the PEM header and added a line-feed;-)
 *
 * -----BEGIN ETAVRIP KEY-----
 * MC4CAQAwBQYDK2VuBCIEIEiVgUq4FlrMNX3lH5osEm1yjqtVcQfeu3hY8VOFortE
 * -----END ETAVRIP KEY-----
 * -----BEGIN ECHCONFIG-----
 * AEP/CQBBAAtleGFtcGxlLmNvbQAkAB0AIF8i/TRompaA6Uoi1H3xqiqzq6IuUqFT
 * 2GNT4wzWmF6ACAABAABAAEAAAAA
 * -----END ECHCONFIG-----
 *
 * There are two sensible ways to call this, either supply just a
 * filename (and inputIsFile=1) or else provide a pesudo-filename,
 * a buffer and the buffer length with inputIsFile=0. The buffer
 * should have contents like the PEM strings above.
 *
 */
static int ech_readpemfile(SSL_CTX *ctx, int inputIsFile, const char *pemfile,
                           const unsigned char *input, size_t inlen,
                           SSL_ECH **sechs)
{
    BIO *pem_in = NULL;
    char *pname = NULL;
    char *pheader = NULL;
    unsigned char *pdata = NULL;
    long plen = 0;
    EVP_PKEY *priv = NULL;
    int num_echs = 0;

    if (ctx == NULL || sechs == NULL)
        return 0;
    switch (inputIsFile) {
    case 1:
        if (pemfile == NULL || strlen(pemfile) == 0)
            return 0;
        break;
    case 0:
        if (input == NULL || inlen == 0)
            return 0;
        break;
    default:
        return 0;
    }
    if (inputIsFile == 1) {
        pem_in = BIO_new(BIO_s_file());
        if (pem_in == NULL)
            goto err;
        if (BIO_read_filename(pem_in, pemfile) <= 0)
            goto err;
    } else {
        pem_in = BIO_new(BIO_s_mem());
        if (pem_in == NULL)
            goto err;
        if (BIO_write(pem_in, (void *)input, (int)inlen) <= 0)
            goto err;
    }
    /* Now check and parse inputs */
    if (PEM_read_bio_PrivateKey(pem_in, &priv, NULL, NULL) == 0)
        goto err;
    if (priv == NULL)
        goto err;
    if (PEM_read_bio(pem_in, &pname, &pheader, &pdata, &plen) <= 0)
        goto err;
    if (pname == NULL || strlen(pname) == 0)
        goto err;
    if (strncmp(PEM_STRING_ECHCONFIG, pname, strlen(pname)))
        goto err;
    OPENSSL_free(pname);
    pname = NULL;
    OPENSSL_free(pheader);
    pheader = NULL;
    if (plen >= OSSL_ECH_MAX_ECHCONFIG_LEN || plen < OSSL_ECH_MIN_ECHCONFIG_LEN)
        goto err;
    BIO_free(pem_in);
    pem_in = NULL;
    /* Now decode that ECHConfigList */
    if (local_ech_add(OSSL_ECH_FMT_GUESS, plen, pdata, &num_echs, sechs) != 1)
        goto err;
    (*sechs)->pemfname = OPENSSL_strdup(pemfile);
    (*sechs)->loadtime = time(0);
    (*sechs)->keyshare = priv;
    OPENSSL_free(pheader);
    OPENSSL_free(pname);
    OPENSSL_free(pdata);
    return 1;

err:
    EVP_PKEY_free(priv);
    OPENSSL_free(pheader);
    OPENSSL_free(pname);
    OPENSSL_free(pdata);
    BIO_free(pem_in);
    SSL_ECH_free(*sechs);
    OPENSSL_free(*sechs);
    return 0;
}

/*
 * @brief utility field-copy fnc used by ECHFDUP macro and ECHConfig_dup
 * @param old is the source buffer
 * @param len is the source buffer size
 * @return is NULL or the copied buffer
 *
 * Copy a field old->foo based on old->foo_len to new->foo
 * We allocate one extra octet in case the value is a
 * string and NUL that out.
 */
static void *ech_len_field_dup(void *old, unsigned int len)
{
    void *new = NULL;

    if (old == NULL || len == 0)
        return NULL;
    new = (void *)OPENSSL_malloc(len + 1);
    if (new == NULL)
        return NULL;
    memcpy(new, old, len);
    memset((unsigned char *)new + len, 0, 1);
    return new;
}

/*
 * @brief deep copy an ECHConfig
 * @param old is the one to copy
 * @param new is the (caller allocated) place to copy-to
 * @return 1 for sucess, other otherwise
 */
static int ECHConfig_dup(ECHConfig *old, ECHConfig *new)
{
    unsigned int i = 0;

    if (new == NULL || old == NULL)
        return 0;
    *new = *old; /* shallow copy, followed by deep copies */
    /* but before deep copy make sure we don't free twice */
    new->ciphersuites = NULL;
    new->exttypes = NULL;
    new->extlens = NULL;
    new->exts = NULL;
    ECHFDUP(pub, pub_len, unsigned char *);
    ECHFDUP(public_name, public_name_len, unsigned char *);
    new->config_id = old->config_id;
    ECHFDUP(encoding_start, encoding_length, unsigned char *);
    if (old->ciphersuites) {
        new->ciphersuites = OPENSSL_malloc(old->nsuites
                                           * sizeof(ech_ciphersuite_t));
        if (new->ciphersuites == NULL)
            goto err;
        memcpy(new->ciphersuites, old->ciphersuites,
               old->nsuites * sizeof(ech_ciphersuite_t));
    }
    if (old->nexts != 0) {
        new->exttypes = OPENSSL_malloc(old->nexts * sizeof(old->exttypes[0]));
        if (new->exttypes == NULL)
            goto err;
        memcpy(new->exttypes, old->exttypes,
               old->nexts * sizeof(old->exttypes[0]));
        new->extlens = OPENSSL_malloc(old->nexts * sizeof(old->extlens[0]));
        if (new->extlens == NULL)
            goto err;
        memcpy(new->extlens, old->extlens,
               old->nexts * sizeof(old->extlens[0]));
        new->exts = OPENSSL_zalloc(old->nexts * sizeof(old->exts[0]));
        if (new->exts == NULL)
            goto err;
    }
    for (i = 0; i != old->nexts; i++) {
        new->exts[i] = OPENSSL_malloc(old->extlens[i]);
        if (new->exts[i] == NULL)
            goto err;
        memcpy(new->exts[i], old->exts[i], old->extlens[i]);
    }
    return 1;
err:
    ECHConfig_free(new);
    return 0;
}

/*
 * @brief deep copy an ECHConfigList
 * @param old is the one to copy
 * @param new is the (caller allocated) place to copy-to
 * @return 1 for sucess, other otherwise
 */
static int ECHConfigList_dup(ECHConfigList *old, ECHConfigList *new)
{
    int i = 0;

    if (new == NULL || old == NULL)
        return 0;
    if (old->encoded_len != 0) {
        new->encoded = (unsigned char *)ech_len_field_dup((void *)old->encoded,
                                                          old->encoded_len);
        if (new->encoded == NULL)
            return 0;
        new->encoded_len = old->encoded_len;
    }
    new->recs = OPENSSL_malloc(old->nrecs * sizeof(ECHConfig));
    if (new->recs == NULL)
        return 0;
    new->nrecs = old->nrecs;
    memset(new->recs, 0, old->nrecs * sizeof(ECHConfig));
    for (i = 0; i != old->nrecs; i++)
        if (ECHConfig_dup(&old->recs[i], &new->recs[i]) != 1)
            return 0;
    return 1;
}

/*
 * @brief return a printable form of alpn
 * @param alpn is the buffer with alpns
 * @param len is the length of the above
 * @return buffer with string form (caller has to free)
 *
 * ALPNs are multi-valued, with lengths between, we
 * map that to a comma-sep list
 */
static char *alpn_print(unsigned char *alpn, size_t len)
{
    size_t ind = 0;
    char *vstr = NULL;

    if (alpn == NULL || len == 0)
        return NULL;
    if (len > OSSL_ECH_MAX_ALPNLEN)
        return NULL;
    vstr = OPENSSL_malloc(len + 1);
    if (vstr == NULL)
        return NULL;
    while (ind < len) {
        size_t vlen = alpn[ind];

        if (ind + vlen > (len - 1))
            return NULL;
        memcpy(&vstr[ind], &alpn[ind + 1], vlen);
        vstr[ind + vlen] = ',';
        ind += (vlen + 1);
    }
    vstr[len - 1] = '\0';
    return vstr;
}

/*
 * @brief produce a printable string form of an ECHConfigList
 * @param out is where we print
 * @param c is the ECHConfigList
 * @return 1 for good, 0 for fail
 */
static int ECHConfigList_print(BIO *out, ECHConfigList *c)
{
    int i;
    unsigned int j;

    if (out == NULL || c == NULL || c->recs == NULL)
        return 0;
    for (i = 0; i != c->nrecs; i++) {
        if (c->recs[i].version != OSSL_ECH_DRAFT_13_VERSION) {
            /* just note we don't support that one today */
            BIO_printf(out, "[Unsupported version (%04x)]", c->recs[i].version);
            continue;
        }
        /* version, config_id, public_name, and kem */
        BIO_printf(out, "[%04x,%02x,%s,%04x,[", c->recs[i].version,
                   c->recs[i].config_id, c->recs[i].public_name,
                   c->recs[i].kem_id);
        /* ciphersuites */
        for (j = 0; j != c->recs[i].nsuites; j++) {
            unsigned char *es = (unsigned char *)&c->recs[i].ciphersuites[j];
            uint16_t kdf_id = es[0] * 256 + es[1];
            uint16_t aead_id = es[2] * 256 + es[3];

            BIO_printf(out, "%04x,%04x", kdf_id, aead_id);
            if (j < (c->recs[i].nsuites - 1)) {
                BIO_printf(out, ",");
            }
        }
        BIO_printf(out, "],");
        /* public key */
        for (j = 0; j != c->recs[i].pub_len; j++)
            BIO_printf(out, "%02x", c->recs[i].pub[j]);
        /* max name length and (only) number of extensions */
        BIO_printf(out, ",%02x,%02x]", c->recs[i].maximum_name_length,
                   c->recs[i].nexts);
    }
    return 1;
}

/*
 * @brief make up HPKE "info" input as per spec
 * @param tc is the ECHconfig being used
 * @param info is a caller-allocated buffer for results
 * @param info_len is the buffer size on input, used-length on output
 * @return 1 for success, other otherwise
 */
static int ech_make_enc_info(ECHConfig *tc, unsigned char *info,
                             size_t *info_len)
{
    unsigned char *ip = info;

    if (tc == NULL || info == NULL || info_len == NULL)
        return 0;
    /*
     * note: we could use strlen() below but I guess sizeof is a litte
     * better - if using strlen() then we'd have a few "+ 1"'s below
     * as the sizeof is 1 bigger than the strlen
     */
    if (*info_len < (sizeof(OSSL_ECH_CONTEXT_STRING) + tc->encoding_length))
        return 0;
    memcpy(ip, OSSL_ECH_CONTEXT_STRING, sizeof(OSSL_ECH_CONTEXT_STRING) - 1);
    ip += sizeof(OSSL_ECH_CONTEXT_STRING) - 1;
    *ip++ = 0x00;
    memcpy(ip, tc->encoding_start, tc->encoding_length);
    *info_len = sizeof(OSSL_ECH_CONTEXT_STRING) + tc->encoding_length;
    return 1;
}

/*!
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
 *
 * Note: input here is untrusted!
 */
int ech_get_ch_offsets(SSL_CONNECTION *s, PACKET *pkt, size_t *sessid,
                       size_t *exts, size_t *echoffset, uint16_t *echtype,
                       int *inner, size_t *snioffset)
{
    const unsigned char *ch = NULL;
    size_t ch_len = 0;
    size_t genoffset = 0;
    size_t sessid_len = 0;
    size_t suiteslen = 0;
    size_t startofexts = 0;
    size_t extlens = 0;
    size_t legacy_compress_len; /* length of legacy_compression */
    const unsigned char *e_start = NULL;
    int extsremaining = 0;
    uint16_t etype = 0;
    size_t elen = 0;
# ifdef OSSL_ECH_SUPERVERBOSE
    size_t echlen = 0; /* length of ECH, including type & ECH-internal length */
    size_t snilen = 0;
# endif

    if (s == NULL || pkt == NULL || sessid == NULL || exts == NULL
        || echoffset == NULL || echtype == NULL || inner == NULL
        || snioffset == NULL)
        return 0;

    *sessid = 0;
    *exts = 0;
    *echoffset = 0;
    *echtype = TLSEXT_TYPE_ech_unknown;
    *snioffset = 0;
    ch_len = PACKET_remaining(pkt);
    if (PACKET_peek_bytes(pkt, &ch, ch_len) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* make sure we're at least tlsv1.2 */
    if (ch_len < 2) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* if we're not TLSv1.2+ then we can bail, but it's not an error */
    if (ch[0] * 256 + ch [1] != TLS1_2_VERSION)
        return 1;
    /*
     * We'll start genoffset at the start of the session ID, just
     * before the ciphersuites
     */
    genoffset = CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE; /* point to len sessid */
    if (ch_len <= genoffset) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    *sessid = genoffset;
    sessid_len = ch[genoffset];
    /*
     * sessid_len can be zero length in encoded inner CH but is normally 32
     * A different length could lead to an error elsewhere.
     */
    if (sessid_len != 0 && sessid_len != SSL_MAX_SSL_SESSION_ID_LENGTH) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    genoffset += (1 + sessid_len);
    if (ch_len <= (genoffset + 2)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    suiteslen = ch[genoffset] * 256 + ch[genoffset + 1];
    if ((genoffset + 2 + suiteslen + 2) > ch_len) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    legacy_compress_len = ch[genoffset + suiteslen + 2];
    /*
     * if compression is on, we're not TLSv1.3 and hence won't be doing
     * ECH, but that's not an error per-se
     */
    if (legacy_compress_len != 1)
        return 1;
    if (ch[genoffset + suiteslen + 2 + 1] != 0x00)
        return 1;

    startofexts = genoffset + 2 + suiteslen + 2; /* the 2 for the suites len */
    if (startofexts == ch_len)
        return 1; /* no extensions present, which is fine, but not for ECH */
    if (startofexts > ch_len) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    *exts = startofexts; /* set output */

    extlens = ch[startofexts] * 256 + ch[startofexts + 1];
    if (ch_len < (startofexts + 2 + extlens)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* find ECH if it's there */
    e_start = &ch[startofexts + 2];
    extsremaining = extlens - 2;
    while (extsremaining > 0 && (*echoffset == 0 || *snioffset == 0)) {
        /* 4 is for 2-octet type and 2-octet length */
        if (ch_len < (4 + (size_t)(e_start - ch))) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        etype = e_start[0] * 256 + e_start[1];
        elen = e_start[2] * 256 + e_start[3];
        if (etype == TLSEXT_TYPE_ech13) {
# ifdef OSSL_ECH_SUPERVERBOSE
            echlen = elen + 4; /* type and length included */
# endif
            if (ch_len < (5 + (size_t)(e_start - ch))) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            /* set outputs */
            *echtype = etype;
            *echoffset = (e_start - ch); /* set output */
            *inner = e_start[4];
        } else if (etype == TLSEXT_TYPE_server_name) {
# ifdef OSSL_ECH_SUPERVERBOSE
            snilen = elen + 4; /* type and length included */
# endif
            /* set output */
            *snioffset = (e_start - ch); /* set output */
        }
        e_start += (4 + elen);
        extsremaining -= (4 + elen);
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig CH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
    ech_pbuf("orig CH", (unsigned char *)ch, ch_len);
    ech_pbuf("orig CH session_id", (unsigned char *)ch + *sessid + 1,
             sessid_len);
    ech_pbuf("orig CH exts", (unsigned char *)ch + *exts, extlens);
    ech_pbuf("orig CH/ECH", (unsigned char *)ch + *echoffset, echlen);
    ech_pbuf("orig CH SNI", (unsigned char *)ch + *snioffset, snilen);
# endif
    return 1;
}

/*!
 * Given a SH (or HRR) find the offsets of the ECH (if any)
 * @param: sh is the SH buffer
 * @paramL sh_len is the length of the SH
 * @param: exts points to offset of extensions
 * @param: echoffset points to offset of ECH
 * @param: echtype points to the ext type of the ECH
 * @return 1 for success, other otherwise
 *
 * Offsets are returned to the type or length field in question.
 * Offsets are set to zero if relevant thing not found.
 *
 * Note: input here is untrusted!
 */
static int ech_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                              size_t *exts, size_t *echoffset,
                              uint16_t *echtype)
{
    size_t sessid_offset = 0;
    size_t sessid_len = 0;
    size_t startofexts = 0;
    size_t extlens = 0;
    const unsigned char *e_start = NULL;
    int extsremaining = 0;
    uint16_t etype = 0;
    size_t elen = 0;
# ifdef OSSL_ECH_SUPERVERBOSE
    size_t echlen = 0; /* length of ECH, including type & ECH-internal length */
# endif

    if (sh == NULL || sh_len == 0 || exts == NULL || echoffset == NULL
        || echtype == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* make sure we're at least tlsv1.2 */
    if (sh_len < 2) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* if we're not TLSv1.2+ then we can bail, but it's not an error */
    if (sh[0] * 256 + sh [1] != TLS1_2_VERSION)
        return 1;
    *exts = 0;
    *echoffset = 0;
    *echtype = TLSEXT_TYPE_ech_unknown;

    sessid_offset = CLIENT_VERSION_LEN /* version */
        + SSL3_RANDOM_SIZE             /* random */
        + 1;                           /* sess_id_len */
    if (sh_len <= sessid_offset) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    sessid_len = (size_t)sh[sessid_offset - 1];
    /*
     * If the session id isn't 32 octets long we might hit
     * problems later/elsewhere
     */
    if (sessid_len != SSL_MAX_SSL_SESSION_ID_LENGTH) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    startofexts = sessid_offset /* up to & incl. sessid_len */
        + sessid_len            /* sessid_len */
        + 2                     /* ciphersuite */
        + 1;                    /* legacy compression */
    if (sh_len < startofexts) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (sh_len == startofexts)
        return 1; /* no exts */
    *exts = startofexts;
    if (sh_len < (startofexts + 6)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0; /* needs at least len+one-ext */
    }
    extlens = sh[startofexts] * 256 + sh[startofexts + 1];
    if (sh_len < (startofexts + 2 + extlens)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* find ECH if it's there */
    e_start = &sh[startofexts + 2];
    extsremaining = extlens - 2;
    while (extsremaining > 0 && *echoffset == 0) {
        if (sh_len < (4 + (size_t)(e_start - sh))) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        etype = e_start[0] * 256 + e_start[1];
        elen = e_start[2] * 256 + e_start[3];
        if (etype == TLSEXT_TYPE_ech13) {
# ifdef OSSL_ECH_SUPERVERBOSE
            echlen = elen + 4; /* type and length included */
# endif
            *echtype = etype;
            *echoffset = (e_start - sh); /* set output */
        }
        e_start += (4 + elen);
        extsremaining -= (4 + elen);
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig SH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
    ech_pbuf("orig SH", (unsigned char *)sh, sh_len);
    ech_pbuf("orig SH session_id", (unsigned char *)sh + sessid_offset,
             sessid_len);
    ech_pbuf("orig SH exts", (unsigned char *)sh + *exts, extlens);
    ech_pbuf("orig SH/ECH ", (unsigned char *)sh + *echoffset, echlen);
# endif
    return 1;
}

/*
 * @brief After successful ECH decrypt, decode, decompress etc.
 * @param ssl is the SSL session
 * @param ob is the outer CH as a buffer
 * @param ob_len is the size of the above
 * @param outer_startofexts is the offset of exts in ob
 * @return 1 for success, error otherwise
 *
 * We need the outer CH as a buffer (ob, below) so we can
 * ECH-decompress.
 * The plaintext we start from is in encoded_innerch
 * and our final decoded, decompressed buffer will end up
 * in innerch (which'll then be further processed).
 * That further processing includes all existing decoding
 * checks so we should be fine wrt fuzzing without having
 * to make all checks here (e.g. we can assume that the
 * protocol version, NULL compression etc are correct here -
 * if not, those'll be caught later).
 * Note: there are a lot of literal values here, but it's
 * not clear that changing those to #define'd symbols will
 * help much - a change to the length of a type or from a
 * 2 octet length to longer would seem unlikely.
 *
 * Might be worth checking out how a PACKET/WPACKET
 * API based approach to this might look.
 */
static int ech_decode_inner(SSL_CONNECTION *s, const unsigned char *ob,
                            size_t ob_len, size_t outer_startofexts)
{
    size_t initial_decomp_len = 0;
    unsigned char *initial_decomp = NULL;
    size_t offset2sessid = 0;
    size_t suiteslen = 0;
    size_t startofexts = 0;
    int found = 0, remaining = 0;
    size_t oneextstart = 0;
    size_t beforeexts = 0;
    uint16_t etype = 0;
    size_t elen = 0;
    int n_outers = 0;
    uint8_t slen = 0;
    const unsigned char *oval_buf = NULL;
    int i = 0, j = 0, k = 0;
    int iind = 0;
    uint16_t outers[OSSL_ECH_OUTERS_MAX]; /* compressed extension types */
    size_t outer_sizes[OSSL_ECH_OUTERS_MAX]; /* sizes, same order as "outers" */
    int outer_offsets[OSSL_ECH_OUTERS_MAX]; /* offsets, same order "outers" */
    size_t tot_outer_lens = 0; /* total length of outers (incl. type+len+val) */
    const unsigned char *exts_start = NULL;
    size_t exts_len = 0;
    const unsigned char *ep = NULL;
    int found_outers = 0;
    size_t outer_exts_len = 0;
    unsigned char *final_decomp = NULL;
    size_t final_decomp_len = 0;
    size_t offset = 0;
    size_t initial_extslen = 0;
    size_t final_extslen = 0;
    uint16_t allexts[OSSL_ECH_ALLEXTS_MAX];

    if (s->ext.ech.encoded_innerch == NULL || ob == NULL || ob_len == 0
        || outer_startofexts == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * We'll try decode encoded_innerch into
     * innerch, modulo s->ext.outers
     * We use initial_decomp as an intermediate buffer
     *
     * As a reminder the CH is:
     *  struct {
     *    ProtocolVersion legacy_version = 0x0303;    TLS v1.2
     *    Random random;
     *    opaque legacy_session_id<0..32>;
     *    CipherSuite cipher_suites<2..2^16-2>;
     *    opaque legacy_compression_methods<1..2^8-1>;
     *    Extension extensions<8..2^16-1>;
     *  } ClientHello;
     */

    /*
     * add bytes for session ID and its length (1)
     * minus the length of the empty session ID (1)
     * that should be there already
     */
    initial_decomp_len = s->ext.ech.encoded_innerch_len;
    initial_decomp_len += s->tmp_session_id_len;
    initial_decomp = OPENSSL_malloc(initial_decomp_len);
    if (initial_decomp == NULL)
        return 0;
    /*
     * Jump over the ciphersuites and (MUST be NULL) compression to
     * the start of extensions
     */
    offset2sessid = CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE;
    if (s->ext.ech.encoded_innerch_len < (offset2sessid + 2)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    suiteslen = s->ext.ech.encoded_innerch[offset2sessid + 1] * 256
        + s->ext.ech.encoded_innerch[offset2sessid + 2];
    startofexts = offset2sessid + 1
        + s->tmp_session_id_len  /* skipping session id */
        + 2 + suiteslen          /* skipping suites */
        + 2;                     /* skipping NULL compression */
    if (startofexts >= initial_decomp_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    memcpy(initial_decomp, s->ext.ech.encoded_innerch, offset2sessid);
    initial_decomp[offset2sessid] =
        (unsigned char)(s->tmp_session_id_len & 0xff);
    memcpy(initial_decomp + offset2sessid + 1, s->tmp_session_id,
           s->tmp_session_id_len);
    memcpy(initial_decomp + offset2sessid + 1 + s->tmp_session_id_len,
           s->ext.ech.encoded_innerch + offset2sessid + 1,
           s->ext.ech.encoded_innerch_len - offset2sessid - 1);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("Inner CH (session-id-added but no decompression)",
             initial_decomp, initial_decomp_len);
    ech_pbuf("start of exts", &initial_decomp[startofexts],
             initial_decomp_len - startofexts);
# endif
    /* Now skip over exts until we do/don't see outers */
    found = 0;
    if ((startofexts + 2) >= initial_decomp_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    remaining = initial_decomp[startofexts] * 256
        + initial_decomp[startofexts + 1];
    /* 1st ext type, skip the overall exts len */
    beforeexts = oneextstart = startofexts + 2;
    etype = 0;
    elen = 0;

    if (startofexts + 2 + remaining > initial_decomp_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }

    while (found == 0 && remaining > 0) {
        if (oneextstart + 4 > initial_decomp_len) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        etype = initial_decomp[oneextstart] * 256
            + initial_decomp[oneextstart + 1];
        elen = initial_decomp[oneextstart + 2] * 256
            + initial_decomp[oneextstart + 3];
        if (oneextstart + 4 + elen > initial_decomp_len) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (etype == TLSEXT_TYPE_outer_extensions) {
            found = 1;
        } else {
            remaining -= (elen + 4);
            oneextstart += (elen + 4);
        }
    }

    if (found == 0) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "We had no compression\n");
        } OSSL_TRACE_END(TLS);
        /* We still need to add msg type & 3-octet length */
        final_decomp_len = initial_decomp_len + 4;
        final_decomp = OPENSSL_malloc(final_decomp_len);
        if (final_decomp == NULL)
            goto err;
        final_decomp[0] = SSL3_MT_CLIENT_HELLO;
        final_decomp[1] = (initial_decomp_len >> 16) % 256;
        final_decomp[2] = (initial_decomp_len >> 8) % 256;
        final_decomp[3] = initial_decomp_len % 256;
        memcpy(final_decomp + 4, initial_decomp, initial_decomp_len);
        /* handle HRR case where we (temporarily) store the old inner CH */
        if (s->ext.ech.innerch != NULL) {
            OPENSSL_free(s->ext.ech.innerch1);
            s->ext.ech.innerch1 = s->ext.ech.innerch;
            s->ext.ech.innerch1_len = s->ext.ech.innerch_len;
        }
        s->ext.ech.innerch = final_decomp;
        s->ext.ech.innerch_len = final_decomp_len;
        OPENSSL_free(initial_decomp);
        return 1;
    }
    /*
     * At this point, onextstart is the offset of the outer extensions in the
     * encoded_innerch
     *
     * As a reminder: the value of the extension here is a (redundant)
     * one-octet length and a set of two-octet extension types that are
     * to be copied from outer to inner (at this location)
     *
     * We impose an arbitrary max on the number of extensions we're willing
     * to copy from outer to inner. That just allows use to use stack
     * buffers, but also seems reasonable. As I type that's got a value
     * of 20.
     */
    n_outers = elen / 2;
    if (n_outers <= 0 || n_outers > OSSL_ECH_OUTERS_MAX) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (oneextstart + 4 >= initial_decomp_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    slen = initial_decomp[oneextstart + 4];
    if (oneextstart + 4 + slen > initial_decomp_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!ossl_assert(n_outers == slen / 2)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    oval_buf = &initial_decomp[oneextstart + 5];
    /* accumulate outer types */
    for (i = 0; i != n_outers; i++) {
        outers[i] = oval_buf[2 * i] * 256 + oval_buf[2 * i + 1];
        if (outers[i] == TLSEXT_TYPE_ech13) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "Can't de-compress ECH within an ECH\n");
            } OSSL_TRACE_END(TLS);
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
    }
    /* brute force check there are no duplicates in outers */
    for (i = 0; i != n_outers; i++) {
        for (j = 0; j != n_outers; j++) {
            if (outers[i] == outers[j] && i != j) {
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out, "Repeated outer (%d)\n", outers[i]);
                } OSSL_TRACE_END(TLS);
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                goto err;
            }
        }
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "We have %d outers compressed\n", n_outers);
    } OSSL_TRACE_END(TLS);
    /* Go through outer exts and mark what we need */
    exts_start = ob + outer_startofexts + 2;
    exts_len = ob_len - outer_startofexts - 2;
    remaining = exts_len;
    ep = exts_start;
    while (remaining > 0) {
        if ((size_t)((ep + 4) - ob) > ob_len) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        etype = *ep * 256 + *(ep + 1);
        elen = *(ep + 2) * 256 + *(ep + 3);
        if ((size_t)((ep + 4 + elen) - ob) > ob_len) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        for (iind = 0; iind < n_outers; iind++) {
            if (etype == outers[iind]) {
                outer_sizes[iind] = elen;
                outer_offsets[iind] = ep - exts_start;
                tot_outer_lens += (elen + 4);
                /*
                 * Note that this check depends on previously barfing on
                 * a single extension appearing twice
                 */
                found_outers++;
            }
        }
        remaining -= (elen + 4);
        ep += (elen + 4);
    }
    if (found_outers != n_outers) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,
                       "Error found outers (%d) not same as claimed (%d)\n",
                       found_outers, n_outers);
        } OSSL_TRACE_END(TLS);
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    /* Now almost-finally, package up the lot */
    outer_exts_len = 4 + 1 + 2 * n_outers;
    if (outer_exts_len >= (4 + initial_decomp_len + tot_outer_lens)) {
        /* that'd make final_decomp_len go zero/negative */
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    final_decomp_len = 4 /* the type and 3-octet length */
        + initial_decomp_len /* where we started */
        - outer_exts_len /* removing the size of the outers_extension */
        + tot_outer_lens; /* add back the length of spliced-in exts */
    final_decomp = OPENSSL_malloc(final_decomp_len);
    if (final_decomp == NULL)
        goto err;
    offset = oneextstart;
    final_decomp[0] = SSL3_MT_CLIENT_HELLO;
    final_decomp[1] = ((final_decomp_len - 4) >> 16) % 256;
    final_decomp[2] = ((final_decomp_len - 4) >> 8) % 256;
    final_decomp[3] = (final_decomp_len - 4) % 256;
    if (((offset + 4) >= final_decomp_len) || (offset > initial_decomp_len)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    memcpy(final_decomp + 4, initial_decomp, offset);
    offset += 4; /* the start up to the "outers"  */
    /* now splice in from the outer CH */
    for (iind = 0; iind != n_outers; iind++) {
        int ooffset = outer_offsets[iind] + 4;
        size_t osize = outer_sizes[iind];

        if ((offset + 4) >= final_decomp_len) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        final_decomp[offset] = (outers[iind] / 256) & 0xff;
        offset++;
        final_decomp[offset] = (outers[iind] % 256) & 0xff;
        offset++;
        final_decomp[offset] = (osize / 256) & 0xff;
        offset++;
        final_decomp[offset] = (osize % 256) & 0xff;
        offset++;
        if (((offset + osize) > final_decomp_len)
            || ((size_t)((exts_start + ooffset + osize) - ob) > ob_len)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        memcpy(final_decomp + offset, exts_start + ooffset, osize);
        offset += osize;
    }

    /* now copy over extensions from inner CH from after "outers" to end */
    if ((offset + initial_decomp_len - oneextstart - outer_exts_len)
        > final_decomp_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    memcpy(final_decomp + offset,
           initial_decomp + oneextstart + outer_exts_len,
           initial_decomp_len - oneextstart - outer_exts_len);
    /*
     * the +4 and +5 are because the final_decomp has the type+3-octet length
     * and startofexts is the offset within initial_decomp which doesn't have
     * those
     */
    if ((startofexts + 5) > final_decomp_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    initial_extslen = final_decomp[startofexts + 4] * 256
        + final_decomp[startofexts + 5];

    if ((initial_extslen + tot_outer_lens) < outer_exts_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    final_extslen = initial_extslen + tot_outer_lens - outer_exts_len;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "Initial extensions length: 0x%zx, "
                   "Final extensions length: 0x%zx\n",
                   initial_extslen, final_extslen);
    } OSSL_TRACE_END(TLS);
    /* the added 4 is for the type+3-octets len */
    final_decomp[startofexts + 4] = (final_extslen / 256) & 0xff;
    final_decomp[startofexts + 5] = final_extslen % 256;
    /*
     * check that we haven't ended up with more than one occurrence
     * of any extension type; 'till now - we've not checked that we
     * didn't have both a compressed-from-outer and duplicated-in-inner
     * extension type.
     */
    etype = 0;
    elen = 0;
    oneextstart = beforeexts + 4;
    remaining = final_decomp_len - beforeexts;
    i = 0;
    memset(allexts, 0, sizeof(allexts));
    /* accumulate all ext types used */
    while (oneextstart + 4 <= final_decomp_len && remaining > 0) {
        etype = final_decomp[oneextstart] * 256
            + final_decomp[oneextstart + 1];
        allexts[i++] = etype;
        if (i >= OSSL_ECH_ALLEXTS_MAX) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        elen = final_decomp[oneextstart + 2] * 256
            + final_decomp[oneextstart + 3];
        if (oneextstart + 4 + elen > final_decomp_len) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        remaining -= (elen + 4);
        oneextstart += (elen + 4);
    }
    if (oneextstart != final_decomp_len) {
        /* must be off by a few, that's bad */
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    /* brute force check for no repeats */
    for (j = 0; j != i; j++) {
        etype = allexts[j];
        for (k = j + 1; k != i; k++) {
            if (etype == allexts[k]) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                goto err;
            }
        }
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("final_decomp", final_decomp, final_decomp_len);
# endif
    /* handle HRR case where we (temporarily) store the old inner CH */
    if (s->ext.ech.innerch != NULL) {
        if (s->ext.ech.innerch1 != NULL)
            OPENSSL_free(s->ext.ech.innerch1);
        s->ext.ech.innerch1 = s->ext.ech.innerch;
        s->ext.ech.innerch1_len = s->ext.ech.innerch_len;
    }
    s->ext.ech.innerch = final_decomp;
    s->ext.ech.innerch_len = final_decomp_len;
    OPENSSL_free(initial_decomp);
    initial_decomp = NULL;
    return 1;
err:
    OPENSSL_free(initial_decomp);
    OPENSSL_free(final_decomp);
    return 0;
}

/*
 * @brief wrapper for hpke_dec just to save code repetition
 * @param s is the SSL session
 * @param ech is the selected ECHConfig
 * @param the_ech is the value sent by the client
 * @param aad_len is the length of the AAD to use
 * @param aad is the AAD to use
 * @param forhrr is 0 if not hrr, 1 if this is for 2nd CH
 * @param innerlen points to the size of the recovered plaintext
 * @return pointer to plaintext or NULL (if error)
 *
 * The plaintext returned is allocated here and must
 * be freed by the caller later.
 */
static unsigned char *hpke_decrypt_encch(SSL_CONNECTION *s, SSL_ECH *ech,
                                         OSSL_ECH_ENCCH *the_ech,
                                         size_t aad_len, unsigned char *aad,
                                         int forhrr, size_t *innerlen)
{
    size_t cipherlen = 0;
    unsigned char *cipher = NULL;
    size_t senderpublen = 0;
    unsigned char *senderpub = NULL;
    size_t clearlen = 0;
    unsigned char *clear = NULL;
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char info[SSL3_RT_MAX_PLAIN_LENGTH];
    size_t info_len = SSL3_RT_MAX_PLAIN_LENGTH;
    int rv = 0;
    OSSL_HPKE_CTX *hctx = NULL;
# ifdef OSSL_ECH_SUPERVERBOSE
    size_t publen = 0;
    unsigned char *pub = NULL;
# endif

    cipherlen = the_ech->payload_len;
    cipher = the_ech->payload;
    senderpublen = the_ech->enc_len;
    senderpub = the_ech->enc;
    hpke_suite.aead_id = the_ech->aead_id;
    hpke_suite.kdf_id = the_ech->kdf_id;
    clearlen = cipherlen; /* small overestimate */
    clear = OPENSSL_malloc(clearlen);
    if (clear == NULL)
        return NULL;
    /*
     * We only support one ECHConfig for now on the server side
     * The calling code looks after matching the ECH.config_id
     * and/or trial decryption.
     */
    hpke_suite.kem_id = ech->cfg->recs[0].kem_id;
# ifdef OSSL_ECH_SUPERVERBOSE
    publen = ech->cfg->recs[0].pub_len;
    pub = ech->cfg->recs[0].pub;
    ech_pbuf("aad", aad, aad_len);
    ech_pbuf("my local pub", pub, publen);
    ech_pbuf("senderpub", senderpub, senderpublen);
    ech_pbuf("cipher", cipher, cipherlen);
# endif
    if (ech_make_enc_info(ech->cfg->recs, info, &info_len) != 1) {
        OPENSSL_free(clear);
        return NULL;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("info", info, info_len);
# endif
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,
                   "hpke_dec suite: kem: %04x, kdf: %04x, aead: %04x\n",
                   hpke_suite.kem_id, hpke_suite.kdf_id, hpke_suite.aead_id);
    } OSSL_TRACE_END(TLS);
    /*
     * We may generate externally visible OpenSSL errors
     * if decryption fails (which is normal) but we'll
     * ignore those as we might be dealing with a GREASEd
     * ECH. The way to do that is to consume all
     * errors generated internally during the attempt
     * to decrypt. Failing to clear those errors can
     * trigger an application to consider TLS session
     * establishment has failed when someone just
     * GREASEd or used an old key.  But to do that we
     * first need to know there are no other errors in
     * the queue that we ought not consume as the application
     * really should know about those.
     */
    if (ERR_peek_error() != 0) {
        OPENSSL_free(clear);
        return NULL;
    }
    /* Use OSSL_HPKE_* APIs */
    hctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite, OSSL_HPKE_ROLE_RECEIVER,
                             NULL, NULL);
    if (hctx == NULL)
        goto clearerrs;
    rv = OSSL_HPKE_decap(hctx, senderpub, senderpublen, ech->keyshare,
                         info, info_len);
    if (rv != 1)
        goto clearerrs;
    if (forhrr == 1) {
        rv = OSSL_HPKE_CTX_set_seq(hctx, 1);
        if (rv != 1) {
            /* don't clear this error - GREASE can't cause it */
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto end;
        }
    }
    rv = OSSL_HPKE_open(hctx, clear, &clearlen, aad, aad_len,
                        cipher, cipherlen);
    if (rv != 1)
        goto clearerrs;

clearerrs:
    /*
     * clear errors from failed decryption as per the above
     * we do this before checking the result from hpke_dec
     * then return, or carry on
     */
    while (ERR_get_error() != 0);
end:
    OSSL_HPKE_CTX_free(hctx);
    if (rv != 1) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "HPKE decryption failed somehow");
        } OSSL_TRACE_END(TLS);
        OPENSSL_free(clear);
        return NULL;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("padded clear", clear, clearlen);
# endif
    /* we need to remove possible (actually, v. likely) padding */
    *innerlen = clearlen;
    if (ech->cfg->recs[0].version == OSSL_ECH_DRAFT_13_VERSION) {
        /* draft-13 pads after the encoded CH with zeros */
        size_t extsoffset = 0;
        size_t extslen = 0;
        size_t ch_len = 0;
        size_t startofsessid = 0;
        size_t echoffset = 0; /* offset of start of ECH within CH */
        uint16_t echtype = TLSEXT_TYPE_ech_unknown; /* type of ECH seen */
        size_t outersnioffset = 0; /* offset to SNI in outer */
        int innerflag = -1;
        PACKET innerchpkt;

        if (PACKET_buf_init(&innerchpkt, clear, clearlen) != 1) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            OPENSSL_free(clear);
            return NULL;
        }
        rv = ech_get_ch_offsets(s, &innerchpkt, &startofsessid, &extsoffset,
                                &echoffset, &echtype, &innerflag,
                                &outersnioffset);
        if (rv != 1) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            OPENSSL_free(clear);
            return NULL;
        }
        /* odd form of check below just for emphasis */
        if ((extsoffset + 1) > clearlen) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            OPENSSL_free(clear);
            return NULL;
        }
        extslen = (unsigned char)(clear[extsoffset]) * 256
            + (unsigned char)(clear[extsoffset + 1]);
        ch_len = extsoffset + 2 + extslen;
        /* the check below protects us from bogus data */
        if (ch_len > clearlen) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            OPENSSL_free(clear);
            return NULL;
        }
        /*
         * The RFC calls for that padding to be all zeros. I'm not so
         * keen on that being a good idea to enforce, so we'll make it
         * easy to not do so (but check by default)
         */
# define CHECKZEROS
# ifdef CHECKZEROS
        {
            size_t zind = 0;
            size_t nonzeros = 0;
            size_t zeros = 0;

            if (*innerlen < ch_len) {
                OPENSSL_free(clear);
                return NULL;
            }
            for (zind = ch_len; zind != *innerlen; zind++) {
                if (clear[zind] == 0x00) {
                    zeros++;
                } else {
                    nonzeros++;
                }
            }
            if (nonzeros > 0 || zeros != (*innerlen - ch_len)) {
                OPENSSL_free(clear);
                return NULL;
            }
        }
# endif
        *innerlen = ch_len;
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("unpadded clear", clear, *innerlen);
# endif
        return clear;
    }
    OPENSSL_free(clear);
    return NULL;
}

/*
 * @brief figure out how much padding for cleartext (on client)
 * @param s is the SSL connection
 * @param tc is the chosen ECHConfig
 * @return is the overall length to use including padding or zero on error
 *
 * "Recommended" inner SNI padding scheme as per spec
 * (section 6.1.3)
 * Might remove the mnl stuff later - overall message padding seems
 * better really, BUT... we might want to keep this if others (e.g.
 * browsers) do it so as to not stand out compared to them.
 *
 * The "+ 9" constant below is from the specifiation and is the
 * expansion comparing a string length to an encoded SNI extension.
 * Same is true of the 31/32 formula below.
 *
 * Note that the AEAD tag will be added later, so if we e.g. have
 * a padded cleartext of 128 octets, the ciphertext will be 144
 * octets.
 */
static size_t ech_calc_padding(SSL_CONNECTION *s, ECHConfig *tc)
{
    int length_of_padding = 0;
    int length_with_snipadding = 0;
    int length_with_padding = 0;
    int innersnipadding = 0;
    size_t mnl = 0;
    size_t clear_len = 0;
    size_t isnilen = 0;

    if (s == NULL || tc == NULL)
        return 0;
    mnl = tc->maximum_name_length;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: ECHConfig had max name len of %zu\n", mnl);
    } OSSL_TRACE_END(TLS);
    if (mnl != 0) {
        /* do weirder padding if SNI present in inner */
        if (s->ext.hostname != NULL) {
            isnilen = strlen(s->ext.hostname) + 9;
            innersnipadding = mnl - isnilen;
        } else {
            innersnipadding = mnl + 9;
        }
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "EAAE: innersnipadding of %d\n",
                       innersnipadding);
        } OSSL_TRACE_END(TLS);
        if (innersnipadding < 0) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "EAAE: innersnipadding zero'd\n");
            } OSSL_TRACE_END(TLS);
            innersnipadding = 0;
        }
    }
    /* draft-13 padding is after the encoded client hello */
    length_with_snipadding = innersnipadding
        + s->ext.ech.encoded_innerch_len;
    length_of_padding = 31 - ((length_with_snipadding - 1) % 32);
    length_with_padding = s->ext.ech.encoded_innerch_len
        + length_of_padding + innersnipadding;
    /*
     * Finally - make sure final result is longer than padding target
     * and a multiple of our padding increment.
     * This is a local addition - might take it out if it makes
     * us stick out; or if we take out the above more complicated
     * scheme, we may only need this in the end (and that'd maybe
     * be better overall:-)
     */
    if (length_with_padding % OSSL_ECH_PADDING_INCREMENT)
        length_with_padding += OSSL_ECH_PADDING_INCREMENT
            - (length_with_padding % OSSL_ECH_PADDING_INCREMENT);
    while (length_with_padding < OSSL_ECH_PADDING_TARGET)
        length_with_padding += OSSL_ECH_PADDING_INCREMENT;
    clear_len = length_with_padding;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: padding: mnl: %zu, lws: %d "
                   "lop: %d, lwp: %d, clear_len: %zu, orig: %zu\n",
                   mnl, length_with_snipadding, length_of_padding,
                   length_with_padding, clear_len,
                   s->ext.ech.encoded_innerch_len);
    } OSSL_TRACE_END(TLS);
    return clear_len;
}

/* SECTION: Non-public functions used elsewhere in the library */

# ifdef OSSL_ECH_SUPERVERBOSE
/*
 * @brief ascii-hex print a buffer nicely for debug/interop purposes
 * @param msg pre-pend to trace lines
 * @param buf points to the buffer to print
 * @param blen is the length of buffer to print
 */
void ech_pbuf(const char *msg, const unsigned char *buf, const size_t blen)
{
    OSSL_TRACE_BEGIN(TLS) {
        if (msg == NULL) {
            BIO_printf(trc_out, "msg is NULL\n");
        } else if (buf == NULL || blen == 0) {
            BIO_printf(trc_out, "%s: buf is %p\n", msg, (void *)buf);
            BIO_printf(trc_out, "%s: blen is %lu\n", msg, (unsigned long)blen);
        } else {
            size_t i;

            BIO_printf(trc_out, "%s (%lu):\n    ", msg, (unsigned long)blen);
            for (i = 0; i < blen; i++) {
                if ((i != 0) && (i % 16 == 0))
                    BIO_printf(trc_out, "\n    ");
                BIO_printf(trc_out, "%02x:", (unsigned)(buf[i]));
            }
            BIO_printf(trc_out, "\n");
        }
    } OSSL_TRACE_END(TLS);
    return;
}

/*
 * @brief trace out transcript
 * @param msg pre-pend to trace lines
 * @param s is the SSL connection
 */
void ech_ptranscript(const char *msg, SSL_CONNECTION *s)
{
    size_t hdatalen = 0;
    unsigned char *hdata = NULL;
    unsigned char ddata[1000];
    size_t ddatalen;

    if (s == NULL)
        return;
    hdatalen = BIO_get_mem_data(s->s3.handshake_buffer, &hdata);
    ech_pbuf(msg, hdata, hdatalen);
    if (s->s3.handshake_dgst != NULL) {
        if (ssl_handshake_hash(s, ddata, 1000, &ddatalen) == 0) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "ssl_handshake_hash failed\n");
            } OSSL_TRACE_END(TLS);
        }
        ech_pbuf(msg, ddata, ddatalen);
    } else {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "handshake_dgst is NULL\n");
        } OSSL_TRACE_END(TLS);
    }
    return;
}
# endif

/*
 * @brief Free an ECHConfig structure's internals
 * @param tbf is the thing to be freed
 */
void ECHConfig_free(ECHConfig *tbf)
{
    unsigned int i = 0;

    if (tbf == NULL)
        return;
    OPENSSL_free(tbf->public_name);
    OPENSSL_free(tbf->pub);
    OPENSSL_free(tbf->ciphersuites);
    OPENSSL_free(tbf->exttypes);
    OPENSSL_free(tbf->extlens);
    for (i = 0; i != tbf->nexts; i++)
        OPENSSL_free(tbf->exts[i]);
    OPENSSL_free(tbf->exts);
    OPENSSL_free(tbf->encoding_start);
    memset(tbf, 0, sizeof(ECHConfig));
    return;
}

/*
 * @brief Free an ECHConfigList structure's internals
 * @param tbf is the thing to be free'd
 */
void ECHConfigList_free(ECHConfigList *tbf)
{
    int i;

    if (tbf == NULL)
        return;
    OPENSSL_free(tbf->encoded);
    for (i = 0; i != tbf->nrecs; i++)
        ECHConfig_free(&tbf->recs[i]);
    OPENSSL_free(tbf->recs);
    memset(tbf, 0, sizeof(ECHConfigList));
    return;
}

/*
 * @brief free an OSSL_ECH_ENCCH
 * @param tbf is the thing to be free'd
 */
void OSSL_ECH_ENCCH_free(OSSL_ECH_ENCCH *tbf)
{
    if (tbf == NULL)
        return;
    OPENSSL_free(tbf->enc);
    OPENSSL_free(tbf->payload);
    return;
}

/*
 * @brief free an SSL_ECH
 * @param tbf is the thing to be free'd
 *
 * Free everything within an SSL_ECH. Note that the
 * caller has to free the top level SSL_ECH, IOW the
 * pattern here is:
 *      SSL_ECH_free(tbf);
 *      OPENSSL_free(tbf);
 */
void SSL_ECH_free(SSL_ECH *tbf)
{
    if (tbf == NULL)
        return;
    if (tbf->cfg != NULL) {
        ECHConfigList_free(tbf->cfg);
        OPENSSL_free(tbf->cfg);
    }
    OPENSSL_free(tbf->inner_name);
    OPENSSL_free(tbf->outer_name);
    OPENSSL_free(tbf->pemfname);
    EVP_PKEY_free(tbf->keyshare);
    memset(tbf, 0, sizeof(SSL_ECH));
    return;
}

/*
 * @brief Free an array of SSL_ECH
 * @param tbf is the thing to be free'd
 * @param elems is the number of elements to free
 */
void SSL_ECH_free_arr(SSL_ECH *tbf, size_t elems)
{
    size_t i;

    if (tbf == NULL)
        return;
    for (i = 0; i != elems; i++)
        SSL_ECH_free(&tbf[i]);
    return;
}

/**
 * @brief print info about the ECH-status of an SSL connection
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param ssl is an SSL session strucutre
 * @param selector OSSL_ECH_SELECT_ALL or just one of the SSL_ECH values
 * @return 1 for success, anything else for failure
 */
int SSL_ech_print(BIO *out, SSL *ssl, int selector)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

# ifdef OSSL_ECH_SUPERVERBOSE
    BIO_printf(out, "SSL_ech_print\n");
    BIO_printf(out, "s=%p\n", (void *)s);
# endif
    BIO_printf(out, "ech_attempted=%d\n", s->ext.ech.attempted);
    BIO_printf(out, "ech_attempted_type=0x%4x\n",
               s->ext.ech.attempted_type);
    if (s->ext.ech.attempted_cid == TLSEXT_TYPE_ech_config_id_unset)
        BIO_printf(out, "ech_atttempted_cid is unset\n");
    else
        BIO_printf(out, "ech_atttempted_cid=0x%02x\n",
                   s->ext.ech.attempted_cid);
    BIO_printf(out, "ech_done=%d\n", s->ext.ech.done);
    BIO_printf(out, "ech_grease=%d\n", s->ext.ech.grease);
# ifdef OSSL_ECH_SUPERVERBOSE
    BIO_printf(out, "HRR=%d\n", s->hello_retry_request);
    BIO_printf(out, "hrr_depth=%d\n", s->ext.ech.hrr_depth);
    BIO_printf(out, "ech_returned=%p\n",
               (void *)s->ext.ech.returned);
# endif
    BIO_printf(out, "ech_returned_len=%ld\n",
               (long)s->ext.ech.returned_len);
    BIO_printf(out, "ech_backend=%d\n", s->ext.ech.backend);
    BIO_printf(out, "ech_success=%d\n", s->ext.ech.success);
    if (s->ext.ech.cfgs != NULL) {
        int i = 0;

        if (s->ext.ech.ncfgs == 1) {
            BIO_printf(out, "1 ECHConfig value loaded\n");
        } else {
            BIO_printf(out, "%d ECHConfig values loaded\n",
                       s->ext.ech.ncfgs);
        }
        for (i = 0; i != s->ext.ech.ncfgs; i++) {
            if (selector == OSSL_ECH_SELECT_ALL || selector == i) {
                BIO_printf(out, "cfg(%d): ", i);
                if (ECHConfigList_print(out, s->ext.ech.cfgs[i].cfg) == 1)
                    BIO_printf(out, "\n");
                else
                    BIO_printf(out, "NULL (huh?)\n");
                if (s->ext.ech.cfgs[i].keyshare != NULL) {
# define OSSL_ECH_TIME_STR_LEN 32 /* apparently 26 is all we need */
                    struct tm local, *local_p = NULL;
                    char lstr[OSSL_ECH_TIME_STR_LEN];
# if defined(OPENSSL_SYS_WINDOWS)
                    errno_t grv;
# endif

# if !defined(OPENSSL_SYS_WINDOWS)
                    local_p = gmtime_r(&s->ext.ech.cfgs[i].loadtime, &local);
                    if (local_p != &local) {
                        strcpy(lstr, "sometime");
                    } else {
                        int srv = strftime(lstr, OSSL_ECH_TIME_STR_LEN,
                                           "%c", &local);

                        if (srv == 0)
                            strcpy(lstr, "sometime");
                    }
# else
                    grv = gmtime_s(&local, &s->ext.ech.cfgs[i].loadtime);
                    if (grv != 0) {
                        strcpy(lstr, "sometime");
                    } else {
                        int srv = strftime(lstr, OSSL_ECH_TIME_STR_LEN,
                                           "%c", &local);

                        if (srv == 0)
                            strcpy(lstr, "sometime");
                    }
# endif
                    BIO_printf(out, "\tpriv=%s, loaded at %s\n",
                               s->ext.ech.cfgs[i].pemfname, lstr);
                }
            }
        }
    } else {
        BIO_printf(out, "cfg=NONE\n");
    }
    if (s->ext.ech.returned) {
        size_t i = 0;

        BIO_printf(out, "ret=");
        for (i = 0; i != s->ext.ech.returned_len; i++) {
            if ((i != 0) && (i % 16 == 0))
                BIO_printf(out, "\n    ");
            BIO_printf(out, "%02x:", (unsigned)(s->ext.ech.returned[i]));
        }
        BIO_printf(out, "\n");
    }
    return 1;
}

/*
 * @brief deep-copy an array of SSL_ECH
 * @param orig is the input array of SSL_ECH to be deep-copied
 * @param nech is the number of elements in the array
 * @param selector means dup all (if OSSL_ECH_SELECT_ALL==-1) or just the
 *        one nominated
 * @return a deep-copy same-sized array or NULL if errors occur
 *
 * This is needed to handle the SSL_CTX->SSL factory model.
 */
SSL_ECH *SSL_ECH_dup(SSL_ECH *orig, size_t nech, int selector)
{
    SSL_ECH *new_se = NULL;
    int min_ind = 0;
    int max_ind = nech;
    int i = 0;

    if ((selector != OSSL_ECH_SELECT_ALL) && selector < 0)
        return NULL;
    if (selector != OSSL_ECH_SELECT_ALL) {
        if ((unsigned int)selector >= nech)
            goto err;
        min_ind = selector;
        max_ind = selector + 1;
    }
    new_se = OPENSSL_malloc((max_ind - min_ind) * sizeof(SSL_ECH));
    if (new_se == NULL)
        goto err;
    memset(new_se, 0, (max_ind - min_ind) * sizeof(SSL_ECH));
    for (i = min_ind; i != max_ind; i++) {
        new_se[i].cfg = OPENSSL_malloc(sizeof(ECHConfigList));
        if (new_se[i].cfg == NULL)
            goto err;
        if (ECHConfigList_dup(orig[i].cfg, new_se[i].cfg) != 1)
            goto err;
        if (orig[i].inner_name != NULL) {
            new_se[i].inner_name = OPENSSL_strdup(orig[i].inner_name);
            if (new_se[i].inner_name == NULL)
                goto err;
        }
        if (orig[i].outer_name != NULL) {
            new_se[i].outer_name = OPENSSL_strdup(orig[i].outer_name);
            if (new_se[i].outer_name == NULL)
                goto err;
        }
        new_se[i].no_outer = orig[i].no_outer;
        if (orig[i].pemfname != NULL) {
            new_se[i].pemfname = OPENSSL_strdup(orig[i].pemfname);
            if (new_se[i].pemfname == NULL)
                goto err;
        }
        new_se[i].loadtime = orig[i].loadtime;
        if (orig[i].keyshare != NULL) {
            new_se[i].keyshare = orig[i].keyshare;
            EVP_PKEY_up_ref(orig[i].keyshare);
        }
    }
    return new_se;
err:
    SSL_ECH_free(new_se);
    OPENSSL_free(new_se);
    return NULL;
}

/**
 * @brief say if extension at index i in ext_defs is to be ECH compressed
 * @param ind is the index of this extension in ext_defs (and ech_ext_handling)
 * @return 1 if this one is to be compressed, 0 if not, -1 for error
 */
int ech_2bcompressed(int ind)
{
    int nexts = OSSL_NELEM(ech_ext_handling);

    if (ind < 0 || ind >= nexts)
        return -1;
    return ech_ext_handling[ind].handling == OSSL_ECH_HANDLING_COMPRESS;
}

/**
 * @brief repeat extension from inner in outer and handle compression
 * @param s is the SSL connection
 * @param pkt is the packet containing extensions
 * @param depth is 0 for outer CH, 1 for inner
 * @return 0: error, 1: copied existing and done, 2: ignore existing
 */
int ech_same_ext(SSL_CONNECTION *s, WPACKET *pkt, int depth)
{
    unsigned int type = 0;
    unsigned int nexts = 0;
    int tind = 0;

# undef DUPEMALL
# ifdef DUPEMALL
    /*
     * DUPEMALL was handy for testing.
     * Setting this means no compression at all.
     */
    return OSSL_ECH_SAME_EXT_CONTINUE;
# endif

    if (s == NULL || s->ext.ech.cfgs == NULL)
        return OSSL_ECH_SAME_EXT_CONTINUE; /* nothing to do */
    type = s->ext.ech.etype;
    nexts = OSSL_NELEM(ech_ext_handling);
    tind = ech_map_ext_type_to_ind(type);
    /* If this index'd extension won't be compressed, we're done */
    if (tind == -1)
        return OSSL_ECH_SAME_EXT_ERR;
    if (tind >= (int)nexts)
        return OSSL_ECH_SAME_EXT_ERR;
    if (depth == 1) {
        /* inner CH - just note compression as configured */
        if (ech_ext_handling[tind].handling != OSSL_ECH_HANDLING_COMPRESS)
            return OSSL_ECH_SAME_EXT_CONTINUE;
        /* mark this one to be "compressed" */
        if (s->ext.ech.n_outer_only >= OSSL_ECH_OUTERS_MAX)
            return OSSL_ECH_SAME_EXT_ERR;
        s->ext.ech.outer_only[s->ext.ech.n_outer_only] =
            ech_ext_handling[tind].type;
        s->ext.ech.n_outer_only++;
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "ech_same_ext: Marking (type %d, ind %d "
                       "tot-comp %d) for compression\n", s->ext.ech.etype, tind,
                       (int) s->ext.ech.n_outer_only);
        } OSSL_TRACE_END(TLS);
        return OSSL_ECH_SAME_EXT_CONTINUE;
    }

    /* Copy value from inner to outer, or indicate a new value needed */
    if (depth == 0) {
        if (s->clienthello == NULL || pkt == NULL)
            return OSSL_ECH_SAME_EXT_ERR;
        if (ech_ext_handling[tind].handling == OSSL_ECH_HANDLING_CALL_BOTH)
            return OSSL_ECH_SAME_EXT_CONTINUE;
        else
            return ech_copy_inner2outer(s, type, pkt);
    }
    /* just in case - shouldn't happen */
    return OSSL_ECH_SAME_EXT_ERR;
}

/**
 * @brief check if we're using the same/different key shares
 * @return 1 if same key share in inner and outer, 0 othewise
 */
int ech_same_key_share(void)
{
    return ech_ext_handling[TLSEXT_IDX_key_share].handling
        != OSSL_ECH_HANDLING_CALL_BOTH;
}

/**
 * @brief After "normal" 1st pass CH is done, fix encoding as needed
 * @param s is the SSL connection
 * @return 1 for success, error otherwise
 *
 * This will make up the ClientHelloInner and EncodedClientHelloInner buffers
 */
int ech_encode_inner(SSL_CONNECTION *s)
{
    unsigned char *innerch_full = NULL;
    WPACKET inner; /* "fake" pkt for inner */
    BUF_MEM *inner_mem = NULL;
    int mt = SSL3_MT_CLIENT_HELLO;
    RAW_EXTENSION *raws = NULL;
    size_t nraws = 0;
    size_t ind = 0;
    size_t innerinnerlen = 0;
    size_t builtins = ech_num_builtins();

    /* basic checks */
    if (s == NULL || s->ext.ech.cfgs == NULL)
        return 0;

    /*
     * encode innerch into encoded_innerch, and handle ECH-compression
     *
     * As a reminder the CH is:
     *  struct {
     *    ProtocolVersion legacy_version = 0x0303;    TLS v1.2
     *    Random random;
     *    opaque legacy_session_id<0..32>;
     *    CipherSuite cipher_suites<2..2^16-2>;
     *    opaque legacy_compression_methods<1..2^8-1>;
     *    Extension extensions<8..2^16-1>;
     *  } ClientHello;
     */

    if ((inner_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(inner_mem, SSL3_RT_MAX_PLAIN_LENGTH)
        || !WPACKET_init(&inner, inner_mem)
        || !ssl_set_handshake_header(s, &inner, mt)
        /* Add ver/rnd/sess-id/suites to buffer */
        || !WPACKET_put_bytes_u16(&inner, s->client_version)
        || !WPACKET_memcpy(&inner, s->ext.ech.client_random, SSL3_RANDOM_SIZE)
        /* Session ID is forced to zero in the encoded inner */
        || !WPACKET_start_sub_packet_u8(&inner)
        || !WPACKET_close(&inner)
        /* Ciphers supported */
        || !WPACKET_start_sub_packet_u16(&inner)
        || !ssl_cipher_list_to_bytes(s, SSL_get_ciphers(&s->ssl), &inner)
        || !WPACKET_close(&inner)
        /* COMPRESSION */
        || !WPACKET_start_sub_packet_u8(&inner)
        /* Add the NULL compression method */
        || !WPACKET_put_bytes_u8(&inner, 0) || !WPACKET_close(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Now handle extensions */
    if (!WPACKET_start_sub_packet_u16(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Grab a pointer to the already constructed extensions */
    raws = s->clienthello->pre_proc_exts;
    nraws = s->clienthello->pre_proc_exts_len;
    if (nraws < builtins) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*  We put ECH-compressed stuff first (if any), because we can */
    if (s->ext.ech.n_outer_only > 0) {
        if (!WPACKET_put_bytes_u16(&inner, TLSEXT_TYPE_outer_extensions)
            || !WPACKET_put_bytes_u16(&inner, 2 * s->ext.ech.n_outer_only + 1)
            /* redundant encoding of more-or-less the same thing */
            || !WPACKET_put_bytes_u8(&inner, 2 * s->ext.ech.n_outer_only)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* add the types for each of the compressed extensions now */
        for (ind = 0; ind != s->ext.ech.n_outer_only; ind++) {
            if (!WPACKET_put_bytes_u16(&inner, s->ext.ech.outer_only[ind])) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }

    /* now copy the rest, as "proper" exts, into encoded inner */
    for (ind = 0; ind < builtins; ind++) {
        if (raws[ind].present == 0)
            continue;
        if (ech_2bcompressed(ind) == 1)
            continue;
        if (PACKET_data(&raws[ind].data) != NULL) {
            if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                || !WPACKET_sub_memcpy_u16(&inner, PACKET_data(&raws[ind].data),
                                           PACKET_remaining(&raws[ind].data))) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            /* empty extension */
            if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                || !WPACKET_put_bytes_u16(&inner, 0)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    /* close the exts sub packet */
    if (!WPACKET_close(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* close the inner CH */
    if (!WPACKET_close(&inner))
        goto err;
    /* Set pointer/len for inner CH */
    if (!WPACKET_get_length(&inner, &innerinnerlen))
        goto err;
    innerch_full = OPENSSL_malloc(innerinnerlen);
    if (innerch_full == NULL)
        goto err;
    /* Finally ditch the type and 3-octet length */
    memcpy(innerch_full, inner_mem->data + 4, innerinnerlen - 4);
    s->ext.ech.encoded_innerch = innerch_full;
    s->ext.ech.encoded_innerch_len = innerinnerlen - 4;
    /* and clean up */
    WPACKET_cleanup(&inner);
    BUF_MEM_free(inner_mem);
    inner_mem = NULL;
    return 1;
err:
    WPACKET_cleanup(&inner);
    BUF_MEM_free(inner_mem);
    return 0;
}

/*
 * @brief reset the handshake buffer for transcript after ECH is good
 * @param ssl is the session
 * @param buf is the data to put into the transcript (usually inner CH)
 * @param blen is the length of buf
 * @return 1 for success
 */
int ech_reset_hs_buffer(SSL_CONNECTION *s, const unsigned char *buf,
                        size_t blen)
{
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "Adding this to transcript: RESET!\n");
    } OSSL_TRACE_END(TLS);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("Adding this to transcript", buf, blen);
# endif

    if (s->s3.handshake_buffer != NULL) {
        (void)BIO_set_close(s->s3.handshake_buffer, BIO_CLOSE);
        BIO_free(s->s3.handshake_buffer);
        s->s3.handshake_buffer = NULL;
    }
    EVP_MD_CTX_free(s->s3.handshake_dgst);
    s->s3.handshake_dgst = NULL;
    s->s3.handshake_buffer = BIO_new(BIO_s_mem());
    if (s->s3.handshake_buffer == NULL) {
        return 0;
    }
    if (buf != NULL || blen > 0) {
        /* providing nothing at all is a real use (mid-HRR) */
        BIO_write(s->s3.handshake_buffer, (void *)buf, (int)blen);
    }
    return 1;
}

/*
 * @brief ECH accept_confirmation calculation
 * @param s is the SSL inner context
 * @oaram for_hrr is 1 if this is for an HRR, otherwise for SH
 * @param ac is (a caller allocated) 8 octet buffer
 * @param shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * @param shlen is the length of the SH buf
 * @return: 1 for success, 0 otherwise
 *
 * This is a magic value in the ServerHello.random lower 8 octets
 * that is used to signal that the inner worked.
 *
 * In draft-13:
 *
 * accept_confirmation = HKDF-Expand-Label(
 *         HKDF-Extract(0, ClientHelloInner.random),
 *         "ech accept confirmation",
 *         transcript_ech_conf,
 *         8)
 *
 * transcript_ech_conf = ClientHelloInner..ServerHello
 *         with last 8 octets of ServerHello.random==0x00
 *
 * and with differences due to HRR
 *
 * We can re-factor this some more (e.g. make one call for
 * SH offsets) but we'll hold on that a bit 'till we get to
 * refactoring transcripts generally.
 */
int ech_calc_ech_confirm(SSL_CONNECTION *s, int for_hrr,
                         unsigned char *acbuf,
                         const unsigned char *shbuf,
                         const size_t shlen)
{
    unsigned char *tbuf = NULL; /* local transcript buffer */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t tlen = 0;
    unsigned char *chbuf = NULL;
    size_t chlen = 0;
    size_t shoffset = 6 + 24; /* offset to magic bits in SH.random in shbuf */
    const EVP_MD *md = NULL;
    const char *label = NULL;
    size_t labellen = 0;
    unsigned int hashlen = 0;
    unsigned char hashval[EVP_MAX_MD_SIZE];
    unsigned char hoval[EVP_MAX_MD_SIZE];
    unsigned char zeros[EVP_MAX_MD_SIZE];
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char digestedCH[4 + EVP_MAX_MD_SIZE];
    size_t digestedCH_len = 0;
    unsigned char *longtrans = NULL;
    unsigned char *conf_loc = NULL;
    unsigned char *p = NULL;

    memset(digestedCH, 0, 4 + EVP_MAX_MD_SIZE);
    md = ssl_handshake_md(s);
    if (md == NULL) {
        /*
         * this does happen, on clients at least, might be better to set
         * the h/s md earlier perhaps rather than the rigmarole below
         */
        int rv;
        size_t extoffset = 0;
        size_t echoffset = 0;
        uint16_t echtype;
        size_t cipheroffset = 0;
        /* fallback to one from the chosen ciphersuite */
        const SSL_CIPHER *c = NULL;
        const unsigned char *cipherchars = NULL;

        if (s->server == 1) {
            /*
             * Not sure if this server-specific code is ever run.
             * Doesn't seem hit even with HRR.
             */
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "server finding MD from SH\n");
            } OSSL_TRACE_END(TLS);
            rv = ech_get_sh_offsets(shbuf + 4, shlen - 4, &extoffset,
                                    &echoffset, &echtype);
            if (rv != 1) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (extoffset < 3) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            cipheroffset = extoffset - 3;
            cipherchars = &shbuf[cipheroffset];
        } else {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "client finding MD from SH\n");
            } OSSL_TRACE_END(TLS);
            rv = ech_get_sh_offsets(shbuf, shlen, &extoffset, &echoffset,
                                    &echtype);
            if (rv != 1) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (extoffset < 3) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            cipheroffset = extoffset - 3;
            cipherchars = &shbuf[cipheroffset];
        }
        c = ssl_get_cipher_by_char(s, cipherchars, 0);
        md = ssl_md(s->ssl.ctx, c->algorithm2);
        if (md == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    hashlen = EVP_MD_size(md);
    if (hashlen > EVP_MAX_MD_SIZE) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (for_hrr == 0 && s->hello_retry_request == SSL_HRR_NONE) {
        chbuf = s->ext.ech.innerch;
        chlen = s->ext.ech.innerch_len;
    } else if (for_hrr == 0 && (s->hello_retry_request == SSL_HRR_PENDING ||
                                s->hello_retry_request == SSL_HRR_COMPLETE)) {
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("calc conf : innerch1", s->ext.ech.innerch1,
                 s->ext.ech.innerch1_len);
# endif
        /*
         * make up mad odd transcript manually, for now: that's
         * hashed-inner-CH1, then (non-hashed) HRR and inner-CH2
         */
        if (EVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVP_DigestUpdate(ctx, s->ext.ech.innerch1,
                                s->ext.ech.innerch1_len) <= 0
            || EVP_DigestFinal_ex(ctx, digestedCH + 4, &hashlen) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        digestedCH[0] = SSL3_MT_MESSAGE_HASH;
        digestedCH[1] = (hashlen >> 16) & 0xff;
        digestedCH[2] = (hashlen >> 8) & 0xff;
        digestedCH[3] = hashlen & 0xff;
        digestedCH_len = hashlen + 4;

# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("calc conf : kepthrr", s->ext.ech.kepthrr,
                 s->ext.ech.kepthrr_len);
# endif
        chlen = digestedCH_len + 4 + s->ext.ech.kepthrr_len
            + s->ext.ech.innerch_len;
        longtrans = OPENSSL_malloc(chlen);
        if (longtrans == NULL)
            goto err;
        memcpy(longtrans, digestedCH, digestedCH_len);
        if (s->server == 0) {
            longtrans[digestedCH_len] = SSL3_MT_SERVER_HELLO;
            longtrans[digestedCH_len + 1] =
                (s->ext.ech.kepthrr_len >> 16) & 0xff;
            longtrans[digestedCH_len + 2] =
                (s->ext.ech.kepthrr_len >> 8) & 0xff;
            longtrans[digestedCH_len + 3] = s->ext.ech.kepthrr_len & 0xff;
            memcpy(longtrans + digestedCH_len + 4,
                   s->ext.ech.kepthrr, s->ext.ech.kepthrr_len);
            memcpy(longtrans + digestedCH_len + 4 + s->ext.ech.kepthrr_len,
                   s->ext.ech.innerch, s->ext.ech.innerch_len);
        } else {
            chlen -= 4;
            memcpy(longtrans + digestedCH_len, s->ext.ech.kepthrr,
                   s->ext.ech.kepthrr_len);
            memcpy(longtrans + digestedCH_len + s->ext.ech.kepthrr_len,
                   s->ext.ech.innerch, s->ext.ech.innerch_len);
        }
        chbuf = longtrans;
    } else {
        /* stash HRR for later */
        s->ext.ech.kepthrr = OPENSSL_malloc(shlen);
        if (s->ext.ech.kepthrr == NULL)
            goto err;
        memcpy(s->ext.ech.kepthrr, shbuf, shlen);
        if (s->server != 0) {
            s->ext.ech.kepthrr[1] = ((shlen - 4) >> 16) & 0xff;
            s->ext.ech.kepthrr[2] = ((shlen - 4) >> 8) & 0xff;
            s->ext.ech.kepthrr[3] = (shlen - 4) & 0xff;
        }
        s->ext.ech.kepthrr_len = shlen;
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("calc conf : kepthrr", s->ext.ech.kepthrr,
                 s->ext.ech.kepthrr_len);
# endif
        if (EVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVP_DigestUpdate(ctx, s->ext.ech.innerch,
                                s->ext.ech.innerch_len) <= 0
            || EVP_DigestFinal_ex(ctx, digestedCH + 4, &hashlen) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        digestedCH[0] = SSL3_MT_MESSAGE_HASH;
        digestedCH[1] = (hashlen >> 16) & 0xff;
        digestedCH[2] = (hashlen >> 8) & 0xff;
        digestedCH[3] = hashlen & 0xff;
        digestedCH_len = hashlen + 4;
        chbuf = digestedCH;
        chlen = hashlen + 4;
    }

# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("calc conf : digested innerch", digestedCH, digestedCH_len);
    ech_pbuf("calc conf : innerch", s->ext.ech.innerch, s->ext.ech.innerch_len);
    ech_pbuf("calc conf : SH", shbuf, shlen);
# endif
    if (s->server == 1) {
        tlen = chlen + shlen;
    } else {
        /* need to add type + 3-octet length for client */
        tlen = chlen + shlen + 4;
    }
    tbuf = OPENSSL_malloc(tlen);
    if (tbuf == NULL)
        goto err;
    memcpy(tbuf, chbuf, chlen);

    /*
     * For some reason the internal 3-length of the shbuf is
     * wrong at this point. We'll fix it so, but in tbuf and
     * not in the actual shbuf, just in case that breaks some
     * other thing.
     */
    if (s->server == 1) {
        memcpy(tbuf + chlen, shbuf, shlen);
        tbuf[chlen + 1] = ((shlen - 4) >> 16) & 0xff;
        tbuf[chlen + 2] = ((shlen - 4) >> 8) & 0xff;
        tbuf[chlen + 3] = (shlen - 4) & 0xff;
    } else {
        /* need to add type + 3-octet length for client */
        tbuf[chlen] = SSL3_MT_SERVER_HELLO;
        tbuf[chlen + 1] = (shlen >> 16) & 0xff;
        tbuf[chlen + 2] = (shlen >> 8) & 0xff;
        tbuf[chlen + 3] = shlen & 0xff;
        memcpy(tbuf + chlen + 4, shbuf, shlen);
    }

    if (for_hrr == 0) {
        /* zap magic octets at fixed place for SH */
        conf_loc = tbuf + chlen + shoffset;
        memset(conf_loc, 0, 8);
    } else {
        if (s->server == 1) {
            /* we get to say where we put ECH:-) */
            conf_loc = tbuf + tlen - 8;
            memset(conf_loc, 0, 8);
        } else {
            int rv;
            size_t extoffset = 0;
            size_t echoffset = 0;
            uint16_t echtype;

            rv = ech_get_sh_offsets(shbuf, shlen, &extoffset, &echoffset,
                                    &echtype);
            if (rv != 1) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (echoffset == 0 || extoffset == 0 || echtype == 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (tlen < (chlen + 4 + echoffset + 4 + 8)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            conf_loc = tbuf + chlen + 4 + echoffset + 4;
            memset(conf_loc, 0, 8);
        }
    }

# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("calc conf : tbuf", tbuf, tlen);
# endif
    /* Next, zap the magic bits and do the keyed hashing */
    if (for_hrr == 1) {
        label = OSSL_ECH_HRR_CONFIRM_STRING;
    } else {
        label = OSSL_ECH_ACCEPT_CONFIRM_STRING;
    }
    labellen = strlen(label);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("calc conf : label", (unsigned char *)label, labellen);
# endif
    hashlen = EVP_MD_size(md);
    if (EVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVP_DigestUpdate(ctx, tbuf, tlen) <= 0
            || EVP_DigestFinal_ex(ctx, hashval, &hashlen) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("calc conf : hashval", hashval, hashlen);
# endif

    if (s->ext.ech.attempted_type == OSSL_ECH_DRAFT_13_VERSION) {
        unsigned char notsecret[EVP_MAX_MD_SIZE];
        size_t retlen = 0;

        memset(zeros, 0, EVP_MAX_MD_SIZE);
        /*
         * We still don't have an hkdf-extract that's exposed by
         * libcrypto
         */
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!pctx) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_derive_init(pctx) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_hkdf_mode(pctx,
                                   EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* pick correct client_random */
        if (s->server)
            p = s->s3.client_random;
        else
            p = s->ext.ech.client_random;
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("calc conf : client_random", p, SSL3_RANDOM_SIZE);
# endif
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, p, SSL3_RANDOM_SIZE) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, zeros, hashlen) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* get the right size set first - new in latest upstream */
        if (EVP_PKEY_derive(pctx, NULL, &retlen) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (hashlen != retlen) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_derive(pctx, notsecret, &retlen) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;

# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("calc conf : notsecret", notsecret, hashlen);
# endif
        if (hashlen < 8) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (!tls13_hkdf_expand(s, md, notsecret,
                               (const unsigned char *)label, labellen,
                               hashval, hashlen,
                               hoval, 8, 1)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    /* Finally, set the output */
    memcpy(acbuf, hoval, 8);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("calc conf : result", acbuf, 8);
# endif
    if (s->hello_retry_request == SSL_HRR_NONE && s->ext.ech.backend != 0)
        ech_reset_hs_buffer(s, s->ext.ech.innerch, s->ext.ech.innerch_len);

    if (s->hello_retry_request == SSL_HRR_NONE && s->ext.ech.backend == 0)
        ech_reset_hs_buffer(s, s->ext.ech.innerch, s->ext.ech.innerch_len);

    if (for_hrr == 1) {
        /* whack confirm value into stored version of hrr */
        memcpy(s->ext.ech.kepthrr + s->ext.ech.kepthrr_len - 8, acbuf, 8);
    }
    /* whack result back into tbuf */
    memcpy(conf_loc, acbuf, 8);
    if (s->hello_retry_request == SSL_HRR_COMPLETE) {
        ech_reset_hs_buffer(s, tbuf, tlen - shlen);
    }

    OPENSSL_free(tbuf);
    tbuf = NULL;
    EVP_MD_CTX_free(ctx);
    ctx = NULL;
# ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        if (SSL_ech_print(trc_out, &s->ssl, OSSL_ECH_SELECT_ALL) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } OSSL_TRACE_END(TLS);
# endif
    OPENSSL_free(longtrans);
    return 1;

err:
    OPENSSL_free(longtrans);
    OPENSSL_free(tbuf);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_CTX_free(pctx);
    return 0;
}

/*
 * @brief Swap the inner and outer
 * @param s is the SSL session to swap about
 * @return 0 for error, 1 for success
 *
 * The only reason to make this a function is because it's
 * likely very brittle - if we need any other fields to be
 * handled specially (e.g. because of some so far untested
 * combination of extensions), then this may fail, so good
 * to keep things in one place as we find that out.
 */
int ech_swaperoo(SSL_CONNECTION *s)
{
    unsigned char *curr_buf = NULL;
    size_t curr_buflen = 0;
    unsigned char *new_buf = NULL;
    size_t new_buflen = 0;
    size_t outer_chlen = 0;
    size_t other_octets = 0;

# ifdef OSSL_ECH_SUPERVERBOSE
    ech_ptranscript("ech_swaperoo, b4", s);
# endif

    /* Make some checks */
    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* un-stash inner key share */
    if (s->ext.ech.tmp_pkey == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_PKEY_free(s->s3.tmp.pkey);
    s->s3.tmp.pkey = s->ext.ech.tmp_pkey;
    s->s3.group_id = s->ext.ech.group_id;
    s->ext.ech.tmp_pkey = NULL;

    /*
     * When not doing HRR...
     * Fix up the transcript to reflect the inner CH
     * If there's a cilent hello at the start of the buffer, then
     * it's likely that's the outer CH and we want to replace that
     * with the inner. We need to be careful that there could be a
     * server hello following and can't lose that.
     * I don't think the outer client hello can be anwhere except
     * at the start of the buffer.
     *
     * For HRR... we'll try leave it alone as (I think)
     * the HRR processing code has already fixed up the
     * buffer.
     */
    if (s->hello_retry_request == 0) {
        curr_buflen = BIO_get_mem_data(s->s3.handshake_buffer,
                                       &curr_buf);
        if (curr_buflen > 4 && curr_buf[0] == SSL3_MT_CLIENT_HELLO) {
            /* It's a client hello, presumably the outer */
            outer_chlen = 1 + curr_buf[1] * 256 * 256
                + curr_buf[2] * 256 + curr_buf[3];
            if (outer_chlen > curr_buflen) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            other_octets = curr_buflen - outer_chlen;
            if (other_octets > 0) {
                new_buflen = s->ext.ech.innerch_len + other_octets;
                new_buf = OPENSSL_malloc(new_buflen);
                if (new_buf == NULL)
                    return 0;
                if (s->ext.ech.innerch != NULL) /* asan check added */
                    memcpy(new_buf, s->ext.ech.innerch,
                           s->ext.ech.innerch_len);
                memcpy(new_buf + s->ext.ech.innerch_len,
                       &curr_buf[outer_chlen], other_octets);
            } else {
                new_buf = s->ext.ech.innerch;
                new_buflen = s->ext.ech.innerch_len;
            }
        } else {
            new_buf = s->ext.ech.innerch;
            new_buflen = s->ext.ech.innerch_len;
        }
        /*
         * And now reset the handshake transcript to our buffer
         * Note ssl3_finish_mac isn't that great a name - that one just
         * adds to the transcript but doesn't actually "finish" anything
         */
        if (ssl3_init_finished_mac(s) == 0) {
            if (other_octets > 0) {
                OPENSSL_free(new_buf);
            }
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (ssl3_finish_mac(s, new_buf, new_buflen) == 0) {
            if (other_octets > 0) {
                OPENSSL_free(new_buf);
            }
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (other_octets > 0) {
            OPENSSL_free(new_buf);
        }
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_ptranscript("ech_swaperoo, after", s);
# endif
    /*
     * Finally! Declare victory - in both contexts.
     * The outer's ech_attempted will have been set already
     * but not the rest of 'em.
     */
    s->ext.ech.attempted = 1;
    s->ext.ech.success = 1;
    s->ext.ech.done = 1;
    s->ext.ech.grease = OSSL_ECH_NOT_GREASE;

    /* call ECH callback */
    if (s->ext.ech.cfgs != NULL && s->ext.ech.done == 1
        && s->hello_retry_request != SSL_HRR_PENDING
        && s->ext.ech.cb != NULL) {
        char pstr[OSSL_ECH_PBUF_SIZE + 1];
        BIO *biom = BIO_new(BIO_s_mem());
        unsigned int cbrv = 0;

        memset(pstr, 0, OSSL_ECH_PBUF_SIZE + 1);
        SSL_ech_print(biom, &s->ssl, OSSL_ECH_SELECT_ALL);
        BIO_read(biom, pstr, OSSL_ECH_PBUF_SIZE);
        cbrv = s->ext.ech.cb(&s->ssl, pstr);
        BIO_free(biom);
        if (cbrv != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    return 1;
}

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
int ech_send_grease(SSL_CONNECTION *s, WPACKET *pkt)
{
    OSSL_HPKE_SUITE hpke_suite_in = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE *hpke_suite_in_p = NULL;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    size_t cid_len = 1;
    unsigned char cid;
    size_t senderpub_len = OSSL_ECH_MAX_GREASE_PUB;
    unsigned char senderpub[OSSL_ECH_MAX_GREASE_PUB];
    size_t cipher_len = OSSL_ECH_DEF_CIPHER_LEN_SMALL;
    size_t cipher_len_jitter = OSSL_ECH_DEF_CIPHER_LEN_JITTER;
    unsigned char cipher[OSSL_ECH_MAX_GREASE_CT];
    /* stuff for copying to ech_sent */
    unsigned char *pp = WPACKET_get_curr(pkt);
    size_t pp_at_start = 0;
    size_t pp_at_end = 0;

    if (s == NULL || s->ssl.ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ech_same_key_share() == 0)
        cipher_len = OSSL_ECH_DEF_CIPHER_LEN_LARGE;
    WPACKET_get_total_written(pkt, &pp_at_start);
    /* generate a random (1 octet) client id */
    if (RAND_bytes_ex(s->ssl.ctx->libctx, &cid, cid_len,
                      RAND_DRBG_STRENGTH) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    s->ext.ech.attempted_cid = cid;
    /*
     * if adding jitter, we adjust cipher length by some random
     * number between +/- cipher_len_jitter
     */
    if (cipher_len_jitter != 0) {
        cipher_len_jitter = cipher_len_jitter % OSSL_ECH_MAX_CIPHER_LEN_JITTER;
        if (cipher_len < cipher_len_jitter) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        cipher_len -= cipher_len_jitter;
        /* the cid is random enough */
        cipher_len += 2 * (cid % cipher_len_jitter);
    }
    if (s->ext.ech.grease_suite != NULL) {
        if (OSSL_HPKE_str2suite(s->ext.ech.grease_suite, &hpke_suite_in) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        hpke_suite_in_p = &hpke_suite_in;
    }
    if (OSSL_HPKE_get_grease_value(s->ssl.ctx->libctx, NULL,
                                   hpke_suite_in_p, &hpke_suite,
                                   senderpub, &senderpub_len,
                                   cipher, cipher_len) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (s->ext.ech.attempted_type == OSSL_ECH_DRAFT_13_VERSION) {
        if (!WPACKET_put_bytes_u16(pkt, s->ext.ech.attempted_type)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, OSSL_ECH_OUTER_CH_TYPE)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
            || !WPACKET_memcpy(pkt, &cid, cid_len)
            || !WPACKET_sub_memcpy_u16(pkt, senderpub, senderpub_len)
            || !WPACKET_sub_memcpy_u16(pkt, cipher, cipher_len)
            || !WPACKET_close(pkt)
            ) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* record the ECH sent so we can re-tx same if we hit an HRR */
    OPENSSL_free(s->ext.ech.sent);
    WPACKET_get_total_written(pkt, &pp_at_end);
    s->ext.ech.sent_len = pp_at_end - pp_at_start;
    s->ext.ech.sent = OPENSSL_malloc(s->ext.ech.sent_len);
    if (s->ext.ech.sent == NULL)
        return 0;
    memcpy(s->ext.ech.sent, pp, s->ext.ech.sent_len);
    s->ext.ech.grease = OSSL_ECH_IS_GREASE;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "ECH - sending DRAFT-13 GREASE\n");
    } OSSL_TRACE_END(TLS);
    return 1;
}

/*
 * @brief pick an ECHConfig to use
 * @param s is the SSL connection
 * @param tc is the ECHConfig to use (if found)
 * @param suite is the HPKE suite to use (if found)
 *
 * Search through the ECHConfigList for one that's a best
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
                          OSSL_HPKE_SUITE *suite)
{
    int namematch = 0;
    int suitematch = 0;
    int cind = 0;
    unsigned int csuite = 0;
    ECHConfig *ltc = NULL;
    ECHConfigList *cfgs = NULL;
    unsigned char *es = NULL;
    char *hn = NULL;
    unsigned int hnlen = 0;

    if (s == NULL || s->ext.ech.cfgs == NULL || tc == NULL || suite == NULL)
        return 0;
    cfgs = s->ext.ech.cfgs->cfg;
    if (cfgs == NULL || cfgs->nrecs == 0) {
        return 0;
    }
    /* allow API-set pref to override */
    hn = s->ext.ech.cfgs->outer_name;
    hnlen = (hn == NULL ? 0 : strlen(hn));
    if (hnlen == 0) {
        /* fallback to outer hostname, if set */
        hn = s->ext.ech.outer_hostname;
        hnlen = (hn == NULL ? 0 : strlen(hn));
    }
    for (cind = 0;
         cind != cfgs->nrecs && suitematch == 0 && namematch == 0;
         cind++) {
        ltc = &cfgs->recs[cind];
        if (ltc->version != OSSL_ECH_DRAFT_13_VERSION)
            continue;
        namematch = 0;
        if (hnlen == 0
            || (ltc->public_name_len == hnlen
                && !OPENSSL_strncasecmp(hn, (char *)ltc->public_name, hnlen))) {
            namematch = 1;
        }
        suite->kem_id = ltc->kem_id;
        suitematch = 0;
        for (csuite = 0;
             csuite != ltc->nsuites && suitematch == 0;
             csuite++) {
            es = (unsigned char *)&ltc->ciphersuites[csuite];
            suite->kdf_id = es[0] * 256 + es[1];
            suite->aead_id = es[2] * 256 + es[3];
            if (OSSL_HPKE_suite_check(*suite) == 1) {
                suitematch = 1;
                /* pick this one if both "fit" */
                if (namematch == 1) {
                    *tc = ltc;
                    break;
                }
            }
        }
    }
    if (namematch == 0 || suitematch == 0) {
        return 0;
    }
    if (*tc == NULL || (*tc)->pub_len == 0 || (*tc)->pub == NULL)
        return 0;
    return 1;
}

/**
 * @brief Calculate AAD and then do ECH encryption
 * @param s is the SSL connection
 * @param pkt is the packet to send
 * @return 1 for success, other otherwise
 *
 * 1. Make up the AAD:
 *        For draft-13: the encoded outer, with ECH ciphertext octets zero'd
 * 2. Do the encryption
 * 3. Put the ECH back into the encoding
 * 4. Encode the outer (again!)
 */
int ech_aad_and_encrypt(SSL_CONNECTION *s, WPACKET *pkt)
{
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    size_t cipherlen = 0;
    unsigned char *cipher = NULL;
    unsigned char *aad = NULL;
    size_t aad_len = 0;
    unsigned char config_id_to_use = 0x00; /* we might replace with random */
    size_t lenclen = 0;
    /*
     * client's ephemeral public value for HPKE encryption ("enc")
     * Has to be externally generated so public can be part of AAD (sigh)
     * and in case of HRR.
     */
    unsigned char *mypub = NULL;
    size_t mypub_len = 0;
    /* a matching server public key from sets given to API (if one exists) */
    ECHConfig *tc = NULL;
    unsigned char info[SSL3_RT_MAX_PLAIN_LENGTH];
    size_t info_len = SSL3_RT_MAX_PLAIN_LENGTH;
    size_t suitesoffset = 0;
    size_t suiteslen = 0;
    size_t startofexts = 0;
    size_t origextlens = 0;
    size_t newextlens = 0;
    size_t echlen = 0;
    unsigned char *clear = NULL;
    size_t clear_len = 0;
    int rv = 0;

    if (s == NULL || s->ext.ech.cfgs == NULL
        || pkt == NULL || s->ssl.ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = ech_pick_matching_cfg(s, &tc, &hpke_suite);
    if (rv != 1 || tc == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    s->ext.ech.attempted_type = tc->version;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: selected: version: %4x, config %2x\n",
                   tc->version, tc->config_id);
    } OSSL_TRACE_END(TLS);
    /* if requested, use a random config_id */
    if (s->ssl.ctx->options & SSL_OP_ECH_IGNORE_CID) {
        if (RAND_bytes_ex(s->ssl.ctx->libctx, &config_id_to_use, 1,
                          RAND_DRBG_STRENGTH) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("EAAE: random config_id", &config_id_to_use, 1);
# endif
    } else {
        config_id_to_use = tc->config_id;
    }
    s->ext.ech.attempted_cid = config_id_to_use;
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: peer pub", tc->pub, tc->pub_len);
    ech_pbuf("EAAE: clear", s->ext.ech.encoded_innerch,
             s->ext.ech.encoded_innerch_len);
    ech_pbuf("EAAE: ECHConfig", tc->encoding_start, tc->encoding_length);
# endif

    /*
     * For draft-13 the AAD is the full outer client hello but
     * with the correct number of zeros for where the ECH ciphertext
     * octets will later be placed.
     *
     * Add the ECH extension to the |pkt| but with zeros for
     * ciphertext - that'll form up the AAD for us, then after
     * we've encrypted, we'll splice in the actual ciphertext
     *
     * Watch out for the "4" offsets that remove the type
     * and 3-octet length from the encoded CH as per the spec.
     */

    /* figure out padding */
    clear_len = ech_calc_padding(s, tc);
    if (clear_len == 0)
        goto err;
    lenclen = OSSL_HPKE_get_public_encap_size(hpke_suite);
    if (s->ext.ech.hpke_ctx == NULL) {
        if (ech_make_enc_info(tc, info, &info_len) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        s->ext.ech.hpke_ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                                OSSL_HPKE_ROLE_SENDER,
                                                NULL, NULL);
        if (s->ext.ech.hpke_ctx == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mypub = OPENSSL_malloc(lenclen);
        if (mypub == NULL)
            goto err;
        mypub_len = lenclen;
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("EAAE info", info, info_len);
# endif
        rv = OSSL_HPKE_encap(s->ext.ech.hpke_ctx, mypub, &mypub_len,
                             tc->pub, tc->pub_len, info, info_len);
        if (rv != 1) {
            OPENSSL_free(mypub);
            mypub = NULL;
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        s->ext.ech.pub = mypub;
        s->ext.ech.pub_len = mypub_len;
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("EAAE: mypub", mypub, mypub_len);
# endif
    } else {
        /* retrieve public */
        mypub = s->ext.ech.pub;
        mypub_len = s->ext.ech.pub_len;
        if (mypub == NULL || mypub_len == 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("EAAE: mypub", mypub, mypub_len);
# endif
    }
    cipherlen = OSSL_HPKE_get_ciphertext_size(hpke_suite, clear_len);
    if (cipherlen <= clear_len) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (cipherlen > OSSL_ECH_MAX_PAYLOAD_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    cipher = OPENSSL_zalloc(cipherlen);
    if (cipher == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    echlen = 1 + 4 + 1 + 2 + mypub_len + 2 + cipherlen;
    if (s->hello_retry_request == SSL_HRR_PENDING) {
        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ech13)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, OSSL_ECH_OUTER_CH_TYPE)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
            || !WPACKET_put_bytes_u8(pkt, config_id_to_use)
            || !WPACKET_put_bytes_u16(pkt, 0x00)
            || !WPACKET_sub_memcpy_u16(pkt, cipher, cipherlen)
            || !WPACKET_close(pkt)
            ) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        echlen -= mypub_len;
    } else {
        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ech13)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, OSSL_ECH_OUTER_CH_TYPE)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
            || !WPACKET_put_bytes_u8(pkt, config_id_to_use)
            || !WPACKET_sub_memcpy_u16(pkt, mypub, mypub_len)
            || !WPACKET_sub_memcpy_u16(pkt, cipher, cipherlen)
            || !WPACKET_close(pkt)
            ) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    aad = (unsigned char *)(pkt->buf->data) + 4;
    aad_len = pkt->written - 4;
    /* fix up the overall extensions length in the aad */
    suitesoffset = CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE + 1
        + s->tmp_session_id_len;
    suiteslen = aad[suitesoffset] * 256 + aad[suitesoffset + 1];
    startofexts = suitesoffset + suiteslen + 2 + 2; /* 2 for the suites len */
    origextlens = aad[startofexts] * 256 + aad[startofexts + 1];
    newextlens = origextlens + 4 + echlen;
    aad[startofexts] = (unsigned char)((newextlens & 0xffff) / 256);
    aad[startofexts + 1] = (unsigned char)((newextlens & 0xffff) % 256);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: aad", aad, aad_len);
# endif
    clear = OPENSSL_zalloc(clear_len);
    if (clear == NULL)
        goto err;
    memcpy(clear, s->ext.ech.encoded_innerch,
           s->ext.ech.encoded_innerch_len);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: draft-13 padded clear", clear, clear_len);
# endif
    rv = OSSL_HPKE_seal(s->ext.ech.hpke_ctx, cipher, &cipherlen,
                        aad, aad_len, clear, clear_len);
    OPENSSL_free(clear);
    if (rv != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: cipher", cipher, cipherlen);
    ech_pbuf("EAAE: hpke mypub", mypub, mypub_len);
# endif
    /* splice real ciphertext back in now */
    memcpy(aad + aad_len - cipherlen, cipher, cipherlen);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE pkt to startofexts+6 (startofexts is 4 offset so +2 really)",
             (unsigned char *) pkt->buf->data, startofexts + 6);
    ech_pbuf("EAAE pkt aftr", (unsigned char *)pkt->buf->data, pkt->written);
# endif
    OPENSSL_free(cipher);
    return 1;
err:
    OPENSSL_free(cipher);
    return 0;
}

/*
 * @brief If an ECH is present, attempt decryption
 * @param s SSL connection
 * @prarm outerpkt is the packet with the outer CH
 * @prarm newpkt is the packet with the decrypted inner CH
 * @return 1 for success, other otherwise
 *
 * If decryption succeeds, the caller can swap the inner and outer
 * CHs so that all further processing will only take into account
 * the inner CH.
 *
 * The fact that decryption worked is signalled to the caller
 * via s->ext.ech.success
 *
 * This function is called early, (hence then name:-), before
 * the outer CH decoding has really started, so we need to be
 * careful peeking into the packet
 *
 * The plan:
 * 1. check if there's an ECH
 * 2. trial-decrypt or check if config matches one loaded
 * 3. if decrypt fails tee-up GREASE
 * 4. if decrypt worked, decode and de-compress cleartext to
 *    make up real inner CH for later processing
 */
int ech_early_decrypt(SSL_CONNECTION *s, PACKET *outerpkt, PACKET *newpkt)
{
    int rv = 0;
    OSSL_ECH_ENCCH *extval = NULL;
    PACKET echpkt;
    PACKET *pkt = NULL;
    const unsigned char *startofech = NULL;
    size_t echlen = 0;
    size_t clearlen = 0;
    unsigned char *clear = NULL;
    unsigned int pval_tmp; /* tmp placeholder of value from packet */
    unsigned char aad[SSL3_RT_MAX_PLAIN_LENGTH];
    size_t aad_len = SSL3_RT_MAX_PLAIN_LENGTH;
    int cfgind = -1;
    int foundcfg = 0;
    int forhrr = 0;
    size_t startofsessid = 0; /* offset of session id within Ch */
    size_t startofexts = 0; /* offset of extensions within CH */
    size_t echoffset = 0; /* offset of start of ECH within CH */
    uint16_t echtype = TLSEXT_TYPE_ech_unknown; /* type of ECH seen */
    size_t outersnioffset = 0; /* offset to SNI in outer */
    size_t ch_len = 0; /* overall length of outer CH */
    const unsigned char *ch = NULL;
    int innerflag = -1;
    size_t startofciphertext = 0;
    size_t lenofciphertext = 0;
    size_t enclen = 0;
    size_t offsetofencwithinech = 0;
    unsigned char innerorouter = 0xff;
    const unsigned char *opd = NULL;
    size_t opl = 0;

    if (s == NULL || outerpkt == NULL || newpkt == NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return rv;
    }
    /*
     * check for placement of various things - when this works, the
     * relevant offsets are safe to use as they're checked within
     * the function
     */
    rv = ech_get_ch_offsets(s, outerpkt, &startofsessid, &startofexts,
                            &echoffset, &echtype, &innerflag, &outersnioffset);
    if (rv != 1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return rv;
    }
    if (echoffset == 0)
        return 1; /* ECH not present */
    if (innerflag == 1) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "EARLY: inner ECH in outer CH - that's bad\n");
        } OSSL_TRACE_END(TLS);
        return 0;
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EARLY: found an ECH\n");
    } OSSL_TRACE_END(TLS);
    /* Remember that we got an ECH */
    s->ext.ech.attempted = 1;
    s->ext.ech.attempted_type = echtype;
    /* set forhrr if that's correct */
    if (s->hello_retry_request == SSL_HRR_PENDING) {
        forhrr = 1;
    }
    opl = PACKET_remaining(outerpkt);
    opd = PACKET_data(outerpkt);
    /* We need to grab the session id */
    s->tmp_session_id_len = opd[startofsessid];
    if (s->tmp_session_id_len > SSL_MAX_SSL_SESSION_ID_LENGTH) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "EARLY: bad sess id len %zu vs max %d\n",
                       s->tmp_session_id_len, SSL_MAX_SSL_SESSION_ID_LENGTH);
        } OSSL_TRACE_END(TLS);
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    memcpy(s->tmp_session_id, &opd[startofsessid + 1],
           s->tmp_session_id_len);
    /* Grab the outer SNI for tracing.  */
    if (outersnioffset > 0) {
        PACKET osni;
        const unsigned char *osnibuf = &opd[outersnioffset + 4];
        size_t osnilen = opd[outersnioffset + 2] * 256
            + opd[outersnioffset + 3];

        if (osnilen > opl - outersnioffset - 4)
            goto err;
        if (PACKET_buf_init(&osni, osnibuf, osnilen) != 1) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (tls_parse_ctos_server_name(s, &osni, 0, NULL, 0) != 1) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (s->ext.ech.cfgs->outer_name != NULL) {
            /* can happen with HRR */
            OPENSSL_free(s->ext.ech.cfgs->outer_name);
        }
        s->ext.ech.cfgs->outer_name = s->ext.hostname;
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "EARLY: outer SNI of %s\n", s->ext.hostname);
        } OSSL_TRACE_END(TLS);
        /* clean up */
        s->ext.hostname = NULL;
        s->servername_done = 0;
    } else {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "EARLY: no sign of an outer SNI\n");
        } OSSL_TRACE_END(TLS);
    }
    /*
     * 2. trial-decrypt or check if config matches one loaded
     */
    if (echoffset > opl - 4)
        goto err;
    startofech = &opd[echoffset + 4];
    echlen = opd[echoffset + 2] * 256 + opd[echoffset + 3];
    if (echlen > opl - echoffset - 4)
        goto err;
    rv = PACKET_buf_init(&echpkt, startofech, echlen);
    pkt = &echpkt;
    /*
     * Try Decode the inbound value.
     * For draft-13, we're only concerned with the "inner"
     * form just here:
     *  enum { outer(0), inner(1) } ECHClientHelloType;
     *  struct {
     *     ECHClientHelloType type;
     *     select (ECHClientHello.type) {
     *         case outer:
     *             HpkeSymmetricCipherSuite cipher_suite;
     *             uint8 config_id;
     *             opaque enc<0..2^16-1>;
     *             opaque payload<1..2^16-1>;
     *         case inner:
     *             Empty;
     *     };
     *  } ECHClientHello;
     */
    extval = OPENSSL_zalloc(sizeof(OSSL_ECH_ENCCH));
    if (extval == NULL)
        goto err;

    if (!PACKET_copy_bytes(pkt, &innerorouter, 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (innerorouter != OSSL_ECH_OUTER_CH_TYPE) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_get_net_2(pkt, &pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->kdf_id = pval_tmp & 0xffff;
    if (!PACKET_get_net_2(pkt, &pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->aead_id = pval_tmp & 0xffff;

    /* config id */
    if (!PACKET_copy_bytes(pkt, &extval->config_id, 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EARLY config id", &extval->config_id, 1);
# endif
    s->ext.ech.attempted_cid = extval->config_id;

    /* enc - the client's public share */
    if (!PACKET_get_net_2(pkt, &pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp > OSSL_ECH_MAX_GREASE_PUB) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp > PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp == 0 && s->hello_retry_request != SSL_HRR_PENDING) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    } else if (pval_tmp == 0 && s->hello_retry_request == SSL_HRR_PENDING) {
        if (s->ext.ech.pub == NULL || s->ext.ech.pub_len == 0) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        extval->enc_len = s->ext.ech.pub_len;
        extval->enc = OPENSSL_malloc(extval->enc_len);
        if (extval->enc == NULL)
            goto err;
        memcpy(extval->enc, s->ext.ech.pub, extval->enc_len);
    } else {
        extval->enc_len = pval_tmp;
        extval->enc = OPENSSL_malloc(pval_tmp);
        if (extval->enc == NULL)
            goto err;
        if (!PACKET_copy_bytes(pkt, extval->enc, pval_tmp)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        /* squirrel away that value in case of future HRR */
        OPENSSL_free(s->ext.ech.pub);
        s->ext.ech.pub_len = extval->enc_len;
        s->ext.ech.pub_len = extval->enc_len;
        s->ext.ech.pub = OPENSSL_malloc(extval->enc_len);
        if (s->ext.ech.pub == NULL)
            goto err;
        memcpy(s->ext.ech.pub, extval->enc, extval->enc_len);
    }

    /* payload - the encrypted CH */
    if (!PACKET_get_net_2(pkt, &pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp > OSSL_ECH_MAX_PAYLOAD_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp > PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->payload_len = pval_tmp;
    extval->payload = OPENSSL_malloc(pval_tmp);
    if (extval->payload == NULL)
        goto err;
    if (!PACKET_copy_bytes(pkt, extval->payload, pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (echtype != OSSL_ECH_DRAFT_13_VERSION) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    ch_len = PACKET_remaining(outerpkt);
    ch = PACKET_data(outerpkt);
    /* AAD in draft-13 is rx'd packet with ciphertext zero'd */
    offsetofencwithinech = 2 + 2 + 1 +2 + 2 + 1;
    if ((echoffset + offsetofencwithinech + 1) > ch_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    enclen = ch[echoffset + offsetofencwithinech] * 256
        + ch[echoffset + offsetofencwithinech + 1];
    /* HRR enclen can be zero if we're handling HRR */
    if (enclen == 0 && s->hello_retry_request != SSL_HRR_PENDING) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    } else if (enclen == 0 && s->hello_retry_request == SSL_HRR_PENDING) {
        if (s->ext.ech.pub == NULL || s->ext.ech.pub_len == 0) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
    }
    if ((echoffset + offsetofencwithinech + 2 + enclen + 1) > ch_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    lenofciphertext = ch[echoffset + offsetofencwithinech + 2 + enclen] * 256
        + ch[echoffset + offsetofencwithinech + 2 + enclen + 1];
    startofciphertext = echoffset + offsetofencwithinech + 2 + enclen + 2;
    if ((startofciphertext + lenofciphertext) > ch_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (ch_len > SSL3_RT_MAX_PLAIN_LENGTH) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    aad_len = ch_len;
    memcpy(aad, ch, aad_len);
    memset(aad + startofciphertext, 0, lenofciphertext);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EARLY aad", aad, aad_len);
# endif

    /*
     * Now see which (if any) of our configs match, or whether
     * we want/need to trial decrypt
     */
    s->ext.ech.grease = OSSL_ECH_GREASE_UNKNOWN;

    if (s->ext.ech.cfgs->cfg == NULL || s->ext.ech.cfgs->cfg->nrecs == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    for (cfgind = 0; cfgind != s->ext.ech.ncfgs; cfgind++) {
        ECHConfig *e = &s->ext.ech.cfgs[cfgind].cfg->recs[0];

        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,
                       "EARLY: rx'd config id (%x) ==? %d-th configured (%x)\n",
                       extval->config_id, cfgind, e->config_id);
        } OSSL_TRACE_END(TLS);
        if (extval->config_id == e->config_id) {
            foundcfg = 1;
            break;
        }
    }
    if (s->ext.ech.encoded_innerch != NULL) {
        /* this happens with HRR */
        OPENSSL_free(s->ext.ech.encoded_innerch);
        s->ext.ech.encoded_innerch = NULL;
        s->ext.ech.encoded_innerch_len = 0;
    }
    if (foundcfg == 1) {
        clear = hpke_decrypt_encch(s, &s->ext.ech.cfgs[cfgind], extval,
                                   aad_len, aad, forhrr, &clearlen);
        if (clear == NULL) {
            s->ext.ech.grease = OSSL_ECH_IS_GREASE;
        }
    }

    /* Trial decrypt, if still needed */
    if (clear == NULL && (s->options & SSL_OP_ECH_TRIALDECRYPT)) {
        foundcfg = 0; /* reset as we're trying again */
        for (cfgind = 0; cfgind != s->ext.ech.ncfgs; cfgind++) {
            clear = hpke_decrypt_encch(s, &s->ext.ech.cfgs[cfgind], extval,
                                       aad_len, aad,
                                       forhrr, &clearlen);
            if (clear != NULL) {
                foundcfg = 1;
                s->ext.ech.grease = OSSL_ECH_NOT_GREASE;
                break;
            }
        }
    }

    /*
     * We succeeded or failed in decrypting, but we're done
     * with that now.
     */
    s->ext.ech.done = 1;

    /* 3. if decrypt fails tee-up GREASE */
    if (clear == NULL) {
        s->ext.ech.grease = OSSL_ECH_IS_GREASE;
        s->ext.ech.success = 0;
    } else {
        s->ext.ech.grease = OSSL_ECH_NOT_GREASE;
        s->ext.ech.success = 1;
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EARLY: success: %d, assume_grease: %d, "
                   "foundcfg: %d, cfgind: %d, clearlen: %zd, clear %p\n",
                   s->ext.ech.success, s->ext.ech.grease, foundcfg,
                   cfgind, clearlen, (void *)clear);
    } OSSL_TRACE_END(TLS);

# ifdef OSSL_ECH_SUPERVERBOSE
    /* Bit more logging */
    if (foundcfg == 1 && clear != NULL) {
        SSL_ECH *se = &s->ext.ech.cfgs[cfgind];
        ECHConfigList *seg = se->cfg;
        ECHConfig *e = &seg->recs[0];

        ech_pbuf("local config_id", &e->config_id, 1);
        ech_pbuf("remote config_id", &extval->config_id, 1);
        ech_pbuf("clear", clear, clearlen);
    }
# endif

    if (extval != NULL) {
        OSSL_ECH_ENCCH_free(extval);
        OPENSSL_free(extval);
        extval = NULL;
    }

    if (s->ext.ech.grease == OSSL_ECH_IS_GREASE)
        return 1;

    /*
     * 4. if decrypt worked, de-compress cleartext to make up real inner CH
     */
    s->ext.ech.encoded_innerch = clear;
    s->ext.ech.encoded_innerch_len = clearlen;
    if (ech_decode_inner(s, ch, ch_len, startofexts) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("Inner CH (decoded)", s->ext.ech.innerch, s->ext.ech.innerch_len);
# endif
    /*
     * The +4 below is because tls_process_client_hello doesn't
     * want to be given the message type & length, so the buffer should
     * start with the version octets (0x03 0x03)
     */
    if (PACKET_buf_init(newpkt, s->ext.ech.innerch + 4,
                        s->ext.ech.innerch_len - 4) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    return 1;

err:
    if (extval != NULL) {
        OSSL_ECH_ENCCH_free(extval);
        OPENSSL_free(extval);
        extval = NULL;
    }
    return 0;
}

/*
 * @brief copy an inner extension value to outer
 * @param s is the SSL connection
 * @param ext_type is the extension type
 * @param pkt is the outer packet being encoded
 * @return the relevant OSSL_ECH_SAME_EXT_* value
 *
 * We assume the inner CH has been pre-decoded into
 * s->clienthello->pre_proc_exts already
 *
 * The extension value could be empty (i.e. zero length)
 * but that's ok.
 */
int ech_copy_inner2outer(SSL_CONNECTION *s, uint16_t ext_type, WPACKET *pkt)
{
    size_t ind = 0;
    RAW_EXTENSION *myext = NULL;
    RAW_EXTENSION *raws = s->clienthello->pre_proc_exts;
    size_t nraws = 0;

    if (s == NULL || s->clienthello == NULL)
        return OSSL_ECH_SAME_EXT_ERR;
    raws = s->clienthello->pre_proc_exts;
    if (raws == NULL)
        return OSSL_ECH_SAME_EXT_ERR;
    nraws = s->clienthello->pre_proc_exts_len;
    /* copy inner to outer */
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "inner2outer: Copying ext type %d to outer\n",
                   ext_type);
    } OSSL_TRACE_END(TLS);
    for (ind = 0; ind != nraws; ind++) {
        if (raws[ind].type == ext_type) {
            myext = &raws[ind];
            break;
        }
    }
    if (myext == NULL) {
        /* This one wasn't in inner, so re-do processing */
        return OSSL_ECH_SAME_EXT_CONTINUE;
    }
    /* copy inner value to outer */
    if (PACKET_data(&myext->data) != NULL
        && PACKET_remaining(&myext->data) > 0) {
        if (!WPACKET_put_bytes_u16(pkt, ext_type)
            || !WPACKET_sub_memcpy_u16(pkt, PACKET_data(&myext->data),
                                       PACKET_remaining(&myext->data)))
            return OSSL_ECH_SAME_EXT_ERR;
    } else {
        /* empty extension */
        if (!WPACKET_put_bytes_u16(pkt, ext_type)
            || !WPACKET_put_bytes_u16(pkt, 0))
            return OSSL_ECH_SAME_EXT_ERR;
    }
    return 1;
}

/* SECTION: Public APIs */

/* Documentation in doc/man3/SSL_ech_set1_echconfig.pod */

void OSSL_ECH_INFO_free(OSSL_ECH_INFO *in, int size)
{
    int i = 0;

    if (in == NULL)
        return;
    for (i = 0; i != size; i++) {
        OPENSSL_free(in[i].public_name);
        OPENSSL_free(in[i].inner_name);
        OPENSSL_free(in[i].outer_alpns);
        OPENSSL_free(in[i].inner_alpns);
        OPENSSL_free(in[i].echconfig);
    }
    OPENSSL_free(in);
    return;
}

int OSSL_ECH_INFO_print(BIO *out, OSSL_ECH_INFO *se, int count)
{
    int i = 0;

    if (out == NULL || se == NULL || count == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    BIO_printf(out, "ECH details (%d configs total)\n", count);
    for (i = 0; i != count; i++) {
        BIO_printf(out, "index: %d: SNI (inner:%s;outer:%s), "
                   "ALPN (inner:%s;outer:%s)\n\t%s\n",
                   i,
                   se[i].inner_name ? se[i].inner_name : "NULL",
                   se[i].public_name ? se[i].public_name : "NULL",
                   se[i].inner_alpns ? se[i].inner_alpns : "NULL",
                   se[i].outer_alpns ? se[i].outer_alpns : "NULL",
                   se[i].echconfig ? se[i].echconfig : "NULL");
    }
    return 1;
}

int SSL_ech_set1_echconfig(SSL *ssl, const unsigned char *val, size_t len)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
    SSL_ECH *echs = NULL;
    SSL_ECH *tmp = NULL;
    int num_echs = 0;

    if (s == NULL || val == NULL || len == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (local_ech_add(OSSL_ECH_FMT_GUESS, len, val, &num_echs, &echs) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (num_echs == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (s->ext.ech.cfgs == NULL) {
        s->ext.ech.cfgs = echs;
        s->ext.ech.ncfgs = num_echs;
        s->ext.ech.attempted = 1;
        s->ext.ech.attempted_type = TLSEXT_TYPE_ech_unknown;
        s->ext.ech.attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
        return 1;
    }
    /* otherwise accumulate */
    tmp = OPENSSL_realloc(s->ext.ech.cfgs,
                          (s->ext.ech.ncfgs + num_echs) * sizeof(SSL_ECH));
    if (tmp == NULL) {
        SSL_ECH_free_arr(echs, num_echs);
        OPENSSL_free(echs);
        return 0;
    }
    s->ext.ech.cfgs = tmp;
    /* shallow copy top level, keeping lower levels */
    memcpy(&s->ext.ech.cfgs[s->ext.ech.ncfgs], echs,
           num_echs * sizeof(SSL_ECH));
    s->ext.ech.ncfgs += num_echs;
    OPENSSL_free(echs);
    return 1;
}

int SSL_CTX_ech_set1_echconfig(SSL_CTX *ctx, const unsigned char *val,
                               size_t len)
{
    SSL_ECH *echs = NULL;
    SSL_ECH *tmp = NULL;
    int num_echs = 0;

    if (ctx == NULL || val == NULL || len == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (local_ech_add(OSSL_ECH_FMT_GUESS, len, val, &num_echs, &echs) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (num_echs == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->ext.ech == NULL) {
        ctx->ext.ech = echs;
        ctx->ext.nechs = num_echs;
        return 1;
    }
    /* otherwise accumulate */
    tmp = OPENSSL_realloc(ctx->ext.ech,
                          (ctx->ext.nechs + num_echs) * sizeof(SSL_ECH));
    if (tmp == NULL) {
        SSL_ECH_free_arr(echs, num_echs);
        OPENSSL_free(echs);
        return 0;
    }
    ctx->ext.ech = tmp;
    /* shallow copy top level, keeping lower levels */
    memcpy(&ctx->ext.ech[ctx->ext.nechs], echs, num_echs * sizeof(SSL_ECH));
    ctx->ext.nechs += num_echs;
    /* top level can now be free'd */
    OPENSSL_free(echs);
    return 1;
}

int SSL_ech_set_server_names(SSL *ssl, const char *inner_name,
                             const char *outer_name, int no_outer)
{
    int nind = 0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /*
     * Note: we could not require s->ext.ech.cfgs to be set already here but
     * seems just as reasonable to impose an ordering on the sequence
     * of calls. (And it means we don't need somewhere to stash the
     * names outside of the s->ext.ech.cfgs array.)
     * Same applies to SSL_ech_set_outer_server_name()
     */
    if (s->ext.ech.cfgs == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    for (nind = 0; nind != s->ext.ech.ncfgs; nind++) {
        OPENSSL_free(s->ext.ech.cfgs[nind].outer_name);
        if (inner_name != NULL && strlen(inner_name) > 0)
            s->ext.ech.cfgs[nind].inner_name = OPENSSL_strdup(inner_name);
        else
            s->ext.ech.cfgs[nind].inner_name = NULL;
        OPENSSL_free(s->ext.ech.cfgs[nind].outer_name);
        if (outer_name != NULL && strlen(outer_name) > 0) {
            s->ext.ech.cfgs[nind].outer_name = OPENSSL_strdup(outer_name);
        } else {
            if (outer_name == NULL && no_outer == 1)
                s->ext.ech.cfgs[nind].no_outer = 1;
            else
                s->ext.ech.cfgs[nind].outer_name = NULL;
        }
    }
    s->ext.ech.attempted = 1;
    s->ext.ech.attempted_type = TLSEXT_TYPE_ech_unknown;
    s->ext.ech.attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
    return 1;
}

int SSL_ech_set_outer_server_name(SSL *ssl, const char *outer_name,
                                  int no_outer)
{
    int nind = 0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /*
     * Note: we could not require s->ext.ech.cfgs to be set already here but
     * seems just as reasonable to impose an ordering on the sequence
     * of calls. (And it means we don't need somewhere to stash the
     * names outside of the s->ext.ech.cfgs array.)
     * Same applies to SSL_ech_set_server_names()
     */
    if (s->ext.ech.cfgs == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    for (nind = 0; nind != s->ext.ech.ncfgs; nind++) {
        OPENSSL_free(s->ext.ech.cfgs[nind].outer_name);
        if (outer_name != NULL && strlen(outer_name) > 0) {
            s->ext.ech.cfgs[nind].outer_name = OPENSSL_strdup(outer_name);
        } else {
            if (outer_name == NULL && no_outer == 1)
                s->ext.ech.cfgs[nind].no_outer = 1;
            else
                s->ext.ech.cfgs[nind].outer_name = NULL;
        }
        /* if this is called and an SNI is set already we copy that to inner */
        if (s->ext.hostname != NULL) {
            OPENSSL_free(s->ext.ech.cfgs[nind].inner_name);
            s->ext.ech.cfgs[nind].inner_name = OPENSSL_strdup(s->ext.hostname);
        }
    }
    s->ext.ech.attempted = 1;
    s->ext.ech.attempted_type = TLSEXT_TYPE_ech_unknown;
    s->ext.ech.attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
    return 1;
}

int SSL_ech_get_info(SSL *ssl, OSSL_ECH_INFO **out, int *nindices)
{
    OSSL_ECH_INFO *rdiff = NULL;
    int i = 0;
    int indices = 0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
    BIO *tbio = NULL;

    if (s == NULL || out == NULL || nindices == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    indices = s->ext.ech.ncfgs;
    if (s->ext.ech.cfgs == NULL || s->ext.ech.ncfgs <= 0) {
        *out = NULL;
        *nindices = 0;
        return 1;
    }
    rdiff = OPENSSL_zalloc(s->ext.ech.ncfgs * sizeof(OSSL_ECH_INFO));
    if (rdiff == NULL)
        goto err;
    for (i = 0; i != s->ext.ech.ncfgs; i++) {
        OSSL_ECH_INFO *inst = &rdiff[i];

        if (s->ext.ech.cfgs->inner_name != NULL) {
            inst->inner_name = OPENSSL_strdup(s->ext.ech.cfgs->inner_name);
            if (inst->inner_name == NULL)
                goto err;
        }
        if (s->ext.ech.cfgs->outer_name != NULL) {
            inst->public_name = OPENSSL_strdup(s->ext.ech.cfgs->outer_name);
            if (inst->public_name == NULL)
                goto err;
        }
        if (s->ext.alpn != NULL) {
            inst->inner_alpns = alpn_print(s->ext.alpn, s->ext.alpn_len);
        }
        if (s->ext.ech.alpn_outer != NULL) {
            inst->outer_alpns = alpn_print(s->ext.ech.alpn_outer,
                                           s->ext.ech.alpn_outer_len);
        }
        /* Now "print" the ECHConfigList */
        if (s->ext.ech.cfgs[i].cfg != NULL) {
            size_t ehlen;
            unsigned char *ignore = NULL;

            tbio = BIO_new(BIO_s_mem());
            if (tbio == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (ECHConfigList_print(tbio, s->ext.ech.cfgs[i].cfg) != 1) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ehlen = BIO_get_mem_data(tbio, &ignore);
            inst->echconfig = OPENSSL_malloc(ehlen + 1);
            if (inst->echconfig == NULL)
                goto err;
            if (BIO_read(tbio, inst->echconfig, ehlen) <= 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            inst->echconfig[ehlen] = '\0';
            BIO_free(tbio);
            tbio = NULL;
        }
    }
    *nindices = indices;
    *out = rdiff;
    return 1;

err:
    BIO_free(tbio);
    OSSL_ECH_INFO_free(rdiff, indices);
    return 0;
}

int SSL_ech_reduce(SSL *ssl, int index)
{
    SSL_ECH *new = NULL;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL || index < 0 || s->ext.ech.cfgs == NULL
        || s->ext.ech.ncfgs <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (s->ext.ech.ncfgs <= index) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /*
     * Copy the one to keep, then zap the pointers at that element in the array
     * free the array and fix s back up
     */
    new = OPENSSL_malloc(sizeof(SSL_ECH));
    if (new == NULL)
        return 0;
    *new = s->ext.ech.cfgs[index];
    memset(&s->ext.ech.cfgs[index], 0, sizeof(SSL_ECH));
    SSL_ECH_free_arr(s->ext.ech.cfgs, s->ext.ech.ncfgs);
    OPENSSL_free(s->ext.ech.cfgs);
    s->ext.ech.cfgs = new;
    s->ext.ech.ncfgs = 1;
    return 1;
}

int SSL_CTX_ech_server_get_key_status(SSL_CTX *s, int *numkeys)
{
    if (s == NULL || numkeys == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (s->ext.ech)
        *numkeys = s->ext.nechs;
    else
        *numkeys = 0;
    return 1;
}

int SSL_CTX_ech_server_flush_keys(SSL_CTX *ctx, unsigned int age)
{
    time_t now = time(0);
    int i = 0;
    int deleted = 0; /* number deleted */
    int orig = 0;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* it's not a failure if nothing loaded yet */
    if (ctx->ext.ech == NULL || ctx->ext.nechs == 0)
        return 1;
    orig = ctx->ext.nechs;
    if (age == 0) {
        SSL_ECH_free_arr(ctx->ext.ech, ctx->ext.nechs);
        OPENSSL_free(ctx->ext.ech);
        ctx->ext.ech = NULL;
        ctx->ext.nechs = 0;
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "Flushed all %d ECH keys at %lu\n", orig,
                       (long unsigned int)now);
        } OSSL_TRACE_END(TLS);
        return 1;
    }
    /* Otherwise go through them and delete as needed */
    for (i = 0; i != ctx->ext.nechs; i++) {
        SSL_ECH *ep = &ctx->ext.ech[i];

        if ((ep->loadtime + (time_t) age) <= now) {
            SSL_ECH_free(ep);
            deleted++;
            continue;
        }
        ctx->ext.ech[i - deleted] = ctx->ext.ech[i]; /* struct copy! */
    }
    ctx->ext.nechs -= deleted;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "Flushed %d (of %d) ECH keys more than %u "
                   "seconds old at %lu\n", deleted, orig, age,
                   (long unsigned int)now);
    } OSSL_TRACE_END(TLS);
    return 1;
}

int SSL_CTX_ech_server_enable_file(SSL_CTX *ctx, const char *pemfile)
{
    int index = -1;
    int fnamestat = 0;
    SSL_ECH *sechs = NULL;
    int rv = 1;

    if (ctx == NULL || pemfile == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Check if we already loaded that one etc.  */
    fnamestat = ech_check_filenames(ctx, pemfile, &index);
    switch (fnamestat) {
    case OSSL_ECH_KEYPAIR_NEW:
        /* fall through */
    case OSSL_ECH_KEYPAIR_MODIFIED:
        /* processed below */
        break;
    case OSSL_ECH_KEYPAIR_UNMODIFIED:
        /* nothing to do */
        return 1;
    case OSSL_ECH_KEYPAIR_FILEMISSING:
        /* nothing to do, but trace this and let caller handle it */
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "Returning OSSL_ECH_FILEMISSING from "
                       "SSL_CTX_ech_server_enable_file for %s\n", pemfile);
            BIO_printf(trc_out, "That's unexpected and likely indicates a "
                       "problem, but the application might be able to "
                       "continue\n");
        } OSSL_TRACE_END(TLS);
        ERR_raise(ERR_LIB_SSL, SSL_R_FILE_OPEN_FAILED);
        return SSL_R_FILE_OPEN_FAILED;
    case OSSL_ECH_KEYPAIR_ERROR:
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    default:
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Load up the file content */
    rv = ech_readpemfile(ctx, 1, pemfile, NULL, 0, &sechs);
    if (rv != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /*
     * This is a restriction of our PEM file scheme - we only accept
     * one public key per PEM file.
     * (Well, simplification would be more accurate than restriction:-)
     */
    if (sechs == NULL || sechs->cfg == NULL || sechs->cfg->nrecs != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /* Now store the keypair in a new or current slot */
    if (fnamestat == OSSL_ECH_KEYPAIR_MODIFIED) {
        SSL_ECH *curr_ec = NULL;

        if (index < 0 || index >= ctx->ext.nechs) {
            SSL_ECH_free(sechs);
            OPENSSL_free(sechs);
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        curr_ec = &ctx->ext.ech[index];
        SSL_ECH_free(curr_ec);
        memset(curr_ec, 0, sizeof(SSL_ECH));
        *curr_ec = *sechs; /* struct copy */
        OPENSSL_free(sechs);
        return 1;
    }
    if (fnamestat == OSSL_ECH_KEYPAIR_NEW) {
        SSL_ECH *re_ec =
            OPENSSL_realloc(ctx->ext.ech,
                            (ctx->ext.nechs + 1) * sizeof(SSL_ECH));
        SSL_ECH *new_ec = NULL;

        if (re_ec == NULL) {
            SSL_ECH_free(sechs);
            OPENSSL_free(sechs);
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        ctx->ext.ech = re_ec;
        new_ec = &ctx->ext.ech[ctx->ext.nechs];
        memset(new_ec, 0, sizeof(SSL_ECH));
        *new_ec = *sechs;
        ctx->ext.nechs++;
        OPENSSL_free(sechs);
        return 1;
    }
    /* shouldn't ever happen, but hey... */
    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
    return 0;
}

int SSL_CTX_ech_server_enable_buffer(SSL_CTX *ctx, const unsigned char *buf,
                                     const size_t blen)
{
    SSL_ECH *sechs = NULL;
    int rv = 1;
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    int j = 0;
    unsigned char hashval[EVP_MAX_MD_SIZE];
    unsigned int hashlen;
    char ah_hash[2 * EVP_MAX_MD_SIZE + 1];
    SSL_ECH *re_ec = NULL;
    SSL_ECH *new_ec = NULL;

    if (ctx == NULL || buf == NULL || blen == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Pseudo-filename is hash of input buffer */
    md = ctx->ssl_digest_methods[SSL_HANDSHAKE_MAC_SHA256];
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (EVP_DigestInit_ex(mdctx, md, NULL) <= 0
        || EVP_DigestUpdate(mdctx, buf, blen) <= 0
        || EVP_DigestFinal_ex(mdctx, hashval, &hashlen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_MD_CTX_free(mdctx);
    /* AH encode hashval to be a string, as replacement for file name */
    if (ah_encode(ah_hash, sizeof(ah_hash), hashval, hashlen) != 1)
        return 0;
    /* Check if we have that buffer loaded already, if we did, we're done */
    for (j = 0; j != ctx->ext.nechs; j++) {
        SSL_ECH *se = &ctx->ext.ech[j];

        if (se->pemfname != NULL
            && strlen(se->pemfname) == strlen(ah_hash)
            && !memcpy(se->pemfname, ah_hash, strlen(ah_hash))) {
            /* we're done here */
            return 1;
        }
    }
    /* Load up the buffer content */
    rv = ech_readpemfile(ctx, 0, ah_hash, buf, blen, &sechs);
    if (rv != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /*
     * This is a restriction of our PEM file scheme - we only accept
     * one public key per PEM file
     */
    if (sechs == NULL || sechs->cfg == NULL || sechs->cfg->nrecs != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Now store the keypair in a new or current place */
    re_ec = OPENSSL_realloc(ctx->ext.ech,
                            (ctx->ext.nechs + 1) * sizeof(SSL_ECH));
    if (re_ec == NULL) {
        SSL_ECH_free(sechs);
        OPENSSL_free(sechs);
        return 0;
    }
    ctx->ext.ech = re_ec;
    new_ec = &ctx->ext.ech[ctx->ext.nechs];
    memset(new_ec, 0, sizeof(SSL_ECH));
    *new_ec = *sechs;
    ctx->ext.nechs++;
    OPENSSL_free(sechs);
    return 1;
}

int SSL_CTX_ech_server_enable_dir(SSL_CTX *ctx, int *number_loaded,
                                  const char *echdir)
{
    OPENSSL_DIR_CTX *d = NULL;
    const char *filename;

    if (ctx == NULL || echdir == NULL || number_loaded == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *number_loaded = 0;
    while ((filename = OPENSSL_DIR_read(&d, echdir))) {
        char echname[PATH_MAX];
        size_t nlen = 0;
        int r;
        const char *last4 = NULL;
        struct stat thestat;

        if (strlen(echdir) + strlen(filename) + 2 > sizeof(echname)) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "name too long: %s/%s - skipping it \r\n",
                           echdir, filename);
            } OSSL_TRACE_END(TLS);
            continue;
        }
# ifdef OPENSSL_SYS_VMS
        r = BIO_snprintf(echname, sizeof(echname), "%s%s", echdir, filename);
# else
        r = BIO_snprintf(echname, sizeof(echname), "%s/%s", echdir, filename);
# endif
        if (r <= 0 || r >= (int)sizeof(echname)) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "name oddity: %s/%s - skipping it \r\n",
                           echdir, filename);
            } OSSL_TRACE_END(TLS);
            continue;
        }
        nlen = strlen(filename);
        if (nlen <= 4) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "name too short: %s/%s - skipping it \r\n",
                           echdir, filename);
            } OSSL_TRACE_END(TLS);
            continue;
        }
        last4 = filename + nlen - 4;
        if (strncmp(last4, ".pem", 4) && strncmp(last4, ".ech", 4)) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,
                           "name doesn't end in .pem: %s/%s - skipping it \r\n",
                           echdir, filename);
            } OSSL_TRACE_END(TLS);
            continue;
        }
        if (stat(echname, &thestat) == 0) {
            if (SSL_CTX_ech_server_enable_file(ctx, echname) == 1) {
                *number_loaded = *number_loaded + 1;
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out, "Added %d-th ECH key pair from: %s\n",
                               *number_loaded, echname);
                } OSSL_TRACE_END(TLS);
            } else {
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out, "Failed to set ECH parameters for %s\n",
                               echname);
                } OSSL_TRACE_END(TLS);
            }
        }
    }
    if (d)
        OPENSSL_DIR_end(&d);
    return 1;
}

int SSL_ech_get_status(SSL *ssl, char **inner_sni, char **outer_sni)
{
    char *sinner = NULL;
    char *souter = NULL;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL || outer_sni == NULL || inner_sni == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return SSL_ECH_STATUS_FAILED;
    }
    *outer_sni = NULL;
    *inner_sni = NULL;
    if (s->ext.ech.grease == OSSL_ECH_IS_GREASE) {
        if (s->ext.ech.returned != NULL)
            return SSL_ECH_STATUS_GREASE_ECH;
        return SSL_ECH_STATUS_GREASE;
    }
    if (s->ext.ech.backend == 1)
        return SSL_ECH_STATUS_BACKEND;
    if (s->ext.ech.cfgs == NULL)
        return SSL_ECH_STATUS_NOT_CONFIGURED;
    /* set output vars - note we may be pointing to NULL which is fine */
    if (s->server == 0) {
        sinner = s->ext.hostname;
        souter = s->ext.ech.outer_hostname;
    } else {
        if (s->ext.ech.cfgs != NULL && s->ext.ech.success == 1) {
            sinner = s->ext.ech.cfgs->inner_name;
            souter = s->ext.ech.cfgs->outer_name;
        }
    }
    if (s->ext.ech.cfgs != NULL && s->ext.ech.attempted == 1
        && s->ext.ech.grease != OSSL_ECH_IS_GREASE) {
        long vr = X509_V_OK;

        vr = SSL_get_verify_result(ssl);
        *inner_sni = sinner;
        *outer_sni = souter;
        if (s->ext.ech.success == 1) {
            if (vr == X509_V_OK)
                return SSL_ECH_STATUS_SUCCESS;
            else
                return SSL_ECH_STATUS_BAD_NAME;
        } else {
            if (s->ext.ech.returned != NULL)
                return SSL_ECH_STATUS_FAILED_ECH;
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return SSL_ECH_STATUS_FAILED;
        }
    } else if (s->ext.ech.grease == OSSL_ECH_IS_GREASE) {
        return SSL_ECH_STATUS_GREASE;
    }
    return SSL_ECH_STATUS_NOT_TRIED;
}

void SSL_ech_set_callback(SSL *ssl, SSL_ech_cb_func f)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL || f == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return;
    }
    s->ext.ech.cb = f;
}

void SSL_CTX_ech_set_callback(SSL_CTX *s, SSL_ech_cb_func f)
{
    if (s == NULL || f == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return;
    }
    s->ext.ech_cb = f;
}

int SSL_ech_set_grease_suite(SSL *ssl, const char *suite)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Just stash the value for now and interpret when/if we do GREASE */
    OPENSSL_free(s->ext.ech.grease_suite);
    s->ext.ech.grease_suite = OPENSSL_strdup(suite);
    return 1;
}

int SSL_ech_set_grease_type(SSL *ssl, uint16_t type)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Just stash the value for now and interpret when/if we do GREASE */
    s->ext.ech.attempted_type = type;
    return 1;
}

int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            int *decrypted_ok,
                            char **inner_sni, char **outer_sni,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len)
{
    SSL *s = NULL;
    PACKET pkt_outer;
    PACKET pkt_inner;
    unsigned char *inner_buf = NULL;
    size_t inner_buf_len = 0;
    int rv = 0;
    size_t startofsessid = 0; /* offset of session id within Ch */
    size_t startofexts = 0; /* offset of extensions within CH */
    size_t echoffset = 0; /* offset of start of ECH within CH */
    uint16_t echtype = TLSEXT_TYPE_ech_unknown; /* type of ECH seen */
    size_t innersnioffset = 0; /* offset to SNI in inner */
    SSL_CONNECTION *sc = NULL;
    int innerflag = -1;

    if (ctx == NULL || outer_ch == NULL || outer_len == 0
        || inner_ch == NULL || inner_len == NULL || inner_sni == NULL
        || outer_sni == NULL || decrypted_ok == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    inner_buf_len = *inner_len;
    s = SSL_new(ctx);
    if (s == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (PACKET_buf_init(&pkt_outer, outer_ch + 9, outer_len - 9) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    inner_buf = OPENSSL_malloc(inner_buf_len);
    if (inner_buf == NULL)
        goto err;
    if (PACKET_buf_init(&pkt_inner, inner_buf, inner_buf_len) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    sc = SSL_CONNECTION_FROM_SSL(s);
    if (sc == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Check if there's any ECH and if so, whether it's an outer
     * (that might need decrypting) or an inner
     */
    rv = ech_get_ch_offsets(sc, &pkt_outer, &startofsessid, &startofexts,
                            &echoffset, &echtype, &innerflag, &innersnioffset);
    if (rv != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    if (echoffset == 0) {
        /* no ECH present */
        SSL_free(s);
        OPENSSL_free(inner_buf);
        *decrypted_ok = 0;
        return 1;
    }
    /* If we're asked to decrypt an inner, that's not ok */
    if (innerflag == 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        SSL_free(s);
        OPENSSL_free(inner_buf);
        *decrypted_ok = 0;
        return 0;
    }

    rv = ech_early_decrypt(sc, &pkt_outer, &pkt_inner);
    if (rv != 1) {
        /* that could've been GREASE, but we've no idea */
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    if (sc->ext.ech.cfgs != NULL && sc->ext.ech.cfgs->outer_name != NULL) {
        *outer_sni = OPENSSL_strdup(sc->ext.ech.cfgs->outer_name);
        if (*outer_sni == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (sc->ext.ech.success == 0) {
        *decrypted_ok = 0;
    } else {
        size_t ilen = PACKET_remaining(&pkt_inner);
        const unsigned char *iptr = NULL;

        /* make sure there's space */
        if ((ilen + 9) > inner_buf_len) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
            goto err;
        }
        if ((iptr = PACKET_data(&pkt_inner)) == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
            goto err;
        }
        /* Fix up header and length of inner CH */
        inner_ch[0] = SSL3_RT_HANDSHAKE;
        /* legacy version exception: RFC8446, 5.1 says 0x0301 is ok */
        inner_ch[1] = (TLS1_VERSION >> 8) & 0xff;
        inner_ch[2] = TLS1_VERSION  & 0xff;
        inner_ch[3] = ((ilen + 4) >> 8) & 0xff;
        inner_ch[4] = (ilen + 4) & 0xff;
        inner_ch[5] = SSL3_MT_CLIENT_HELLO;
        inner_ch[6] = (ilen >> 16) & 0xff;
        inner_ch[7] = (ilen >> 8) & 0xff;
        inner_ch[8] = ilen & 0xff;
        memcpy(inner_ch + 9, iptr, ilen);
        *inner_len = ilen + 9;
        /* Grab the inner SNI (if it's there) */
        rv = ech_get_ch_offsets(sc, &pkt_inner, &startofsessid, &startofexts,
                                &echoffset, &echtype, &innerflag,
                                &innersnioffset);
        if (rv != 1) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
            return rv;
        }
        if (innersnioffset > 0) {
            PACKET isni;
            size_t plen;
            const unsigned char *isnipeek = NULL;
            const unsigned char *isnibuf = NULL;
            size_t isnilen = 0;

            plen = PACKET_remaining(&pkt_inner);
            if (PACKET_peek_bytes(&pkt_inner, &isnipeek, plen) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            if (plen <= 4) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            isnibuf = &(isnipeek[innersnioffset + 4]);
            isnilen = isnipeek[innersnioffset + 2] * 256
                + isnipeek[innersnioffset + 3];
            if (isnilen >= plen - 4) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            if (PACKET_buf_init(&isni, isnibuf, isnilen) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            if (tls_parse_ctos_server_name(sc, &isni, 0, NULL, 0) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            if (sc->ext.hostname != NULL) {
                *inner_sni = OPENSSL_strdup(sc->ext.hostname);
                if (*inner_sni == NULL) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
            }
        }

        /* Declare success to caller */
        *decrypted_ok = 1;
    }
    SSL_free(s);
    OPENSSL_free(inner_buf);
    return 1;
err:
    SSL_free(s);
    OPENSSL_free(inner_buf);
    return 0;
}

int SSL_CTX_ech_set_outer_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
                                      const size_t protos_len)
{
    if (ctx == NULL || protos == NULL || protos_len == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    OPENSSL_free(ctx->ext.alpn_outer);
    ctx->ext.alpn_outer = OPENSSL_memdup(protos, protos_len);
    if (ctx->ext.alpn_outer == NULL) {
        return 0;
    }
    ctx->ext.alpn_outer_len = protos_len;
    return 1;
}

int SSL_ech_get_retry_config(SSL *ssl, const unsigned char **ec, size_t *eclen)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL || eclen == NULL || ec == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (s->ext.ech.returned != NULL) {
        *eclen = s->ext.ech.returned_len;
        *ec = s->ext.ech.returned;
    } else {
        *eclen = 0;
        *ec = NULL;
    }
    return 1;
}

int ossl_ech_make_echconfig(unsigned char *echconfig, size_t *echconfiglen,
                            unsigned char *priv, size_t *privlen,
                            uint16_t ekversion, uint16_t max_name_length,
                            const char *public_name, OSSL_HPKE_SUITE suite,
                            const unsigned char *extvals, size_t extlen)
{
    size_t pnlen = 0;
    size_t publen = OSSL_ECH_CRYPTO_VAR_SIZE;
    unsigned char pub[OSSL_ECH_CRYPTO_VAR_SIZE];
    int rv = 0;
    unsigned char *bp = NULL;
    size_t bblen = 0;
    unsigned int b64len = 0;
    EVP_PKEY *privp = NULL;
    BIO *bfp = NULL;
    size_t lprivlen = 0;
    uint8_t config_id = 0;
    WPACKET epkt;
    BUF_MEM *epkt_mem = NULL;

    /* basic checks */
    if (echconfig == NULL || echconfiglen == NULL
        || priv == NULL || privlen == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    pnlen = (public_name == NULL ? 0 : strlen(public_name));
    if (pnlen > OSSL_ECH_MAX_PUBLICNAME) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (max_name_length > OSSL_ECH_MAX_MAXNAMELEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    /* this used have more versions and will again in future */
    switch (ekversion) {
    case OSSL_ECH_DRAFT_13_VERSION:
        break;
    default:
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    /* so WPAKCET_cleanup() won't go wrong */
    memset(&epkt, 0, sizeof(epkt));

    if (OSSL_HPKE_keygen(suite, pub, &publen, &privp, NULL, 0, NULL, NULL)
        != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    bfp = BIO_new(BIO_s_mem());
    if (bfp == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!PEM_write_bio_PrivateKey(bfp, privp, NULL, NULL, 0, NULL, NULL)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    lprivlen = BIO_read(bfp, priv, *privlen);
    if (lprivlen <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (lprivlen > *privlen) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    /*
     * if we can, add a NUL to the end of the private key string, just
     * to be nice to users
     */
    if (lprivlen < *privlen)
        priv[lprivlen] = 0x00;
    *privlen = lprivlen;

    /*
     *   Reminder, for draft-13 we want this:
     *
     *   opaque HpkePublicKey<1..2^16-1>;
     *   uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
     *   struct {
     *       HpkeKdfId kdf_id;
     *       HpkeAeadId aead_id;
     *   } HpkeSymmetricCipherSuite;
     *   struct {
     *       uint8 config_id;
     *       HpkeKemId kem_id;
     *       HpkePublicKey public_key;
     *       HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
     *   } HpkeKeyConfig;
     *   struct {
     *       HpkeKeyConfig key_config;
     *       uint8 maximum_name_length;
     *       opaque public_name<1..255>;
     *       Extension extensions<0..2^16-1>;
     *   } ECHConfigContents;
     *   struct {
     *       uint16 version;
     *       uint16 length;
     *       select (ECHConfig.version) {
     *         case 0xfe0d: ECHConfigContents contents;
     *       }
     *   } ECHConfig;
     *   ECHConfig ECHConfigList<1..2^16-1>;
     */

    if ((epkt_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(epkt_mem, OSSL_ECH_MAX_ECHCONFIG_LEN)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* config id, KEM, public, KDF, AEAD, max name len, public_name, exts */
    if (!WPACKET_init(&epkt, epkt_mem)
        || (bp = WPACKET_get_curr(&epkt)) == NULL
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_put_bytes_u16(&epkt, ekversion)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_put_bytes_u8(&epkt, config_id)
        || !WPACKET_put_bytes_u16(&epkt, suite.kem_id)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_memcpy(&epkt, pub, publen)
        || !WPACKET_close(&epkt)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_put_bytes_u16(&epkt, suite.kdf_id)
        || !WPACKET_put_bytes_u16(&epkt, suite.aead_id)
        || !WPACKET_close(&epkt)
        || !WPACKET_put_bytes_u8(&epkt, max_name_length)
        || !WPACKET_start_sub_packet_u8(&epkt)
        || !WPACKET_memcpy(&epkt, public_name, pnlen)
        || !WPACKET_close(&epkt)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_memcpy(&epkt, extvals, extlen)
        || !WPACKET_close(&epkt)
        || !WPACKET_close(&epkt)
        || !WPACKET_close(&epkt)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    WPACKET_get_total_written(&epkt, &bblen);
    b64len = EVP_EncodeBlock((unsigned char *)echconfig,
                             (unsigned char *)bp, bblen);
    if (b64len >= (*echconfiglen - 1)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    echconfig[b64len] = '\0';
    *echconfiglen = b64len;
    rv = 1;

err:
    EVP_PKEY_free(privp);
    BIO_free_all(bfp);
    WPACKET_cleanup(&epkt);
    BUF_MEM_free(epkt_mem);
    return rv;
}

int ossl_ech_find_echconfigs(int *num_echs,
                             unsigned char ***echconfigs, size_t **echlens,
                             const unsigned char *val, size_t len)
{
    SSL_ECH *new_echs = NULL;
    int rv = 0, i, num_new = 0;
    unsigned char **ebufs = NULL;
    size_t *elens = NULL;

    if (num_echs == NULL || echconfigs == NULL || echlens == NULL
        || val == NULL || len == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (ech_finder(&num_new, &new_echs, len, val) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (num_new == 0) {
        /* that's not a fail, just an empty set result */
        *num_echs = num_new;
        return 1;
    }
    ebufs = OPENSSL_malloc(num_new * sizeof(unsigned char *));
    if (ebufs == NULL)
        goto err;
    elens = OPENSSL_malloc(num_new * sizeof(size_t));
    if (elens == NULL)
        goto err;
    for (i = 0; i != num_new; i++) {
        ebufs[i] = new_echs[i].cfg->encoded;
        elens[i] = new_echs[i].cfg->encoded_len;
        new_echs[i].cfg->encoded = NULL; /* so we don't double free later */
    }
    *echconfigs = ebufs;
    *echlens = elens;
    *num_echs = num_new;
    rv = 1;
err:
    if (rv == 0) {
        OPENSSL_free(ebufs);
        OPENSSL_free(elens);
    }
    /* this free is ok as we've NULL'd the encoded version above */
    SSL_ECH_free_arr(new_echs, num_new);
    OPENSSL_free(new_echs);
    return rv;
}

#endif
