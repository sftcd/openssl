/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
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
 * 272 is the size I produce for a real ECH when including padding in
 * the inner CH with the default/current client hello padding code.
 * This value doesn't vary with at least minor changes to inner SNI
 * length. The 272 is 256 of padded cleartext plus a 16-octet AEAD
 * tag.
 */
# define OSSL_ECH_DEF_CIPHER_LEN 272
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
# define OSSL_ECH_PADDING_TARGET 256 /* ECH cleartext padded to at least this */
# define OSSL_ECH_PADDING_INCREMENT 32 /* ECH padded to a multiple of this */

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
 * When doing ECH, this array specifies which inner CH extensions (if
 * any) are to be "compressed" using the outer extensions scheme.
 *
 * Basically, we store a 0 for "don't compress" and a 1 for "do compress"
 * and the index is the same as the index of the extension itself.
 *
 * This might disappear before submitting a PR to upstream as it may
 * make more sense for this to be a new field in the ext_defs table
 * in ssl/statem/extensions.c For now however, we'll keep it separate,
 * in case it changes. Reasons this could change include: wanting better
 * than compile-time, handling custom extensions or a desire to look
 * the same as some extant browser.
 *
 * As with ext_defs in extensions.c: NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the
 * indexes ( TLSEXT_IDX_* ) defined in ssl_local.h.
 */
static const int ech_outer_config[] =
    {
     /* TLSEXT_IDX_renegotiate, 0xff01 */ 0,
     /* TLSEXT_IDX_server_name, 0 */ 0,
     /* TLSEXT_IDX_max_fragment_length, 1 */ 1,
     /* TLSEXT_IDX_srp, 12 */ 1,
     /* TLSEXT_IDX_ec_point_formats, 11 */ 1,
     /* TLSEXT_IDX_supported_groups, 10 */ 1,
     /* TLSEXT_IDX_session_ticket, 35 */ 1,
     /* TLSEXT_IDX_status_request, 5 */ 1,
     /* TLSEXT_IDX_next_proto_neg, 13172 */ 1,
     /* TLSEXT_IDX_application_layer_protocol_negotiation, 16 */ 0,
     /* TLSEXT_IDX_use_srtp, 14 */ 1,
     /* TLSEXT_IDX_encrypt_then_mac, 22 */ 1,
     /* TLSEXT_IDX_signed_certificate_timestamp, 18 */ 0,
     /* TLSEXT_IDX_extended_master_secret, 23 */ 1,
     /* TLSEXT_IDX_signature_algorithms_cert, 50 */ 0,
     /* TLSEXT_IDX_post_handshake_auth, 49 */ 0,
     /* TLSEXT_IDX_signature_algorithms, 13 */ 1,
     /* TLSEXT_IDX_supported_versions, 43 */ 1,
     /* TLSEXT_IDX_psk_kex_modes, 45 */ 0,
     /* TLSEXT_IDX_key_share, 51 */ 0,
     /* TLSEXT_IDX_cookie, 44 */ 0,
     /* TLSEXT_IDX_cryptopro_bug, 0xfde8 */ 0,
     /* TLSEXT_IDX_early_data, 42 */ 0,
     /* TLSEXT_IDX_certificate_authorities, 47 */ 0,
     /* TLSEXT_IDX_ech, 0xfe0a */ 0,
     /* TLSEXT_IDX_ech13, 0xfe0d */ 0,
     /* TLSEXT_IDX_outer_extensions, 0xfd00 */ 0,
     /* TLSEXT_IDX_ech_is_inner, 0xda09 */ 0,
     /* TLSEXT_IDX_padding, 21 */ 0,
     /* TLSEXT_IDX_psk, 41 */ 0
    };

/*
 * When doing ECH, this array specifies whether, when we're not
 * compressing, we want to re-use the inner value in the outer CH
 * ("0") or whether to generate an independently new value for the
 * outer ("1"). That makes most sense perhaps for the key_share,
 * but maybe also for others, hence being generic.
 *
 * These settings will be ignored for some extensions that don't
 * use the IOSAME macro (in ssl/statem/extensions_clnt.c) - for
 * example the ECH setting below is ignored as you'd imagine.
 *
 * As above this could disappear before submitting a PR to upstream.
 *
 * As with ext_defs in extensions.c: NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the
 * indexes ( TLSEXT_IDX_* ) defined in ssl_local.h.
 */
static const int ech_outer_indep[] =
    {
     /* TLSEXT_IDX_renegotiate */ 0,
     /* TLSEXT_IDX_server_name */ 1,
     /* TLSEXT_IDX_max_fragment_length */ 0,
     /* TLSEXT_IDX_srp */ 0,
     /* TLSEXT_IDX_ec_point_formats */ 0,
     /* TLSEXT_IDX_supported_groups */ 0,
     /* TLSEXT_IDX_session_ticket */ 0,
     /* TLSEXT_IDX_status_request */ 0,
     /* TLSEXT_IDX_next_proto_neg */ 0,
     /* TLSEXT_IDX_application_layer_protocol_negotiation */ 1,
     /* TLSEXT_IDX_use_srtp */ 0,
     /* TLSEXT_IDX_encrypt_then_mac */ 0,
     /* TLSEXT_IDX_signed_certificate_timestamp */ 0,
     /* TLSEXT_IDX_extended_master_secret */ 0,
     /* TLSEXT_IDX_signature_algorithms_cert */ 0,
     /* TLSEXT_IDX_post_handshake_auth */ 0,
     /* TLSEXT_IDX_signature_algorithms */ 0,
     /* TLSEXT_IDX_supported_versions */ 0,
     /* TLSEXT_IDX_psk_kex_modes */ 0,
     /* TLSEXT_IDX_key_share */ 1,
     /* TLSEXT_IDX_cookie */ 0,
     /* TLSEXT_IDX_cryptopro_bug */ 0,
     /* TLSEXT_IDX_early_data */ 0,
     /* TLSEXT_IDX_certificate_authorities */ 0,
     /* TLSEXT_IDX_ech */ 0,
     /* TLSEXT_IDX_ech13 */ 0,
     /* TLSEXT_IDX_outer_extensions */ 0,
     /* TLSEXT_IDX_ech_is_inner */ 0,
     /* TLSEXT_IDX_padding */ 0,
     /* TLSEXT_IDX_psk */ 0,
    };

/*
 * Telltales we use when guessing which form of encoded input we've
 * been given for an RR value or ECHConfig
 * TODO: check if these need the EBCDIC treatment as per the above.
 */

/* ascii hex is easy:-) either case allowed, plus a semi-colon separator */
static const char *AH_alphabet = "0123456789ABCDEFabcdef;";
/* b64 plus a semi-colon - we accept multiple semi-colon separated values */
static const char *B64_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=;";
/* telltale for ECH HTTPS/SVCB in presentation format, as per svcb spec */
static const char *httpssvc_telltale = "ech=";

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
     * if no file info, crap out... hmm, that could happen if the
     * disk fails hence different return value - the application may
     * be able to continue anyway...
     */
    if (stat(pemfname, &pemstat) < 0)
        return OSSL_ECH_KEYPAIR_FILEMISSING;

    /* check the time info - we're only gonna do 1s precision on purpose */
# if defined(__APPLE__)
    pemmod = pemstat.st_mtimespec.tv_sec;
# elif defined(OPENSSL_SYS_WINDOWS)
    pemmod = pemstat.st_mtime;
# else
    pemmod = pemstat.st_mtim.tv_sec;
# endif

    /* search list of existing key pairs to see if we have that one already */
    pemlen = strlen(pemfname);
    for (ind = 0; ind != ctx->ext.nechs; ind++) {
        size_t llen = 0;

        if (ctx->ext.ech[ind].pemfname == NULL)
            return OSSL_ECH_KEYPAIR_ERROR;
        llen = strlen(ctx->ext.ech[ind].pemfname);
        if (llen == pemlen
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
 * @param out is the binary equivalent
 * @return is the number of octets in |out| if successful, <=0 for failure
 *
 * This is like ct_base64_decode from crypto/ct/ct_b64.c but a) that's static
 * and b) we extend here to allow a sequence of semi-colon separated strings
 * as the input to support multivalued RRs. If the latter were ok for both
 * functions (it probably isn't) then we could merge the two functions.
 *
 * The input is modified if multivalued (NULL bytes are added in place of
 * semi-colon separators) so the caller should have copied  that if that's
 * an issue.
 */
static int ech_base64_decode(char *in, unsigned char **out)
{
    const char *sepstr = OSSL_ECH_FMT_SEPARATOR;
    size_t inlen = 0;
    int i = 0;
    int outlen = 0;
    unsigned char *outbuf = NULL;
    char *inp = in;
    unsigned char *outp = NULL;
    size_t overallfraglen = 0;

    if (in == NULL || out == NULL)
        return 0;
    inlen = strlen(in);
    if (inlen == 0) {
        *out = NULL;
        return 0;
    }
    /* overestimate of space but easier */
    outbuf = OPENSSL_malloc(inlen);
    if (outbuf == NULL)
        goto err;
    outp = outbuf;
    while (overallfraglen < inlen) {
        int ofraglen = 0;
        /* find length of 1st b64 string */
        size_t thisfraglen = strcspn(inp, sepstr);

        /* For ECH we'll never see this but just so we have bounds */
        if (thisfraglen <= OSSL_ECH_MIN_ECHCONFIG_LEN
            || thisfraglen > OSSL_ECH_MAX_ECHCONFIG_LEN)
            goto err;
        if (thisfraglen > inlen)
            goto err;
        if (thisfraglen < inlen)
            inp[thisfraglen] = '\0';
        overallfraglen += (thisfraglen + 1);
        ofraglen = EVP_DecodeBlock(outp, (unsigned char *)inp, thisfraglen);
        if (ofraglen < 0)
            goto err;
        /* Subtract padding bytes from |outlen|.  More than 2 is malformed. */
        i = 0;
        while (inp[thisfraglen - i - 1] == '=') {
            if (++i > 2)
                goto err;
        }
        outp += (ofraglen - i);
        outlen += (ofraglen - i);
        inp += (thisfraglen + 1);
    }
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
 * the OSSL_ECH_FMT_GUESS value.
 */
static int ech_guess_fmt(size_t eklen, unsigned char *rrval, int *guessedfmt)
{
    size_t span = 0;

    /* 
     * This could be more terse, but this is better for
     * debugging corner cases for now
     */
    if (guessedfmt == NULL || eklen == 0 || rrval == NULL)
        return 0;
    if (strstr((char *)rrval, httpssvc_telltale)) {
        *guessedfmt = OSSL_ECH_FMT_HTTPSSVC;
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

/*!
 * @brief decode ascii hex to a binary buffer
 *
 * @param ahlen is the ascii hex string length
 * @param ah is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return 1 for good otherwise bad
 */
static int ah_decode(size_t ahlen, const char *ah,
                     size_t *blen, unsigned char **buf)
{
    size_t lblen = 0;
    int i = 0, j = 0;
    int nibble = 0;
    unsigned char *lbuf = NULL;

    if (ahlen <= 0 || ah == NULL || blen == NULL || buf == NULL)
        return 0;
    if (ahlen % 2 == 1)
        nibble = 1;
    lblen = ahlen / 2 + nibble;
    lbuf = OPENSSL_malloc(lblen);
    if (lbuf == NULL)
        return 0;
    for (i = ahlen - 1; i > nibble; i -= 2) {
        j = i / 2;
        lbuf[j] = LOCAL_A2B(ah[i - 1]) * 16 + LOCAL_A2B(ah[i]);
    }
    if (nibble)
        lbuf[0] = LOCAL_A2B(ah[0]);
    *blen = lblen;
    *buf = lbuf;
    return 1;
}

/*
 * @brief Decode the first ECHConfigs from a binary buffer
 * @param binbuf is the buffer with the encoding
 * @param binblen is the length of binbunf
 * @param leftover is the number of unused octets from the input
 * @return NULL on error, or a pointer to an ECHConfigs structure
 */
static ECHConfigs *ECHConfigs_from_binary(unsigned char *binbuf,
                                          size_t binblen, int *leftover)
{
    ECHConfigs *er = NULL; /* ECHConfigs record */
    ECHConfig  *te = NULL; /* Array of ECHConfig to be embedded in that */
    int rind = 0;
    size_t remaining = 0;
    PACKET pkt;
    unsigned int olen = 0;
    size_t not_to_consume = 0;

    if (leftover == NULL || binbuf == NULL || binblen == 0) {
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
     * Overall length of this ECHConfigs (olen) still could be
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
    printf("olen: %u, binblen: %lu\n", olen, binblen);
    if (olen > (binblen - 2)) {
        printf("olen: %u, binblen: %lu\n", olen, binblen);
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

    /*
     * if none of the offered ECHConfig values work (e.g. bad versions)
     * then that's broken
     */
    if (rind == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Success - make up return value */
    *leftover = PACKET_remaining(&pkt);
    er = (ECHConfigs *)OPENSSL_malloc(sizeof(ECHConfigs));
    if (er == NULL)
        goto err;
    memset(er, 0, sizeof(ECHConfigs));
    er->nrecs = rind;
    er->recs = te;
    te = NULL;
    er->encoded_len = binblen;
    er->encoded = binbuf;
    return er;

err:
    ECHConfigs_free(er);
    OPENSSL_free(er);
    if (te) {
        int teind;

        for (teind = 0; teind != rind; teind++)
            ECHConfig_free(&te[teind]);
        OPENSSL_free(te);
    }
    return NULL;
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
        *tp = '.';
        tp++;
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
 * @brief Decode/check the value from DNS (binary, base64 or ascii-hex encoded)
 * @param eklen length of the binary, base64 or ascii-hex encoded value from DNS
 * @param ekval is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param echs is a pointer to an array of decoded SSL_ECH
 * @return is 1 for success, error otherwise
 *
 * This does the real work, can be called to add to a context or a connection
 */
static int local_ech_add(int ekfmt, size_t eklen, unsigned char *ekval,
                         int *num_echs, SSL_ECH **echs)
{
    int detfmt = OSSL_ECH_FMT_GUESS;
    int rv = 0;
    unsigned char *outbuf = NULL; /* sequence of ECHConfigs (binary) */
    size_t declen = 0; /* length of the above */
    char *ekptr = NULL;
    int done = 0;
    unsigned char *outp = outbuf;
    unsigned char *ekcpy = NULL;
    int oleftover = 0;
    int nlens = 0;
    SSL_ECH *retechs = NULL;
    SSL_ECH *newech = NULL;
    int cfgind = 0;

    if (eklen == 0 || ekval == NULL || num_echs == NULL) {
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
    case OSSL_ECH_FMT_HTTPSSVC:
    case OSSL_ECH_FMT_ASCIIHEX:
    case OSSL_ECH_FMT_B64TXT:
    case OSSL_ECH_FMT_BIN:
        detfmt = ekfmt;
        break;
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

    if (detfmt == OSSL_ECH_FMT_HTTPSSVC) {
        if (strlen((char *)ekcpy) != eklen) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ekptr = strstr((char *)ekcpy, httpssvc_telltale);
        if (ekptr == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* point ekptr at b64 encoded value */
        if (strlen(ekptr) <= strlen(httpssvc_telltale)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ekptr += strlen(httpssvc_telltale);
        detfmt = OSSL_ECH_FMT_B64TXT; /* tee up next step */
    }
    if (detfmt == OSSL_ECH_FMT_B64TXT) {
        int tdeclen = 0;

        if (strlen((char *)ekcpy) != eklen) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* need an int to get -1 return for failure case */
        tdeclen = ech_base64_decode(ekptr, &outbuf);
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
    /*
     * Now try decode the catenated binary encodings if we can
     * We'll probably only get one, but there could be more.
     */
    outp = outbuf;
    oleftover = declen;
    while (done == 0) {
        SSL_ECH *ts = NULL;
        int leftover = oleftover;
        ECHConfigs *er = NULL;
        ECHConfig  *ec = NULL;

        nlens += 1;
        ts = OPENSSL_realloc(retechs, nlens * sizeof(SSL_ECH));
        if (ts == NULL)
            goto err;
        retechs = ts;
        newech = &retechs[nlens - 1];
        memset(newech, 0, sizeof(SSL_ECH));

        er = ECHConfigs_from_binary(outp, oleftover, &leftover);
        if (er == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        newech->cfg = er;

        /*
         * If needed, flatten the storage so each SSL_ECH has exactly
         * one ECHConfig which has exactly one public key, thus enabling
         * the application to sensibly downselect if they wish.
         */
        if (er->nrecs > 1) {
            /* need another slot (or more) to flatten into */
            ts = OPENSSL_realloc(retechs,
                                 (nlens + er->nrecs - 1) * sizeof(SSL_ECH));
            if (ts == NULL)
                goto err;
            retechs = ts;
            /* move the cfgs up a level as needed */
            for (cfgind = 0; cfgind != er->nrecs - 1; cfgind++) {
                if (retechs[nlens - 1].inner_name != NULL) {
                    retechs[nlens + cfgind].inner_name =
                        OPENSSL_strdup(retechs[nlens - 1].inner_name);
                    if (retechs[nlens + cfgind].inner_name == NULL)
                        goto err;
                } else {
                    retechs[nlens + cfgind].inner_name = NULL;
                }
                if (retechs[nlens - 1].outer_name != NULL) {
                    retechs[nlens + cfgind].outer_name =
                        OPENSSL_strdup(retechs[nlens - 1].outer_name);
                    if (retechs[nlens + cfgind].outer_name == NULL)
                        goto err;
                } else {
                    retechs[nlens + cfgind].outer_name = NULL;
                }
                retechs[nlens + cfgind].no_outer = 0;
                retechs[nlens + cfgind].pemfname = NULL;
                retechs[nlens + cfgind].loadtime = 0;
                retechs[nlens + cfgind].keyshare = NULL;
                retechs[nlens + cfgind].cfg =
                    OPENSSL_malloc(sizeof(ECHConfigs));
                if (retechs[nlens + cfgind].cfg == NULL)
                    goto err;
                retechs[nlens + cfgind].cfg->nrecs = 1;
                ec = OPENSSL_malloc(sizeof(ECHConfig));
                if (ec == NULL)
                    goto err;
                /* note - shallow copy is correct on next line */
                *ec = retechs[nlens - 1].cfg->recs[cfgind + 1];
                retechs[nlens + cfgind].cfg->recs = ec;
                retechs[nlens + cfgind].cfg->encoded_len =
                    retechs[nlens - 1].cfg->encoded_len;
                retechs[nlens + cfgind].cfg->encoded =
                    OPENSSL_malloc(retechs[nlens - 1].cfg->encoded_len);
                if (retechs[nlens + cfgind].cfg->encoded == NULL)
                    goto err;
                memcpy(retechs[nlens + cfgind].cfg->encoded,
                       retechs[nlens - 1].cfg->encoded,
                       retechs[nlens - 1].cfg->encoded_len);
            }
            nlens += er->nrecs - 1;
            er->nrecs = 1;
        }
        if (leftover <= 0)
            done = 1;
        oleftover = leftover;
        outp += er->encoded_len;
    }
    *num_echs = nlens;
    *echs = retechs;
    OPENSSL_free(ekcpy);
    return 1;

err:
    OPENSSL_free(outbuf);
    OPENSSL_free(ekcpy);
    SSL_ECH_free(retechs);
    OPENSSL_free(retechs);
    return 0;
}

/*
 * @brief Decode SVCB/HTTPS RR value provided as binary or ascii-hex
 * @param rrlen is the length of the rrval
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param echs is the returned array of SSL_ECH
 * @return is 1 for success, error otherwise
 *
 * The rrval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g.
 * OSSL_ECH_FMT_ASCII_HEX.
 *
 * Note that we "succeed" even if there is no ECHConfigs in the input - some
 * callers might download the RR from DNS and pass it here without looking
 * inside, and there are valid uses of such RRs. The caller can check though
 * using the num_echs output.
 */
static int local_svcb_add(int rrfmt, size_t rrlen, char *rrval,
                          int *num_echs, SSL_ECH **echs)
{
    int detfmt = OSSL_ECH_FMT_GUESS;
    int rv = 0;
    size_t binlen = 0; /* the RData */
    unsigned char *binbuf = NULL;
    size_t eklen = 0; /* the ECHConfigs, within the above */
    unsigned char *ekval = NULL;
    unsigned char *cp = NULL;
    size_t remaining = 0;
    char *dnsname = NULL;
    uint16_t pcode = 0;
    uint16_t plen = 0;
    int done = 0;

    if (rrfmt == OSSL_ECH_FMT_ASCIIHEX) {
        detfmt = rrfmt;
    } else if (rrfmt == OSSL_ECH_FMT_BIN) {
        detfmt = rrfmt;
        binlen = rrlen;
        binbuf = OPENSSL_malloc(binlen);
        if (binbuf == NULL) {
            return 0;
        }
        memcpy(binbuf, rrval, binlen);
    } else {
        rv = ech_guess_fmt(rrlen, (unsigned char *)rrval, &detfmt);
        if (rv == 0)
            return rv;
    }
    if (detfmt == OSSL_ECH_FMT_ASCIIHEX) {
        rv = ah_decode(rrlen, rrval, &binlen, &binbuf);
        if (rv == 0)
            return rv;
    } else if (detfmt == OSSL_ECH_FMT_B64TXT) {
        int ebd_rv = ech_base64_decode(rrval, &binbuf);

        if (ebd_rv <= 0)
            return 0;
        binlen = (size_t)ebd_rv;
    }
    /*
     * Now we have a binary encoded RData so we'll skip the
     * name, and then walk through the SvcParamKey binary
     * codes 'till we find what we want
     */
    cp = binbuf;
    remaining = binlen;
    /*
     * skip 2 octet priority and TargetName as those are the
     * application's responsibility, not the library's
     */
    if (remaining <= 2)
        goto err;
    cp += 2;
    remaining -= 2;
    rv = local_decode_rdata_name(&cp, &remaining, &dnsname);
    if (rv != 1)
        goto err;
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
        *num_echs = 0;
        OPENSSL_free(binbuf);
        return 1;
    }
    /* Parse & load any ECHConfigs that we found */
    rv = local_ech_add(OSSL_ECH_FMT_BIN, eklen, ekval, num_echs, echs);
    if (rv != 1)
        goto err;
    OPENSSL_free(binbuf);
    return 1;
err:
    OPENSSL_free(dnsname);
    OPENSSL_free(binbuf);
    return 0;
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
    /* Now decode that ECHConfigs */
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
 * @brief deep copy an ECHConfigs
 * @param old is the one to copy
 * @param new is the (caller allocated) place to copy-to
 * @return 1 for sucess, other otherwise
 */
static int ECHConfigs_dup(ECHConfigs *old, ECHConfigs *new)
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
 * @brief produce a printable string form of an ECHConfigs
 * @param out is where we print
 * @param c is the ECHConfigs
 * @return 1 for good, 0 for fail
 */
static int ECHConfigs_print(BIO *out, ECHConfigs *c)
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
 * Given a CH find the offsets of the session id, extensions and ECH
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
 * Note: input here can be untrusted!
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
    size_t origextlens = 0;
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
    /* if we're not TLSv1.3 then we can bail, but it's not an error */
    if (ch[0] != 0x03 || ch[1] != 0x03)
        return 1;
    /*
     * We'll start genoffset at the start of the session ID, just
     * before the ciphersuites
     */
    *sessid = CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE; /* point to len sessid */
    genoffset = *sessid;
    if (ch_len <= genoffset) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    sessid_len = ch[genoffset];
    /* sessid_len can be zero in encoded inner CH */
    genoffset += (1 + sessid_len);
    if (ch_len <= (genoffset + 2)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    suiteslen = ch[genoffset] * 256 + ch[genoffset + 1];

    if ((genoffset + suiteslen + 2 + 2) > ch_len) {
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

    startofexts = genoffset + suiteslen + 2 + 2; /* the 2 for the suites len */
    if (startofexts == ch_len)
        return 1; /* no extensions present, which is in theory fine */
    if (startofexts > ch_len) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    *exts = startofexts; /* set output */
    origextlens = ch[startofexts] * 256 + ch[startofexts + 1];
    if (ch_len < (startofexts + 2 + origextlens)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* find ECH if it's there */
    e_start = &ch[startofexts + 2];
    extsremaining = origextlens - 2;
    while (extsremaining > 0 && (*echoffset == 0 || *snioffset == 0)) {
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
            *echtype = etype;
            *echoffset = (e_start - ch); /* set output */
            if (etype == TLSEXT_TYPE_ech13) {
                if (ch_len < (5 + (size_t)(e_start - ch))) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                /* check if inner or outer type set */
                *inner = e_start[4];
            }
        } else if (etype == TLSEXT_TYPE_server_name) {
# ifdef OSSL_ECH_SUPERVERBOSE
            snilen = elen + 4; /* type and length included */
# endif
            *snioffset = (e_start - ch); /* set output */
        }
        e_start += (4 + elen);
        extsremaining -= (4 + elen);
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig CH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("orig CH", (unsigned char *)ch, ch_len);
    ech_pbuf("orig CH session_id", (unsigned char *)ch + *sessid + 1,
             sessid_len);
    ech_pbuf("orig CH exts", (unsigned char *)ch + *exts, origextlens);
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
 */
static int ech_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                              size_t *exts, size_t *echoffset,
                              uint16_t *echtype)
{
    size_t sessid_offset = 0;
    size_t sessid_len = 0;
    size_t startofexts = 0;
    size_t origextlens = 0;
    const unsigned char *e_start = NULL;
    int extsremaining = 0;
    uint16_t etype = 0;
    size_t elen = 0;
# ifdef OSSL_ECH_SUPERVERBOSE
    size_t echlen = 0; /* length of ECH, including type & ECH-internal length */
# endif

    if (sh == NULL || sh_len == 0 || exts == NULL || echoffset == NULL
        || echtype == NULL)
        return 0;
    *exts = 0;
    *echoffset = 0;
    *echtype = TLSEXT_TYPE_ech_unknown;
    sessid_offset = CLIENT_VERSION_LEN /* version */
        + 32                           /* random */
        + 1;                           /* sess_id_len */
    if (sh_len <= sessid_offset)
        return 0;
    sessid_len = (size_t)sh[sessid_offset - 1];
    startofexts = sessid_offset /* up to & incl. sessid_len */
        + sessid_len            /* sessid_len */
        + 2                     /* ciphersuite */
        + 1;                    /* legacy compression */
    if (sh_len < startofexts)
        return 0;
    if (sh_len == startofexts)
        return 1; /* no exts */
    *exts = startofexts;
    if (sh_len < (startofexts + 6))
        return 0; /* needs at least len+one-ext */
    origextlens = sh[startofexts] * 256 + sh[startofexts + 1];
    if (sh_len < (startofexts + 2 + origextlens))
        return 0; /* needs at least len+one-ext */
    /* find ECH if it's there */
    e_start = &sh[startofexts + 2];
    extsremaining = origextlens - 2;
    while (extsremaining > 0 && *echoffset == 0) {
        if (sh_len < (4 + (size_t)(e_start - sh)))
            return 0;
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
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig SH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("orig SH", (unsigned char *)sh, sh_len);
    ech_pbuf("orig SH session_id", (unsigned char *)sh + sessid_offset,
             sessid_len);
    ech_pbuf("orig SH exts", (unsigned char *)sh + *exts, origextlens);
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
 * The plaintext we start from is in s->ext.encoded_innerch
 * and our final decoded, decompressed buffer will end up
 * in s->ext.innerch (which'll then be further processed).
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
    uint16_t etype = 0;
    size_t elen = 0;
    int n_outers = 0;
    uint8_t slen = 0;
    const unsigned char *oval_buf = NULL;
    int i = 0, j = 0;
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

    if (s->ext.encoded_innerch == NULL || ob == NULL || ob_len == 0
        || outer_startofexts == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * We'll try decode s->ext.encoded_innerch into
     * s->ext.innerch, modulo s->ext.outers
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

    /* not sure this is needed, here anyway - seems arbitrary */
    if (ob_len <= (outer_startofexts + 2)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * add bytes for session ID and its length (1)
     * minus the length of the empty session ID (1)
     * that should be there already
     */
    initial_decomp_len = s->ext.encoded_innerch_len;
    initial_decomp_len += s->tmp_session_id_len;
    initial_decomp = OPENSSL_malloc(initial_decomp_len);
    if (initial_decomp == NULL)
        return 0;
    /*
     * Jump over the ciphersuites and (MUST be NULL) compression to
     * the start of extensions
     */
    offset2sessid = CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE;
    if (s->ext.encoded_innerch_len < (offset2sessid + 2)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    suiteslen = s->ext.encoded_innerch[offset2sessid + 1] * 256
        + s->ext.encoded_innerch[offset2sessid + 2];
    startofexts = offset2sessid + 1
        + s->tmp_session_id_len  /* skipping session id */
        + 2 + suiteslen          /* skipping suites */
        + 2;                     /* skipping NULL compression */
    if (startofexts >= initial_decomp_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    memcpy(initial_decomp, s->ext.encoded_innerch, offset2sessid);
    initial_decomp[offset2sessid] =
        (unsigned char)(s->tmp_session_id_len & 0xff);
    memcpy(initial_decomp + offset2sessid + 1, s->tmp_session_id,
           s->tmp_session_id_len);
    memcpy(initial_decomp + offset2sessid + 1 + s->tmp_session_id_len,
           s->ext.encoded_innerch + offset2sessid + 1,
           s->ext.encoded_innerch_len - offset2sessid - 1);
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
    oneextstart = startofexts + 2; /* 1st ext type, skip the overall exts len */
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
        if (s->ext.innerch != NULL) {
            OPENSSL_free(s->ext.innerch1);
            s->ext.innerch1 = s->ext.innerch;
            s->ext.innerch1_len = s->ext.innerch_len;
        }
        s->ext.innerch = final_decomp;
        s->ext.innerch_len = final_decomp_len;
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
    final_decomp[0] = 0x01;
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
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("final_decomp", final_decomp, final_decomp_len);
# endif
    /* handle HRR case where we (temporarily) store the old inner CH */
    if (s->ext.innerch != NULL) {
        if (s->ext.innerch1 != NULL)
            OPENSSL_free(s->ext.innerch1);
        s->ext.innerch1 = s->ext.innerch;
        s->ext.innerch1_len = s->ext.innerch_len;
    }
    s->ext.innerch = final_decomp;
    s->ext.innerch_len = final_decomp_len;
    OPENSSL_free(initial_decomp);
    initial_decomp = NULL;
    return 1;
err:
    OPENSSL_free(initial_decomp);
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

    if (s == NULL || s->ext.inner_s == NULL || tc == NULL)
        return 0;
    mnl = tc->maximum_name_length;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: ECHConfig had max name len of %zu\n", mnl);
    } OSSL_TRACE_END(TLS);
    if (mnl != 0) {
        /* do weirder padding if SNI present in inner */
        if (s->ext.inner_s->ext.hostname != NULL) {
            isnilen = strlen(s->ext.inner_s->ext.hostname) + 9;
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
        + s->ext.inner_s->ext.encoded_innerch_len;
    length_of_padding = 31 - ((length_with_snipadding - 1) % 32);
    length_with_padding = s->ext.inner_s->ext.encoded_innerch_len
        + length_of_padding + innersnipadding;
    /*
     * finally - make sure we're longer than padding target too
     * this is a local addition - might take it out if it makes
     * us stick out; or if we take out the above more complicated
     * scheme, we may only need this in the end (and that'd maybe
     * be better overall:-)
     */
    while (length_with_padding < OSSL_ECH_PADDING_TARGET)
        length_with_padding += OSSL_ECH_PADDING_INCREMENT;
    clear_len = length_with_padding;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: padding: mnl: %zu, lws: %d "
                   "lop: %d, lwp: %d, clear_len: %zu, orig: %zu\n",
                   mnl, length_with_snipadding, length_of_padding,
                   length_with_padding, clear_len,
                   s->ext.inner_s->ext.encoded_innerch_len);
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
 * @brief Free an ECHConfigs structure's internals
 * @param tbf is the thing to be free'd
 */
void ECHConfigs_free(ECHConfigs *tbf)
{
    int i;

    if (tbf == NULL)
        return;
    OPENSSL_free(tbf->encoded);
    for (i = 0; i != tbf->nrecs; i++)
        ECHConfig_free(&tbf->recs[i]);
    OPENSSL_free(tbf->recs);
    memset(tbf, 0, sizeof(ECHConfigs));
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
        ECHConfigs_free(tbf->cfg);
        OPENSSL_free(tbf->cfg);
    }
    OPENSSL_free(tbf->inner_name);
    OPENSSL_free(tbf->outer_name);
    OPENSSL_free(tbf->pemfname);
    EVP_PKEY_free(tbf->keyshare);
    memset(tbf, 0, sizeof(SSL_ECH));
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
    BIO_printf(out, "inner_s=%p\n", (void *)s->ext.inner_s);
    BIO_printf(out, "outer_s=%p\n", (void *)s->ext.outer_s);
# endif
    BIO_printf(out, "ech_attempted=%d\n", s->ext.ech_attempted);
    BIO_printf(out, "ech_attempted_type=0x%4x\n",
               s->ext.ech_attempted_type);
    if (s->ext.ech_attempted_cid == TLSEXT_TYPE_ech_config_id_unset)
        BIO_printf(out, "ech_atttempted_cid is unset\n");
    else
        BIO_printf(out, "ech_atttempted_cid=0x%02x\n",
                   s->ext.ech_attempted_cid);
    BIO_printf(out, "ech_done=%d\n", s->ext.ech_done);
    BIO_printf(out, "ech_grease=%d\n", s->ext.ech_grease);
# ifdef OSSL_ECH_SUPERVERBOSE
    BIO_printf(out, "HRR=%d\n", s->hello_retry_request);
    BIO_printf(out, "hrr_depth=%d\n", s->ext.hrr_depth);
    BIO_printf(out, "ech_returned=%p\n",
               (void *)s->ext.ech_returned);
# endif
    BIO_printf(out, "ech_returned_len=%ld\n",
               (long)s->ext.ech_returned_len);
    BIO_printf(out, "ech_backend=%d\n", s->ext.ech_backend);
    BIO_printf(out, "ech_success=%d\n", s->ext.ech_success);
    if (s->ech != NULL) {
        int i = 0;

        if (s->nechs == 1) {
            BIO_printf(out, "1 ECHConfig value loaded\n");
        } else {
            BIO_printf(out, "%d ECHConfig values loaded\n",
                       s->nechs);
        }
        for (i = 0; i != s->nechs; i++) {
            if (selector == OSSL_ECH_SELECT_ALL || selector == i) {
                BIO_printf(out, "cfg(%d): ", i);
                if (ECHConfigs_print(out, s->ech[i].cfg) == 1)
                    BIO_printf(out, "\n");
                else
                    BIO_printf(out, "NULL (huh?)\n");
                if (s->ech[i].keyshare != NULL) {
# define OSSL_ECH_TIME_STR_LEN 32 /* apparently 26 is all we need */
                    struct tm local, *local_p = NULL;
                    char lstr[OSSL_ECH_TIME_STR_LEN];
# if defined(OPENSSL_SYS_WINDOWS)
                    errno_t grv;
# endif

# if !defined(OPENSSL_SYS_WINDOWS)
                    local_p = gmtime_r(&s->ech[i].loadtime, &local);
                    if (local_p != &local) {
                        strcpy(lstr, "sometime");
                    } else {
                        int srv = strftime(lstr, OSSL_ECH_TIME_STR_LEN,
                                           "%c", &local);

                        if (srv == 0)
                            strcpy(lstr, "sometime");
                    }
# else
                    grv = gmtime_s(&local, &s->ech[i].loadtime);
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
                               s->ech[i].pemfname, lstr);
                }
            }
        }
    } else {
        BIO_printf(out, "cfg=NONE\n");
    }
    if (s->ext.ech_returned) {
        size_t i = 0;

        BIO_printf(out, "ret=");
        for (i = 0; i != s->ext.ech_returned_len; i++) {
            if ((i != 0) && (i % 16 == 0))
                BIO_printf(out, "\n    ");
            BIO_printf(out, "%02x:", (unsigned)(s->ext.ech_returned[i]));
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
        new_se[i].cfg = OPENSSL_malloc(sizeof(ECHConfigs));
        if (new_se[i].cfg == NULL)
            goto err;
        if (ECHConfigs_dup(orig[i].cfg, new_se[i].cfg) != 1)
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
 * @param ind is the index of this extension in ext_defs (and ech_outer_config)
 * @return 1 if this one is to be compressed, 0 if not, -1 for error
 */
int ech_2bcompressed(int ind)
{
    int nexts = OSSL_NELEM(ech_outer_config);

    if (ind < 0 || ind >= nexts)
        return -1;
    return ech_outer_config[ind];
}

/**
 * @brief repeat extension from inner in outer and handle compression
 * @param s is the SSL connection
 * @param pkt is the packet containing extensions
 * @return 0: error, 1: copied existing and done, 2: ignore existing
 */
int ech_same_ext(SSL_CONNECTION *s, WPACKET *pkt)
{
    SSL_CONNECTION *inner = NULL;
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

    if (s == NULL || s->ech == NULL)
        return OSSL_ECH_SAME_EXT_CONTINUE; /* nothing to do */
    inner = s->ext.inner_s;
    type = s->ext.etype;
    nexts = OSSL_NELEM(ech_outer_config);
    tind = ech_map_ext_type_to_ind(type);

    /* If this index'd extension won't be compressed, we're done */
    if (tind == -1)
        return OSSL_ECH_SAME_EXT_ERR;
    if (tind >= (int)nexts)
        return OSSL_ECH_SAME_EXT_ERR;

    if (s->ext.ch_depth == 1) {
        /* inner CH - just note compression as configured */
        if (ech_outer_config[tind] == 0)
            return OSSL_ECH_SAME_EXT_CONTINUE;
        if (s->ext.n_outer_only >= OSSL_ECH_OUTERS_MAX)
            return OSSL_ECH_SAME_EXT_ERR;
        /* mark this one to be "compressed" */
        s->ext.outer_only[s->ext.n_outer_only] = type;
        s->ext.n_outer_only++;
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "ech_same_ext: Marking ext (type %x,ind %d) "
                       "for compression\n", s->ext.etype, tind);
        } OSSL_TRACE_END(TLS);
        return OSSL_ECH_SAME_EXT_CONTINUE;
    }

    /* Copy value from inner to outer, or indicate a new value needed */
    if (s->ext.ch_depth == 0) {
        if (inner->clienthello == NULL || pkt == NULL)
            return OSSL_ECH_SAME_EXT_ERR;
        if (ech_outer_indep[tind] != 0) {
            /* continue processing, meaning get a new value */
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "ech_same_ext: New outer value for ext "
                           "type %x,ind %d)\n", s->ext.etype, tind);
            } OSSL_TRACE_END(TLS);
            return OSSL_ECH_SAME_EXT_CONTINUE;
        } else {
            size_t ind = 0;
            RAW_EXTENSION *myext = NULL;
            RAW_EXTENSION *raws = inner->clienthello->pre_proc_exts;
            size_t nraws = 0;

            if (raws == NULL)
                return OSSL_ECH_SAME_EXT_ERR;
            nraws = inner->clienthello->pre_proc_exts_len;
            /* copy inner to outer */
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "ech_same_ext: Copying ext "
                           "(type %x,ind %d) to outer\n", s->ext.etype, tind);
            } OSSL_TRACE_END(TLS);
            for (ind = 0; ind != nraws; ind++) {
                if (raws[ind].type == type) {
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
                if (!WPACKET_put_bytes_u16(pkt, type)
                    || !WPACKET_sub_memcpy_u16(pkt, PACKET_data(&myext->data),
                                               PACKET_remaining(&myext->data)))
                    return OSSL_ECH_SAME_EXT_ERR;
            } else {
                /* empty extension */
                if (!WPACKET_put_bytes_u16(pkt, type)
                    || !WPACKET_put_bytes_u16(pkt, 0))
                    return OSSL_ECH_SAME_EXT_ERR;
            }
            /* we've done the copy so we're done */
            return OSSL_ECH_SAME_EXT_DONE;
        }
    }
    /* just in case - shouldn't happen */
    return OSSL_ECH_SAME_EXT_ERR;
}

/**
 * @brief After "normal" 1st pass CH is done, fix encoding as needed
 * @param ssl is the SSL connection
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

    /* basic checks */
    if (s == NULL || s->ech == NULL)
        return 0;

    /*
     * encode s->ext.innerch into s->ext.encoded_innerch,
     * and handle ECH-compression
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
        || !WPACKET_memcpy(&inner, s->s3.client_random, SSL3_RANDOM_SIZE)
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
    /* Grab a pointer to the alraedy constructed extensions */
    raws = s->clienthello->pre_proc_exts;
    nraws = s->clienthello->pre_proc_exts_len;

    /*  We put ECH-compressed stuff first (if any), because we can */
    if (s->ext.n_outer_only > 0) {
        if (!WPACKET_put_bytes_u16(&inner, TLSEXT_TYPE_outer_extensions)
            || !WPACKET_put_bytes_u16(&inner, 2 * s->ext.n_outer_only + 1)
            /* redundant encoding of more-or-less the same thing */
            || !WPACKET_put_bytes_u8(&inner, 2 * s->ext.n_outer_only)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* add the types for each of the compressed extensions now */
        for (ind = 0; ind != s->ext.n_outer_only; ind++) {
            if (!WPACKET_put_bytes_u16(&inner, s->ext.outer_only[ind])) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    /* now copy the rest, as "proper" exts, into encoded inner */
    for (ind = 0; ind != nraws; ind++) {
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
    s->ext.encoded_innerch = innerch_full;
    s->ext.encoded_innerch_len = innerinnerlen - 4;
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
        chbuf = s->ext.innerch;
        chlen = s->ext.innerch_len;
    } else if (for_hrr == 0 && (s->hello_retry_request == SSL_HRR_PENDING ||
                                s->hello_retry_request == SSL_HRR_COMPLETE)) {
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("calc conf : innerch1", s->ext.innerch1, s->ext.innerch1_len);
# endif
        /*
         * make up mad odd transcript manually, for now: that's
         * hashed-inner-CH1, then (non-hashed) HRR and inner-CH2
         */
        if (EVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVP_DigestUpdate(ctx, s->ext.innerch1, s->ext.innerch1_len) <= 0
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
        ech_pbuf("calc conf : kepthrr", s->ext.kepthrr, s->ext.kepthrr_len);
# endif
        chlen = digestedCH_len + 4 + s->ext.kepthrr_len + s->ext.innerch_len;
        longtrans = OPENSSL_malloc(chlen);
        if (longtrans == NULL)
            goto err;
        memcpy(longtrans, digestedCH, digestedCH_len);
        if (s->server == 0) {
            longtrans[digestedCH_len] = SSL3_MT_SERVER_HELLO;
            longtrans[digestedCH_len + 1] = (s->ext.kepthrr_len >> 16) & 0xff;
            longtrans[digestedCH_len + 2] = (s->ext.kepthrr_len >> 8) & 0xff;
            longtrans[digestedCH_len + 3] = s->ext.kepthrr_len & 0xff;
            memcpy(longtrans + digestedCH_len + 4,
                   s->ext.kepthrr, s->ext.kepthrr_len);
            memcpy(longtrans + digestedCH_len + 4 + s->ext.kepthrr_len,
                   s->ext.innerch, s->ext.innerch_len);
        } else {
            chlen -= 4;
            memcpy(longtrans + digestedCH_len, s->ext.kepthrr,
                   s->ext.kepthrr_len);
            memcpy(longtrans + digestedCH_len + s->ext.kepthrr_len,
                   s->ext.innerch, s->ext.innerch_len);
        }
        chbuf = longtrans;
    } else {
        /* stash HRR for later */
        s->ext.kepthrr = OPENSSL_malloc(shlen);
        if (s->ext.kepthrr == NULL)
            goto err;
        memcpy(s->ext.kepthrr, shbuf, shlen);
        if (s->server != 0) {
            s->ext.kepthrr[1] = ((shlen - 4) >> 16) & 0xff;
            s->ext.kepthrr[2] = ((shlen - 4) >> 8) & 0xff;
            s->ext.kepthrr[3] = (shlen - 4) & 0xff;
        }
        s->ext.kepthrr_len = shlen;
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("calc conf : kepthrr", s->ext.kepthrr, s->ext.kepthrr_len);
# endif
        if (EVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVP_DigestUpdate(ctx, s->ext.innerch, s->ext.innerch_len) <= 0
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
    ech_pbuf("calc conf : innerch", s->ext.innerch, s->ext.innerch_len);
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

    if (s->ext.ech_attempted_type == OSSL_ECH_DRAFT_13_VERSION) {
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
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, s->s3.client_random,
                                       SSL3_RANDOM_SIZE) != 1) {
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
    if (s->hello_retry_request == SSL_HRR_NONE && s->ext.ech_backend != 0)
        ech_reset_hs_buffer(s, s->ext.innerch, s->ext.innerch_len);

    if (s->hello_retry_request == SSL_HRR_NONE && s->ext.ech_backend == 0)
        ech_reset_hs_buffer(s, s->ext.innerch, s->ext.innerch_len);

    if (for_hrr == 1) {
        /* whack confirm value into stored version of hrr */
        memcpy(s->ext.kepthrr + s->ext.kepthrr_len - 8, acbuf, 8);
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
    SSL_CONNECTION *inp = NULL;
    SSL_CONNECTION *outp = NULL;
    SSL_CONNECTION tmp_outer;
    SSL_CONNECTION tmp_inner;
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
    if (s == NULL || s->ext.inner_s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    inp = s->ext.inner_s;
    outp = s->ext.inner_s->ext.outer_s;
    if (!ossl_assert(outp == s))
        return 0;

    /* Stash fields */
    tmp_outer = *s;
    tmp_inner = *inp;

    /* General field swap */
    *s = tmp_inner;
    *inp = tmp_outer;
    /* fix up new inner/outer pointers */
    s->ext.outer_s = inp;
    s->ext.inner_s = NULL;
    s->ext.outer_s->ext.inner_s = s;
    s->ext.outer_s->ext.outer_s = NULL;

    /* Copy and up-ref readers and writers */
    s->wbio = tmp_outer.wbio;
    BIO_up_ref(s->wbio);
    s->rbio = tmp_outer.rbio;
    BIO_up_ref(s->rbio);
    s->bbio = tmp_outer.bbio;

    /* fix buffers and record layers */
    s->init_buf = tmp_outer.init_buf;
    s->init_msg = tmp_outer.init_msg;
    s->init_off = tmp_outer.init_off;
    s->init_num = tmp_outer.init_num;
    s->rlayer = tmp_outer.rlayer;
    memset(&inp->rlayer, 0, sizeof(tmp_outer.rlayer));

    /* HRR processing */
    s->hello_retry_request = tmp_outer.hello_retry_request;

    /*  lighttpd failure case implies I need this */
    s->handshake_func = tmp_outer.handshake_func;

    /* fix callbacks and state */
    s->ext.debug_cb = tmp_outer.ext.debug_cb;
    s->ext.debug_arg = tmp_outer.ext.debug_arg;
    s->statem = tmp_outer.statem;

    /* Used by CH callback in lighttpd */
    s->ssl.ex_data = tmp_outer.ssl.ex_data;

    /* early data */
    s->early_data_state = tmp_outer.early_data_state;
    s->early_data_count = tmp_outer.early_data_count;

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
        curr_buflen = BIO_get_mem_data(tmp_outer.s3.handshake_buffer,
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
                new_buflen = tmp_outer.ext.innerch_len + other_octets;
                new_buf = OPENSSL_malloc(new_buflen);
                if (new_buf == NULL)
                    return 0;
                if (tmp_outer.ext.innerch != NULL) /* asan check added */
                    memcpy(new_buf, tmp_outer.ext.innerch,
                           tmp_outer.ext.innerch_len);
                memcpy(new_buf + tmp_outer.ext.innerch_len,
                       &curr_buf[outer_chlen], other_octets);
            } else {
                new_buf = tmp_outer.ext.innerch;
                new_buflen = tmp_outer.ext.innerch_len;
            }
        } else {
            new_buf = tmp_outer.ext.innerch;
            new_buflen = tmp_outer.ext.innerch_len;
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
    s->ext.outer_s->ext.ech_attempted = 1;
    s->ext.ech_attempted = 1;
    s->ext.ech_attempted_type = s->ext.outer_s->ext.ech_attempted_type;
    s->ext.ech_attempted_cid = s->ext.outer_s->ext.ech_attempted_cid;
    s->ext.outer_s->ext.ech_success = 1;
    s->ext.ech_success = 1;
    s->ext.outer_s->ext.ech_done = 1;
    s->ext.ech_done = 1;
    s->ext.outer_s->ext.ech_grease = OSSL_ECH_NOT_GREASE;
    s->ext.ech_grease = OSSL_ECH_NOT_GREASE;

    /* call ECH callback */
    if (s->ech != NULL && s->ext.ech_done == 1
        && s->hello_retry_request != SSL_HRR_PENDING
        && s->ech_cb != NULL) {
        char pstr[OSSL_ECH_PBUF_SIZE + 1];
        BIO *biom = BIO_new(BIO_s_mem());
        unsigned int cbrv = 0;

        memset(pstr, 0, OSSL_ECH_PBUF_SIZE + 1);
        SSL_ech_print(biom, &s->ssl, OSSL_ECH_SELECT_ALL);
        BIO_read(biom, pstr, OSSL_ECH_PBUF_SIZE);
        cbrv = s->ech_cb(&s->ssl, pstr);
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
    size_t cipher_len = OSSL_ECH_DEF_CIPHER_LEN;
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
    WPACKET_get_total_written(pkt, &pp_at_start);
    /* generate a random (1 octet) client id */
    if (RAND_bytes_ex(s->ssl.ctx->libctx, &cid, cid_len,
                      RAND_DRBG_STRENGTH) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    s->ext.ech_attempted_cid = cid;
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
    if (s->ext.ech_grease_suite != NULL) {
        if (OSSL_HPKE_str2suite(s->ext.ech_grease_suite, &hpke_suite_in) != 1) {
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
    if (s->ext.ech_attempted_type == OSSL_ECH_DRAFT_13_VERSION) {
        if (!WPACKET_put_bytes_u16(pkt, s->ext.ech_attempted_type)
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
    OPENSSL_free(s->ext.ech_sent);
    WPACKET_get_total_written(pkt, &pp_at_end);
    s->ext.ech_sent_len = pp_at_end - pp_at_start;
    s->ext.ech_sent = OPENSSL_malloc(s->ext.ech_sent_len);
    if (s->ext.ech_sent == NULL)
        return 0;
    memcpy(s->ext.ech_sent, pp, s->ext.ech_sent_len);
    s->ext.ech_grease = OSSL_ECH_IS_GREASE;
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
                          OSSL_HPKE_SUITE *suite)
{
    unsigned int onlen = 0;
    int namematch = 0;
    int suitematch = 0;
    int cind = 0;
    unsigned int csuite = 0;
    ECHConfig *ltc = NULL;
    ECHConfigs *cfgs = NULL;
    unsigned char *es = NULL;

    if (s == NULL || s->ech == NULL || tc == NULL || suite == NULL)
        return 0;
    cfgs = s->ech->cfg;
    if (cfgs == NULL || cfgs->nrecs == 0) {
        return 0;
    }
    onlen = (s->ech->outer_name == NULL ? 0 : strlen(s->ech->outer_name));
    for (cind = 0;
         cind != cfgs->nrecs && suitematch == 0 && namematch == 0;
         cind++) {
        ltc = &cfgs->recs[cind];
        if (ltc->version != OSSL_ECH_DRAFT_13_VERSION)
            continue;
        namematch = 0;
        if (onlen == 0
            || (ltc->public_name_len == onlen
                && !OPENSSL_strncasecmp(s->ech->outer_name,
                                        (char *)ltc->public_name, onlen))) {
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

    if (s == NULL || s->ech == NULL || pkt == NULL || s->ssl.ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* do this check separately for now as it may well change */
    if (s->ext.inner_s == NULL || s->ext.inner_s->ech == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = ech_pick_matching_cfg(s, &tc, &hpke_suite);
    if (rv != 1 || tc == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    s->ext.ech_attempted_type = tc->version;
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
    s->ext.ech_attempted_cid = config_id_to_use;
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: peer pub", tc->pub, tc->pub_len);
    ech_pbuf("EAAE: clear", s->ext.inner_s->ext.encoded_innerch,
             s->ext.inner_s->ext.encoded_innerch_len);
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
    if (s->ext.ech_ctx == NULL) {
        if (ech_make_enc_info(tc, info, &info_len) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        s->ext.ech_ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                           OSSL_HPKE_ROLE_SENDER, NULL, NULL);
        if (s->ext.ech_ctx == NULL) {
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
        rv = OSSL_HPKE_encap(s->ext.ech_ctx, mypub, &mypub_len,
                             tc->pub, tc->pub_len, info, info_len);
        if (rv != 1) {
            OPENSSL_free(mypub);
            mypub = NULL;
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        s->ext.ech_pub = mypub;
        s->ext.ech_pub_len = mypub_len;
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("EAAE: mypub", mypub, mypub_len);
# endif
    } else {
        /* retrieve public */
        mypub = s->ext.ech_pub;
        mypub_len = s->ext.ech_pub_len;
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
    memcpy(clear, s->ext.inner_s->ext.encoded_innerch,
           s->ext.inner_s->ext.encoded_innerch_len);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: draft-13 padded clear", clear, clear_len);
# endif
    rv = OSSL_HPKE_seal(s->ext.ech_ctx, cipher, &cipherlen,
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

/**
 * @brief If an ECH is present, attempt decryption
 * @param ssl: SSL session stuff
 * @prarm outerpkt is the packet with the outer CH
 * @prarm newpkt is the packet with the decrypted inner CH
 * @return 1 for success, other otherwise
 *
 * If decryption succeeds, then we'll swap the inner and outer
 * CHs so that all further processing will only take into account
 * the inner CH.
 *
 * The fact that decryption worked is signalled to the caller
 * via s->ext.ech_success
 *
 * This function is called early, (hence then name:-), before
 * the outer CH decoding has really started
 *
 * The plan:
 * 1. check if there's an ECH
 * 2. trial-decrypt or check if config matches one loaded
 * 3. if decrypt fails tee-up GREASE
 * 4. if decrypt worked, decode and de-compress cleartext to
 *    make up real inner CH for later processing
 */
int ech_early_decrypt(SSL *ssl, PACKET *outerpkt, PACKET *newpkt)
{
    int rv = 0;
    OSSL_ECH_ENCCH *extval = NULL;
    PACKET echpkt;
    PACKET *pkt = NULL;
    const unsigned char *startofech = NULL;
    size_t echlen = 0;
    size_t clearlen = 0;
    unsigned char *clear = NULL;
    unsigned int tmp;
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
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
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
    s->ext.ech_attempted = 1;
    s->ext.ech_attempted_type = echtype;
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
        if (s->ech->outer_name != NULL) {
            /* can happen with HRR */
            OPENSSL_free(s->ech->outer_name);
        }
        s->ech->outer_name = s->ext.hostname;
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "EARLY: outer SNI of %s\n", s->ext.hostname);
        } OSSL_TRACE_END(TLS);
        /* clean up  */
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
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->kdf_id = tmp & 0xffff;
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->aead_id = tmp & 0xffff;

    /* config id */
    if (!PACKET_copy_bytes(pkt, &extval->config_id, 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EARLY config id", &extval->config_id, 1);
# endif
    s->ext.ech_attempted_cid = extval->config_id;

    /* enc - the client's public share */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > OSSL_ECH_MAX_GREASE_PUB) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp == 0 && s->hello_retry_request != SSL_HRR_PENDING) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    } else if (tmp == 0 && s->hello_retry_request == SSL_HRR_PENDING) {
        if (s->ext.ech_pub == NULL || s->ext.ech_pub_len == 0) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        extval->enc_len = s->ext.ech_pub_len;
        extval->enc = OPENSSL_malloc(extval->enc_len);
        if (extval->enc == NULL)
            goto err;
        memcpy(extval->enc, s->ext.ech_pub, extval->enc_len);
    } else {
        extval->enc_len = tmp;
        extval->enc = OPENSSL_malloc(tmp);
        if (extval->enc == NULL)
            goto err;
        if (!PACKET_copy_bytes(pkt, extval->enc, tmp)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        /* squirrel away that value in case of future HRR */
        OPENSSL_free(s->ext.ech_pub);
        s->ext.ech_pub_len = extval->enc_len;
        s->ext.ech_pub_len = extval->enc_len;
        s->ext.ech_pub = OPENSSL_malloc(extval->enc_len);
        if (s->ext.ech_pub == NULL)
            goto err;
        memcpy(s->ext.ech_pub, extval->enc, extval->enc_len);
    }

    /* payload - the encrypted CH */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > OSSL_ECH_MAX_PAYLOAD_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->payload_len = tmp;
    extval->payload = OPENSSL_malloc(tmp);
    if (extval->payload == NULL)
        goto err;
    if (!PACKET_copy_bytes(pkt, extval->payload, tmp)) {
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
        if (s->ext.ech_pub == NULL || s->ext.ech_pub_len == 0) {
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
    s->ext.ech_grease = OSSL_ECH_GREASE_UNKNOWN;

    if (s->ech->cfg == NULL || s->ech->cfg->nrecs == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    for (cfgind = 0; cfgind != s->nechs; cfgind++) {
        ECHConfig *e = &s->ech[cfgind].cfg->recs[0];

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
    if (s->ext.encoded_innerch != NULL) {
        /* this happens with HRR */
        OPENSSL_free(s->ext.encoded_innerch);
        s->ext.encoded_innerch = NULL;
        s->ext.encoded_innerch_len = 0;
    }
    if (foundcfg == 1) {
        clear = hpke_decrypt_encch(s, &s->ech[cfgind], extval, aad_len, aad,
                                   forhrr, &clearlen);
        if (clear == NULL) {
            s->ext.ech_grease = OSSL_ECH_IS_GREASE;
        }
    }

    /* Trial decrypt, if still needed */
    if (clear == NULL && (s->options & SSL_OP_ECH_TRIALDECRYPT)) {
        foundcfg = 0; /* reset as we're trying again */
        for (cfgind = 0; cfgind != s->nechs; cfgind++) {
            clear = hpke_decrypt_encch(s, &s->ech[cfgind], extval,
                                       aad_len, aad,
                                       forhrr, &clearlen);
            if (clear != NULL) {
                foundcfg = 1;
                s->ext.ech_grease = OSSL_ECH_NOT_GREASE;
                break;
            }
        }
    }

    /*
     * We succeeded or failed in decrypting, but we're done
     * with that now.
     */
    s->ext.ech_done = 1;

    /* 3. if decrypt fails tee-up GREASE */
    if (clear == NULL) {
        s->ext.ech_grease = OSSL_ECH_IS_GREASE;
        s->ext.ech_success = 0;
    } else {
        s->ext.ech_grease = OSSL_ECH_NOT_GREASE;
        s->ext.ech_success = 1;
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EARLY: success: %d, assume_grease: %d, "
                   "foundcfg: %d, cfgind: %d, clearlen: %zd, clear %p\n",
                   s->ext.ech_success, s->ext.ech_grease, foundcfg,
                   cfgind, clearlen, (void *)clear);
    } OSSL_TRACE_END(TLS);

# ifdef OSSL_ECH_SUPERVERBOSE
    /* Bit more logging */
    if (foundcfg == 1 && clear != NULL) {
        SSL_ECH *se = &s->ech[cfgind];
        ECHConfigs *seg = se->cfg;
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

    if (s->ext.ech_grease == OSSL_ECH_IS_GREASE)
        return 1;

    /*
     * 4. if decrypt worked, de-compress cleartext to make up real inner CH
     */
    s->ext.encoded_innerch = clear;
    s->ext.encoded_innerch_len = clearlen;
    if (ech_decode_inner(s, ch, ch_len, startofexts) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("Inner CH (decoded)", s->ext.innerch, s->ext.innerch_len);
# endif
    /*
     * The +4 below is because tls_process_client_hello doesn't
     * want to be given the message type & length, so the buffer should
     * start with the version octets (0x03 0x03)
     */
    if (PACKET_buf_init(newpkt, s->ext.innerch + 4,
                        s->ext.innerch_len - 4) != 1) {
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

/**
 * @brief check which SNI to send when doing ECH
 * @param s is the SSL context
 * @return 1 for success
 *
 * An application can set inner and/or outer SNIs.
 * Or it might only set one and we may have a
 * public_name from an ECHConfig.
 * Or an application may say to not send an outer
 * or inner SNI at all.
 *
 * If the application states a preferece we'll
 * abide by that, despite the public_name from
 * an ECHConfig.
 *
 * This function fixes those up to ensure that
 * the s->ext.hostname as desired for a client.
 */
int ech_server_name_fixup(SSL_CONNECTION *s)
{
    char *pn = NULL;
    size_t pn_len = 0;
    size_t in_len = 0;
    size_t on_len = 0;
    size_t ehn_len = 0;

    if (s == NULL || s->ech == NULL)
        return 0;

    if (s->ech->cfg->recs != NULL) {
        /* at this point we only handle one on the client */
        if (s->ech->cfg->nrecs != 1)
            return 0;
        pn_len = s->ech->cfg->recs[0].public_name_len;
        pn = (char *)s->ech->cfg->recs[0].public_name;
    }
    /* These are from the application, direct */
    in_len = (s->ech->inner_name == NULL ? 0 :
              OPENSSL_strnlen(s->ech->inner_name, TLSEXT_MAXLEN_host_name));
    on_len = (s->ech->outer_name == NULL ? 0 :
              OPENSSL_strnlen(s->ech->outer_name, TLSEXT_MAXLEN_host_name));
    /* in cae there's a value set already (legacy app calls can do) */
    ehn_len = (s->ext.hostname == NULL ? 0 :
               OPENSSL_strnlen(s->ext.hostname, TLSEXT_MAXLEN_host_name));
    if (s->ext.ch_depth == 1) { /* Inner CH */
        if (in_len != 0) {
            /* we prefer this over all */
            if (ehn_len != 0) {
                OPENSSL_free(s->ext.hostname);
                s->ext.hostname = NULL;
                ehn_len = 0;
            }
            s->ext.hostname = OPENSSL_strdup(s->ech->inner_name);
        }
        /* otherwise we leave the s->ext.hostname alone */
    }
    if (s->ext.ch_depth == 0) { /* Outer CH */
        if (on_len != 0) {
            if (ehn_len != 0) {
                OPENSSL_free(s->ext.hostname);
                s->ext.hostname = NULL;
                ehn_len = 0;
            }
            s->ext.hostname = OPENSSL_strdup(s->ech->outer_name);
        } else if (pn_len != 0) {
            if (ehn_len != 0) {
                OPENSSL_free(s->ext.hostname);
                s->ext.hostname = NULL;
                ehn_len = 0;
            }
            s->ext.hostname = OPENSSL_strndup(pn, pn_len);
        } else { /* don't send possibly sensitive inner in outer! */
            if (ehn_len != 0) {
                OPENSSL_free(s->ext.hostname);
                s->ext.hostname = NULL;
                ehn_len = 0;
            }
        }
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

int SSL_ech_set1_echconfig(SSL *s, int *num_echs,
                           int ekfmt, char *ekval, size_t eklen)
{
    SSL_ECH *echs = NULL;
    SSL_CONNECTION *con = SSL_CONNECTION_FROM_SSL(s);
    SSL_ECH *tmp = NULL;

    if (con == NULL || ekval == NULL || eklen == 0 || num_echs == NULL) {
        SSLfatal(con, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (local_ech_add(ekfmt, eklen, (unsigned char *)ekval,
                      num_echs, &echs) != 1) {
        SSLfatal(con, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (con->ech == NULL) {
        con->ech = echs;
        con->nechs = *num_echs;
        con->ext.ech_attempted = 1;
        con->ext.ech_attempted_type = TLSEXT_TYPE_ech_unknown;
        con->ext.ech_attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
        return 1;
    }
    /* otherwise accumulate */
    tmp = OPENSSL_realloc(con->ech,
                          (con->nechs + *num_echs) * sizeof(SSL_ECH));
    if (tmp == NULL)
        return 0;
    con->ech = tmp;
    /* shallow copy top level, keeping lower levels */
    memcpy(&con->ech[con->nechs], echs, *num_echs * sizeof(SSL_ECH));
    con->nechs += *num_echs;
    *num_echs = con->nechs;
    OPENSSL_free(echs);
    return 1;
}

int SSL_CTX_ech_set1_echconfig(SSL_CTX *ctx, int *num_echs,
                               int ekfmt, char *ekval, size_t eklen)
{
    SSL_ECH *echs = NULL;
    SSL_ECH *tmp = NULL;

    if (ctx == NULL || ekval == NULL || eklen == 0 || num_echs == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (local_ech_add(ekfmt, eklen, (unsigned char *)ekval,
                      num_echs, &echs) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->ext.ech == NULL) {
        ctx->ext.ech = echs;
        ctx->ext.nechs = *num_echs;
        return 1;
    }
    /* otherwise accumulate */
    tmp = OPENSSL_realloc(ctx->ext.ech,
                          (ctx->ext.nechs + *num_echs) * sizeof(SSL_ECH));
    if (tmp == NULL)
        return 0;
    ctx->ext.ech = tmp;
    /* shallow copy top level, keeping lower levels */
    memcpy(&ctx->ext.ech[ctx->ext.nechs], echs, *num_echs * sizeof(SSL_ECH));
    ctx->ext.nechs += *num_echs;
    *num_echs = ctx->ext.nechs;
    OPENSSL_free(echs);
    return 1;
}

/**
 * @brief Decode/store SVCB/HTTPS RR binary or ascii-hex encoded value
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param ssl is the SSL session
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param rrlen is the length of the rrval
 * @return is 1 for success, error otherwise
 *
 * The input rrval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later) use whichever is
 * relevant/best. The fmt parameter can be e.g. OSSL_ECH_FMT_ASCII_HEX
 *
 * This API is additive, i.e. values from multiple calls will be merged, but
 * not that the merge isn't clever so the application would need to take that
 * into account if it cared about priority.
 *
 * In the case of decoding error, any existing ECHConfigs are unaffected.
 */
int SSL_ech_set1_svcb(SSL *ssl, int *num_echs,
                      int rrfmt, char *rrval, size_t rrlen)
{
    SSL_ECH *new_echs = NULL;
    int num_new = 0;
    SSL_ECH *all_echs = NULL;
    int i = 0;
    SSL_CONNECTION *con = SSL_CONNECTION_FROM_SSL(ssl);

    if (ssl == NULL || con == NULL || rrval == NULL || num_echs == NULL
        || rrlen == 0) {
        SSLfatal(con, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (local_svcb_add(rrfmt, rrlen, rrval, &num_new, &new_echs) != 1) {
        SSLfatal(con, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (num_new == 0) {
        *num_echs = con->nechs;
        return 1;
    }
    /* merge new and old */
    all_echs = OPENSSL_realloc(con->ech,
                               (con->nechs + num_new) * sizeof(SSL_ECH));
    if (all_echs == NULL) {
        for (i = 0; i != num_new; i++)
            SSL_ECH_free(&new_echs[i]);
        OPENSSL_free(new_echs);
        return 0;
    }
    con->ech = all_echs;
    for (i = 0; i != num_new; i++)
        con->ech[con->nechs + i] = new_echs[i]; /* struct  copy */
    OPENSSL_free(new_echs);
    con->nechs += num_new;
    *num_echs = con->nechs;
    return 1;
}

int SSL_ech_set_server_names(SSL *ssl, const char *inner_name,
                             const char *outer_name, int no_outer)
{
    int nind = 0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    /*
     * Note: we could not require s->ech to be set already here but
     * seems just as reasonable to impose an ordering on the sequence
     * of calls. (And it means we don't need somewhere to stash the
     * names outside of the s->ech array.)
     * Same applies to SSL_ech_set_outer_server_name()
     */
    if (s == NULL || s->ech == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    for (nind = 0; nind != s->nechs; nind++) {
        OPENSSL_free(s->ech[nind].outer_name);
        if (inner_name != NULL && strlen(inner_name) > 0)
            s->ech[nind].inner_name = OPENSSL_strdup(inner_name);
        else
            s->ech[nind].inner_name = NULL;
        OPENSSL_free(s->ech[nind].outer_name);
        if (outer_name != NULL && strlen(outer_name) > 0) {
            s->ech[nind].outer_name = OPENSSL_strdup(outer_name);
        } else {
            if (outer_name == NULL && no_outer == 1)
                s->ech[nind].no_outer = 1;
            else
                s->ech[nind].outer_name = NULL;
        }
    }
    s->ext.ech_attempted = 1;
    s->ext.ech_attempted_type = TLSEXT_TYPE_ech_unknown;
    s->ext.ech_attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
    return 1;
}

int SSL_ech_set_outer_server_name(SSL *ssl, const char *outer_name,
                                  int no_outer)
{
    int nind = 0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    /*
     * Note: we could not require s->ech to be set already here but
     * seems just as reasonable to impose an ordering on the sequence
     * of calls. (And it means we don't need somewhere to stash the
     * names outside of the s->ech array.)
     * Same applies to SSL_ech_set_server_names()
     */
    if (s == NULL || s->ech == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    for (nind = 0; nind != s->nechs; nind++) {
        OPENSSL_free(s->ech[nind].outer_name);
        if (outer_name != NULL && strlen(outer_name) > 0) {
            s->ech[nind].outer_name = OPENSSL_strdup(outer_name);
        } else {
            if (outer_name == NULL && no_outer == 1)
                s->ech[nind].no_outer = 1;
            else
                s->ech[nind].outer_name = NULL;
        }
        /* if this is called and an SNI is set already we copy that to inner */
        if (s->ext.hostname != NULL) {
            OPENSSL_free(s->ech[nind].inner_name);
            s->ech[nind].inner_name = OPENSSL_strdup(s->ext.hostname);
        }
    }
    s->ext.ech_attempted = 1;
    s->ext.ech_attempted_type = TLSEXT_TYPE_ech_unknown;
    s->ext.ech_attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
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
    indices = s->nechs;
    if (s->ech == NULL || s->nechs <= 0) {
        *out = NULL;
        *nindices = 0;
        return 1;
    }
    rdiff = OPENSSL_zalloc(s->nechs * sizeof(OSSL_ECH_INFO));
    if (rdiff == NULL)
        goto err;
    for (i = 0; i != s->nechs; i++) {
        OSSL_ECH_INFO *inst = &rdiff[i];

        if (s->ech->inner_name != NULL) {
            inst->inner_name = OPENSSL_strdup(s->ech->inner_name);
            if (inst->inner_name == NULL)
                goto err;
        }
        if (s->ech->outer_name != NULL) {
            inst->public_name = OPENSSL_strdup(s->ech->outer_name);
            if (inst->public_name == NULL)
                goto err;
        }
        if (s->ext.alpn != NULL) {
            inst->inner_alpns = alpn_print(s->ext.alpn, s->ext.alpn_len);
        }
        if (s->ext.alpn_outer != NULL) {
            inst->outer_alpns = alpn_print(s->ext.alpn_outer,
                                           s->ext.alpn_outer_len);
        }
        /* Now "print" the ECHConfig(s) */
        if (s->ech[i].cfg != NULL) {
            size_t ehlen;
            unsigned char *ignore = NULL;

            tbio = BIO_new(BIO_s_mem());
            if (tbio == NULL)
                goto err;
            if (ECHConfigs_print(tbio, s->ech[i].cfg) != 1)
                goto err;
            ehlen = BIO_get_mem_data(tbio, &ignore);
            inst->echconfig = OPENSSL_malloc(ehlen + 1);
            if (inst->echconfig == NULL)
                goto err;
            if (BIO_read(tbio, inst->echconfig, ehlen) <= 0)
                goto err;
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
    int i = 0;

    if (s == NULL || index < 0 || s->ech == NULL || s->nechs <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (s->nechs <= index) {
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
    *new = s->ech[index];
    memset(&s->ech[index], 0, sizeof(SSL_ECH));
    for (i = 0; i != s->nechs; i++)
        SSL_ECH_free(&s->ech[i]);
    OPENSSL_free(s->ech);
    s->ech = new;
    s->nechs = 1;
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

int SSL_CTX_ech_server_flush_keys(SSL_CTX *ctx, time_t age)
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
        SSL_ECH_free(ctx->ext.ech);
        OPENSSL_free(ctx->ext.ech);
        ctx->ext.ech = NULL;
        ctx->ext.nechs = 0;
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "Flushed all %d ECH keys at %lu\n", orig, now);
        } OSSL_TRACE_END(TLS);
        return 1;
    }
    /* Otherwise go through them and delete as needed */
    for (i = 0; i != ctx->ext.nechs; i++) {
        SSL_ECH *ep = &ctx->ext.ech[i];

        if ((ep->loadtime + age) <= now) {
            SSL_ECH_free(ep);
            deleted++;
            continue;
        }
        ctx->ext.ech[i - deleted] = ctx->ext.ech[i]; /* struct copy! */
    }
    ctx->ext.nechs -= deleted;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "Flushed %d (of %d) ECH keys more than %lu "
                   "seconds old at %lu\n", deleted, orig, age, now);
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
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
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
    unsigned int i = 0;
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
    for (i = 0; i != hashlen; i++) {
        uint8_t tn = (hashval[i] >> 4) & 0x0f;
        uint8_t bn = (hashval[i] & 0x0f);

        ah_hash[2 * i] = (tn < 10 ? tn + '0' : (tn - 10 + 'A'));
        ah_hash[2 * i + 1] = (bn < 10 ? bn + '0' : (bn - 10 + 'A'));
    }
    ah_hash[i] = '\0';

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
    if (s->ext.ech_grease == OSSL_ECH_IS_GREASE) {
        if (s->ext.ech_returned != NULL)
            return SSL_ECH_STATUS_GREASE_ECH;
        return SSL_ECH_STATUS_GREASE;
    }
    if (s->ext.ech_backend == 1)
        return SSL_ECH_STATUS_BACKEND;
    if (s->ech == NULL)
        return SSL_ECH_STATUS_NOT_CONFIGURED;
    /* set output vars - note we may be pointing to NULL which is fine */
    if (s->server == 0) {
        if (s->ext.inner_s != NULL)
            sinner = s->ext.inner_s->ext.hostname;
        else
            sinner = s->ext.hostname;
        if (s->ext.outer_s != NULL)
            souter = s->ext.outer_s->ext.hostname;
        else
            souter = s->ext.hostname;
    } else {
        if (s->ech != NULL && s->ext.ech_success == 1) {
            sinner = s->ech->inner_name;
            souter = s->ech->outer_name;
        }
    }
    if (s->ech != NULL && s->ext.ech_attempted == 1
        && s->ext.ech_grease != OSSL_ECH_IS_GREASE) {
        long vr = X509_V_OK;

        vr = SSL_get_verify_result(ssl);
        *inner_sni = sinner;
        *outer_sni = souter;
        if (s->ext.ech_success == 1) {
            if (vr == X509_V_OK)
                return SSL_ECH_STATUS_SUCCESS;
            else
                return SSL_ECH_STATUS_BAD_NAME;
        } else {
            if (s->ext.ech_returned != NULL)
                return SSL_ECH_STATUS_FAILED_ECH;
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return SSL_ECH_STATUS_FAILED;
        }
    } else if (s->ext.ech_grease == OSSL_ECH_IS_GREASE) {
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
    s->ech_cb = f;
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
    OPENSSL_free(s->ext.ech_grease_suite);
    s->ext.ech_grease_suite = OPENSSL_strdup(suite);
    return 1;
}

int SSL_ech_set_grease_type(SSL *ssl, uint16_t type)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (ssl == NULL || s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Just stash the value for now and interpret when/if we do GREASE */
    s->ext.ech_attempted_type = type;
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

    /*
     * Check if there's any ECH and if so, whether it's an outer
     * (that might need decrypting) or an inner
     */
    rv = ech_get_ch_offsets(sc, &pkt_outer, &startofsessid, &startofexts,
                            &echoffset, &echtype, &innerflag, &innersnioffset);
    if (rv != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return rv;
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

    rv = ech_early_decrypt(s, &pkt_outer, &pkt_inner);
    if (rv != 1) {
        /* that could've been GREASE, but we've no idea */
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    sc = SSL_CONNECTION_FROM_SSL(s);
    if (sc == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (sc->ech != NULL && sc->ech->outer_name != NULL) {
        *outer_sni = OPENSSL_strdup(sc->ech->outer_name);
        if (*outer_sni == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (sc->ext.ech_success == 0) {
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
        inner_ch[0] = 0x16;
        inner_ch[1] = 0x03;
        inner_ch[2] = 0x01;
        inner_ch[3] = ((ilen + 4) >> 8) & 0xff;
        inner_ch[4] = (ilen + 4) & 0xff;
        inner_ch[5] = 0x01;
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
            if (PACKET_peek_bytes(&pkt_inner, &isnipeek, plen) != 1)
                goto err;
            if (plen <= 4)
                goto err;
            isnibuf = &(isnipeek[innersnioffset + 4]);
            isnilen = isnipeek[innersnioffset + 2] * 256
                + isnipeek[innersnioffset + 3];
            if (isnilen >= plen - 4)
                goto err;
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
    if (s->ext.ech_returned) {
        *eclen = s->ext.ech_returned_len;
        *ec = s->ext.ech_returned;
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
    unsigned char lpriv[OSSL_ECH_CRYPTO_VAR_SIZE];
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
    lprivlen = BIO_read(bfp, lpriv, OSSL_ECH_CRYPTO_VAR_SIZE);
    if (lprivlen <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (lprivlen > *privlen) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    *privlen = lprivlen;
    memcpy(priv, lpriv, lprivlen);

    /*
     *   In draft-13 we get:
     *
     *   opaque HpkePublicKey<1..2^16-1>;
     *   uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
     *
     *   struct {
     *       HpkeKdfId kdf_id;
     *       HpkeAeadId aead_id;
     *   } HpkeSymmetricCipherSuite;
     *
     *   struct {
     *       uint8 config_id;
     *       HpkeKemId kem_id;
     *       HpkePublicKey public_key;
     *       HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
     *   } HpkeKeyConfig;
     *
     *   struct {
     *       HpkeKeyConfig key_config;
     *       uint8 maximum_name_length;
     *       opaque public_name<1..255>;
     *       Extension extensions<0..2^16-1>;
     *   } ECHConfigContents;
     *
     *   struct {
     *       uint16 version;
     *       uint16 length;
     *       select (ECHConfig.version) {
     *         case 0xfe0d: ECHConfigContents contents;
     *       }
     *   } ECHConfig;
     *
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

#endif
