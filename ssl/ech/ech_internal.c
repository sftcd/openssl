/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "../ssl_local.h"
#include "ech_local.h"
#include <openssl/rand.h>
#include "../statem/statem_local.h"
#include <internal/ech_helpers.h>
#include <openssl/kdf.h>

#ifndef OPENSSL_NO_ECH

/*
 * Strings used in ECH crypto derivations (odd format for EBCDIC goodness)
 */
/* "ech accept confirmation" */
static const char OSSL_ECH_ACCEPT_CONFIRM_STRING[] = "\x65\x63\x68\x20\x61\x63\x63\x65\x70\x74\x20\x63\x6f\x6e\x66\x69\x72\x6d\x61\x74\x69\x6f\x6e";
/* "hrr ech accept confirmation" */
static const char OSSL_ECH_HRR_CONFIRM_STRING[] = "\x68\x72\x72\x20\x65\x63\x68\x20\x61\x63\x63\x65\x70\x74\x20\x63\x6f\x6e\x66\x69\x72\x6d\x61\x74\x69\x6f\x6e";

/* ECH internal API functions */

# ifdef OSSL_ECH_SUPERVERBOSE
/* ascii-hex print a buffer nicely for debug/interop purposes */
void ech_pbuf(const char *msg, const unsigned char *buf, const size_t blen)
{
    size_t i;

    OSSL_TRACE_BEGIN(TLS) {
        if (msg == NULL) {
            BIO_printf(trc_out, "msg is NULL\n");
        } else if (buf == NULL || blen == 0) {
            BIO_printf(trc_out, "%s: buf is %p\n", msg, (void *)buf);
            BIO_printf(trc_out, "%s: blen is %lu\n", msg, (unsigned long)blen);
        } else {
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

/* trace out transcript */
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
                /* check-format doesn't like one statement here;-( */
                BIO_printf(trc_out, "ssl_handshake_hash failed\n");
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

static OSSL_ECHSTORE_ENTRY *ossl_echstore_entry_dup(OSSL_ECHSTORE_ENTRY *orig)
{
    OSSL_ECHSTORE_ENTRY *ret = NULL;
    OSSL_ECHEXT *ext = NULL, *newext = NULL;
    int i;

    if (orig == NULL)
        return NULL;
    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;
    ret->version = orig->version;
    if (orig->public_name != NULL) {
        ret->public_name = OPENSSL_strdup(orig->public_name);
        if (ret->public_name == NULL)
            goto err;
    }
    ret->pub_len = orig->pub_len;
    if (orig->pub != NULL) {
        ret->pub = OPENSSL_memdup(orig->pub, orig->pub_len);
        if (ret->pub == NULL)
            goto err;
    }
    ret->nsuites = orig->nsuites;
    ret->suites = OPENSSL_memdup(orig->suites, sizeof(OSSL_HPKE_SUITE) * ret->nsuites);
    if (ret->suites == NULL)
        goto err;
    ret->max_name_length = orig->max_name_length;
    ret->config_id = orig->config_id;
    if (orig->exts != NULL) {
        int num;

        if ((ret->exts = sk_OSSL_ECHEXT_new_null()) == NULL)
            goto err;
        num = (orig->exts == NULL ? 0 : sk_OSSL_ECHEXT_num(orig->exts));
        for (i = 0; i != num; i++) {
            ext = sk_OSSL_ECHEXT_value(orig->exts, i);
            if (ext == NULL)
                goto err;
            newext = OPENSSL_malloc(sizeof(OSSL_ECHEXT));
            if (newext == NULL)
                goto err;
            newext->type = ext->type;
            newext->len = ext->len;
            newext->val = NULL;
            if (ext->len != 0) {
                newext->val = OPENSSL_memdup(ext->val, ext->len);
                if (newext->val == NULL)
                    goto err;
            }
            if (sk_OSSL_ECHEXT_insert(ret->exts, newext, i) == 0) {
                OPENSSL_free(newext->val);
                OPENSSL_free(newext);
                goto err;
            }
        }
    }
    ret->loadtime = orig->loadtime;
    if (orig->keyshare != NULL) {
        ret->keyshare = orig->keyshare;
        EVP_PKEY_up_ref(orig->keyshare);
    }
    ret->for_retry = orig->for_retry;
    if (orig->encoded != NULL) {
        ret->encoded_len = orig->encoded_len;
        ret->encoded = OPENSSL_memdup(orig->encoded, ret->encoded_len);
        if (ret->encoded == NULL)
            goto err;
    }
    return ret;
err:
    ossl_echstore_entry_free(ret);
    return NULL;
}

/* duplicate an OSSL_ECHSTORE as needed */
int ossl_echstore_dup(OSSL_ECHSTORE **new, OSSL_ECHSTORE *old)
{
    OSSL_ECHSTORE *cp = NULL;
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    int i, num;

    if (new == NULL || old == NULL)
        return 0;
    cp = OPENSSL_zalloc(sizeof(*cp));
    if (cp == NULL)
        return 0;
    cp->libctx = old->libctx;
    cp->propq = old->propq;
    if (old->entries == NULL) {
        *new = cp;
        return 1;
    }
    if ((cp->entries = sk_OSSL_ECHSTORE_ENTRY_new_null()) == NULL)
        goto err;
    num = sk_OSSL_ECHSTORE_ENTRY_num(old->entries);
    for (i = 0; i != num; i++) {
        ee = ossl_echstore_entry_dup(sk_OSSL_ECHSTORE_ENTRY_value(old->entries,
                                                                  i));
        if (ee == NULL)
            goto err;
        if (sk_OSSL_ECHSTORE_ENTRY_insert(cp->entries, ee, i) == 0)
            goto err;
    }
    *new = cp;
    return 1;
err:
    OSSL_ECHSTORE_free(cp);
    ossl_echstore_entry_free(ee);
    return 0;
}

void ossl_ctx_ech_free(OSSL_CTX_ECH *ce)
{
    if (ce == NULL)
        return;
    OSSL_ECHSTORE_free(ce->es);
    OPENSSL_free(ce->alpn_outer);
    return;
}

void ossl_ech_conn_free(OSSL_ECH_CONN *ec)
{
    if (ec == NULL)
        return;
    OSSL_ECHSTORE_free(ec->es);
    OPENSSL_free(ec->outer_hostname);
    OPENSSL_free(ec->alpn_outer);
    OPENSSL_free(ec->former_inner);
    OPENSSL_free(ec->innerch);
    OPENSSL_free(ec->encoded_innerch);
    OPENSSL_free(ec->innerch1);
    OPENSSL_free(ec->kepthrr);
    OPENSSL_free(ec->grease_suite);
    OPENSSL_free(ec->sent);
    OPENSSL_free(ec->returned);
    OPENSSL_free(ec->pub);
    OSSL_HPKE_CTX_free(ec->hpke_ctx);
    EVP_PKEY_free(ec->tmp_pkey);
    return;
}

/* called from ssl/ssl_lib.c: ossl_ssl_connection_new_int */
int ossl_ech_conn_init(SSL_CONNECTION *s, SSL_CTX *ctx,
                       const SSL_METHOD *method)
{
    OSSL_ECHSTORE *new = NULL;

    memset(&s->ext.ech, 0, sizeof(s->ext.ech));
    if (ctx->ext.ech.es != NULL && !ossl_echstore_dup(&new, ctx->ext.ech.es))
        goto err;
    s->ext.ech.es = new;
    new = NULL;
    s->ext.ech.cb = ctx->ext.ech.cb;
    if (ctx->ext.ech.alpn_outer != NULL) {
        s->ext.ech.alpn_outer = OPENSSL_memdup(ctx->ext.ech.alpn_outer,
                                               ctx->ext.ech.alpn_outer_len);
        if (s->ext.ech.alpn_outer == NULL)
            goto err;
        s->ext.ech.alpn_outer_len = ctx->ext.ech.alpn_outer_len;
    }
    /* initialise type/cid to unknown */
    s->ext.ech.attempted_type = TLSEXT_TYPE_ech_unknown;
    s->ext.ech.attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
    if (s->ext.ech.es != NULL)
        s->ext.ech.attempted = 1;
    if (ctx->options & SSL_OP_ECH_GREASE)
        s->options |= SSL_OP_ECH_GREASE;
    return 1;
err:
    OSSL_ECHSTORE_free(s->ext.ech.es);
    OPENSSL_free(s->ext.ech.alpn_outer);
    return 0;
}

/*
 * Assemble the set of ECHConfig values to return as retry-configs.
 * The caller (stoc ECH extension handler) needs to OPENSSL_free the rcfgs
 * The rcfgs itself is missing the outer length to make it an ECHConfigList
 * so the caller adds that using WPACKET functions
 */
int ech_get_retry_configs(SSL_CONNECTION *s, unsigned char **rcfgs,
                          size_t *rcfgslen)
{
    OSSL_ECHSTORE *es = NULL;
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    int i, num;
    size_t retslen = 0, encilen = 0;
    unsigned char *tmp = NULL, *enci = NULL, *rets = NULL;

    if (s == NULL || rcfgs == NULL || rcfgslen == NULL)
        return 0;
    es = s->ext.ech.es;
    num = (es == NULL || es->entries == NULL ? 0
           : sk_OSSL_ECHSTORE_ENTRY_num(es->entries));
    for (i = 0; i != num; i++) {
        ee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, i);
        if (ee != NULL && ee->for_retry == OSSL_ECH_FOR_RETRY) {
            encilen = ee->encoded_len;
            if (encilen < 2)
                goto err;
            encilen -= 2;
            enci = ee->encoded + 2;
            tmp = (unsigned char *)OPENSSL_realloc(rets, retslen + encilen);
            if (tmp == NULL)
                goto err;
            rets = tmp;
            memcpy(rets + retslen, enci, encilen);
            retslen += encilen;
        }
    }
    *rcfgs = rets;
    *rcfgslen = retslen;
    return 1;
err:
    OPENSSL_free(rets);
    *rcfgs = NULL;
    *rcfgslen = 0;
    return 0;
}

/* GREASEy constants */
# define OSSL_ECH_MAX_GREASE_PUB 0x100 /* buffer size for 'enc' values */
# define OSSL_ECH_MAX_GREASE_CT 0x200 /* max GREASEy ciphertext we'll emit */
/*
 * When including a different key_share in the inner CH, 256 is the
 * size we produce for a real ECH when including padding in the inner
 * CH with the default/current client hello padding code.
 * This value doesn't vary with at least minor changes to inner SNI
 * length. The 272 is 256 of padded cleartext plus a 16-octet AEAD
 * tag. If we ECH-`compress key_share's that brings us down to 128 for
 * the padded inner CH and 144 for the ciphertext including AEAD tag.
 * So, we'll adjust the GREASE ciphertext size to match whatever key_share
 * handling we do.
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

/*
 * Send a random value that looks like a real ECH.
 *
 * TODO(ECH): the "best" thing to do here is not yet
 * known; arguably we might try replicate what the
 * most popular client(s) do, in some sense. But that
 * may require measurement campaigns after ECH has been
 * in use for some time, which we can't yet do. The
 * current code makes an attempt to offer compile time
 * flexibility so we can more easily change to whatever
 * seems to make sense later.
 */
int ech_send_grease(SSL_CONNECTION *s, WPACKET *pkt)
{
    OSSL_HPKE_SUITE hpke_suite_in = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE *hpke_suite_in_p = NULL;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    size_t pp_at_start = 0, pp_at_end = 0;
    size_t senderpub_len = OSSL_ECH_MAX_GREASE_PUB;
    size_t cipher_len = OSSL_ECH_DEF_CIPHER_LEN_SMALL;
    size_t cipher_len_jitter = OSSL_ECH_DEF_CIPHER_LEN_JITTER;
    unsigned char cid, senderpub[OSSL_ECH_MAX_GREASE_PUB];
    unsigned char cipher[OSSL_ECH_MAX_GREASE_CT];
    unsigned char *pp = WPACKET_get_curr(pkt);

    if (s == NULL)
        return 0;
    if (s->ssl.ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /*
     * if we normally send different inner/outer key shares
     * then we should send a larger GREASE value
     */
    if (ech_same_key_share() == 0)
        cipher_len = OSSL_ECH_DEF_CIPHER_LEN_LARGE;
    WPACKET_get_total_written(pkt, &pp_at_start);
    /* generate a random (1 octet) client id */
    if (RAND_bytes_ex(s->ssl.ctx->libctx, &cid, 1,
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
    if (OSSL_HPKE_get_grease_value(hpke_suite_in_p, &hpke_suite,
                                   senderpub, &senderpub_len,
                                   cipher, cipher_len,
                                   s->ssl.ctx->libctx, NULL) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (s->ext.ech.attempted_type == TLSEXT_TYPE_ech) {
        if (!WPACKET_put_bytes_u16(pkt, s->ext.ech.attempted_type)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, OSSL_ECH_OUTER_CH_TYPE)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
            || !WPACKET_memcpy(pkt, &cid, 1)
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
        BIO_printf(trc_out, "ECH - sending GREASE\n");
    } OSSL_TRACE_END(TLS);
    return 1;
}

/*
 * Search the ECH store for one that's a match. If no outer_name was set via
 * API then we just take the 1st match where we locally support the HPKE suite.
 * If OTOH, an outer_name was provided via API then we prefer the first that
 * matches that. Name comparison is via case-insensitive exact matches.
 */
int ech_pick_matching_cfg(SSL_CONNECTION *s, OSSL_ECHSTORE_ENTRY **ee,
                          OSSL_HPKE_SUITE *suite)
{
    int namematch = 0, nameoverride = 0, suitematch = 0, num, cind = 0;
    unsigned int csuite = 0, hnlen = 0;
    OSSL_ECHSTORE_ENTRY *lee = NULL;
    OSSL_ECHSTORE *es = NULL;
    char *hn = NULL;

    if (s == NULL || s->ext.ech.es == NULL || ee == NULL || suite == NULL)
        return 0;
    es = s->ext.ech.es;
    if (es->entries == NULL)
        return 0;
    num = sk_OSSL_ECHSTORE_ENTRY_num(es->entries);
    /* allow API-set pref to override */
    hn = s->ext.ech.outer_hostname;
    hnlen = (hn == NULL ? 0 : strlen(hn));
    if (hnlen != 0)
        nameoverride = 1;
    if (s->ext.ech.no_outer == 1) {
        hn = NULL;
        hnlen = 0;
        nameoverride = 1;
    }
    for (cind = 0; cind != num && suitematch == 0 && namematch == 0; cind++) {
        lee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, cind);
        if (lee == NULL || lee->version != OSSL_ECH_RFCXXXX_VERSION)
            continue;
        if (nameoverride == 1) {
            namematch = 1;
        } else {
            namematch = 0;
            if (hnlen == 0
                || (lee->public_name != NULL
                    && strlen(lee->public_name) == hnlen
                    && !OPENSSL_strncasecmp(hn, (char *)lee->public_name,
                                            hnlen)))
                namematch = 1;
        }
        suitematch = 0;
        for (csuite = 0; csuite != lee->nsuites && suitematch == 0; csuite++) {
            if (OSSL_HPKE_suite_check(lee->suites[csuite]) == 1) {
                suitematch = 1;
                *suite = lee->suites[csuite];
                if (namematch == 1) { /* pick this one if both "fit" */
                    *ee = lee;
                    break;
                }
            }
        }
    }
    if (namematch == 0 || suitematch == 0)
        return 0;
    if (*ee == NULL || (*ee)->pub_len == 0 || (*ee)->pub == NULL)
        return 0;
    return 1;
}

/* Make up the ClientHelloInner and EncodedClientHelloInner buffers */
int ech_encode_inner(SSL_CONNECTION *s)
{
    int rv = 0, mt = SSL3_MT_CLIENT_HELLO;
    size_t nraws = 0, ind = 0, innerlen = 0;
    unsigned char *innerch_full = NULL;
    WPACKET inner; /* "fake" pkt for inner */
    BUF_MEM *inner_mem = NULL;
    RAW_EXTENSION *raws = NULL;

    /* basic checks */
    if (s == NULL)
        return 0;
    if (s->ext.ech.es == NULL || s->clienthello == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
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
    if (raws == NULL || nraws < TLSEXT_IDX_num_builtins) {
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
    for (ind = 0; ind < TLSEXT_IDX_num_builtins; ind++) {
        if (raws[ind].present == 0 || ech_2bcompressed(ind) == 1)
            continue;
        if (PACKET_data(&raws[ind].data) != NULL) {
            if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                || !WPACKET_sub_memcpy_u16(&inner, PACKET_data(&raws[ind].data),
                                           PACKET_remaining(&raws[ind].data))) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else { /* empty extension */
            if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                || !WPACKET_put_bytes_u16(&inner, 0)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    if (!WPACKET_close(&inner)  /* close the exts sub packet */
        || !WPACKET_close(&inner) /* close the inner CH */
        || !WPACKET_get_length(&inner, &innerlen)) { /* len for inner CH */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    innerch_full = OPENSSL_malloc(innerlen);
    if (innerch_full == NULL)
        goto err;
    /* Finally ditch the type and 3-octet length */
    memcpy(innerch_full, inner_mem->data + 4, innerlen - 4);
    OPENSSL_free(s->ext.ech.encoded_innerch);
    s->ext.ech.encoded_innerch = innerch_full;
    s->ext.ech.encoded_innerch_len = innerlen - 4;
    /* and clean up */
    rv = 1;
err:
    WPACKET_cleanup(&inner);
    BUF_MEM_free(inner_mem);
    return rv;
}

/*
 * Find ECH acceptance signal in a SH
 * hrr is 1 if this is for an HRR, otherwise for SH
 * acbuf is (a preallocated) 8 octet buffer
 * shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * shlen is the length of the SH buf
 * return: 1 for success, 0 otherwise
 */
int ech_find_confirm(SSL_CONNECTION *s, int hrr, unsigned char *acbuf,
                     const unsigned char *shbuf, const size_t shlen)
{
    PACKET pkt;
    const unsigned char *acp = NULL, *pp_tmp;
    unsigned int pi_tmp, etype, elen;
    int done = 0;

    if (hrr == 0) {
        if (shlen < CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE)
            return 0;
        acp = shbuf + CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE - 8;
        memcpy(acbuf, acp, 8);
        return 1;
    } else {
        if (!PACKET_buf_init(&pkt, shbuf, shlen)
            || !PACKET_get_net_2(&pkt, &pi_tmp)
            || !PACKET_get_bytes(&pkt, &pp_tmp, SSL3_RANDOM_SIZE)
            || !PACKET_get_1(&pkt, &pi_tmp) /* sessid len */
            || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* sessid */
            || !PACKET_get_net_2(&pkt, &pi_tmp) /* ciphersuite */
            || !PACKET_get_1(&pkt, &pi_tmp) /* compression */
            || !PACKET_get_net_2(&pkt, &pi_tmp)) /* len(extensions) */
            return 0;
        while (PACKET_remaining(&pkt) > 0 && done < 1) {
            if (!PACKET_get_net_2(&pkt, &etype)
                || !PACKET_get_net_2(&pkt, &elen))
                return 0;
            if (etype == TLSEXT_TYPE_ech) {
                if (elen != 8 || !PACKET_get_bytes(&pkt, &acp, elen))
                    return 0;
                memcpy(acbuf, acp, elen);
                done++;
            } else {
                if (!PACKET_get_bytes(&pkt, &pp_tmp, elen))
                    return 0;
            }
        }
        return done;
    }
    return 0;
}

/*
 * return the h/s hash from the connection or ServerHello
 * rmd is the returned h/s hash
 * shbuf is the ServerHello
 * shlen is the length of the ServerHello
 * return 1 for good, 0 for error
 */
static int ech_get_md_from_hs(SSL_CONNECTION *s, EVP_MD **rmd,
                              const unsigned char *shbuf, const size_t shlen)
{
    int rv;
    size_t extoffset = 0, echoffset = 0, cipheroffset = 0;
    uint16_t echtype;
    const SSL_CIPHER *c = NULL;
    const unsigned char *cipherchars = NULL;
    EVP_MD *md = NULL;

    /* this branch works for the server */
    md = (EVP_MD *)ssl_handshake_md(s);
    if (md != NULL) {
        *rmd = md;
        return 1;
    }
    /*
     * if we're a client we'll fallback to hash from the chosen ciphersuite
     * that means ECH acceptance depends on no bidding down, but that's ok
     */
    rv = ech_helper_get_sh_offsets(shbuf, shlen, &extoffset, &echoffset,
                                   &echtype);
    if (rv != 1 || extoffset < 3) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
        return 0;
    }
    cipheroffset = extoffset - 3;
    cipherchars = &shbuf[cipheroffset];
    c = ssl_get_cipher_by_char(s, cipherchars, 0);
    if (c == NULL /* fuzzer fix */
        || (md = (EVP_MD *)ssl_md(s->ssl.ctx, c->algorithm2)) == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    *rmd = md;
    return 1;
}

/*
 * make up a buffer to use to reset transcript
 * for_hrr is 1 if we've just seen HRR, 0 otherwise
 * shbuf is the output buffer
 * shlen is the length of that buffer
 * tbuf is the output buffer
 * tlen is the length of that buffer
 * chend returns the offset of the end of the last CH in the buffer
 * fixedshbuf_len returns the fixed up length of the SH
 * return 1 for good, 0 otherwise
 */
int ech_make_transcript_buffer(SSL_CONNECTION *s, int for_hrr,
                               const unsigned char *shbuf, size_t shlen,
                               unsigned char **tbuf, size_t *tlen,
                               size_t *chend, size_t *fixedshbuf_len)
{
    unsigned char *fixedshbuf = NULL, *hashin = NULL, hashval[EVP_MAX_MD_SIZE];
    unsigned int hashlen = 0, hashin_len = 0;
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    WPACKET tpkt, shpkt;
    BUF_MEM *tpkt_mem = NULL, *shpkt_mem = NULL;

    /*
     * SH preamble has bad length at this point on server
     * and is missing on client so we'll fix
     */
    if ((shpkt_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(shpkt_mem, SSL3_RT_MAX_PLAIN_LENGTH)
        || !WPACKET_init(&shpkt, shpkt_mem)) {
        BUF_MEM_free(shpkt_mem);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!WPACKET_put_bytes_u8(&shpkt, SSL3_MT_SERVER_HELLO)
        || (s->server == 1 && !WPACKET_put_bytes_u24(&shpkt, shlen - 4))
        || (s->server == 1 && !WPACKET_memcpy(&shpkt, shbuf + 4, shlen -4))
        || (s->server == 0 && !WPACKET_put_bytes_u24(&shpkt, shlen))
        || (s->server == 0 && !WPACKET_memcpy(&shpkt, shbuf, shlen))
        || !WPACKET_get_length(&shpkt, fixedshbuf_len)) {
        BUF_MEM_free(shpkt_mem);
        WPACKET_cleanup(&shpkt);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    fixedshbuf = OPENSSL_malloc(*fixedshbuf_len);
    if (fixedshbuf == NULL) {
        BUF_MEM_free(shpkt_mem);
        WPACKET_cleanup(&shpkt);
        goto err;
    }
    memcpy(fixedshbuf, WPACKET_get_curr(&shpkt) - *fixedshbuf_len,
           *fixedshbuf_len);
    BUF_MEM_free(shpkt_mem);
    WPACKET_cleanup(&shpkt);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: fixed sh buf", fixedshbuf, *fixedshbuf_len);
# endif
    if ((tpkt_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(tpkt_mem, SSL3_RT_MAX_PLAIN_LENGTH)
        || !WPACKET_init(&tpkt, tpkt_mem)) {
        BUF_MEM_free(tpkt_mem);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (s->hello_retry_request == SSL_HRR_NONE) {
        if (!WPACKET_memcpy(&tpkt, s->ext.ech.innerch,
                            s->ext.ech.innerch_len)
            || !WPACKET_get_length(&tpkt, chend)
            || !WPACKET_memcpy(&tpkt, fixedshbuf, *fixedshbuf_len)
            || !WPACKET_get_length(&tpkt, tlen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        OPENSSL_free(fixedshbuf);
        *tbuf = OPENSSL_malloc(*tlen);
        if (*tbuf == NULL)
            goto err;
        memcpy(*tbuf, WPACKET_get_curr(&tpkt) - *tlen, *tlen);
        WPACKET_cleanup(&tpkt);
        BUF_MEM_free(tpkt_mem);
        return 1;
    }
    /* everything below only applies if we're at some stage in doing HRR */
    if (*fixedshbuf_len <= 5 /* SH here has outer type/24-bit length */
        || ech_get_md_from_hs(s, &md, fixedshbuf + 4, *fixedshbuf_len - 4) != 1
        || (hashlen = EVP_MD_size(md)) > EVP_MAX_MD_SIZE)
        goto err;
    if (for_hrr == 0) { /* after 2nd SH rx'd */
        hashin = s->ext.ech.innerch1;
        hashin_len = s->ext.ech.innerch1_len;
    } else { /* after HRR rx'd */
        hashin = s->ext.ech.innerch;
        hashin_len = s->ext.ech.innerch_len;
        OPENSSL_free(s->ext.ech.kepthrr);
        s->ext.ech.kepthrr = fixedshbuf; /* stash this SH/HRR for later */
        s->ext.ech.kepthrr_len = *fixedshbuf_len;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: ch2hash", hashin, hashin_len);
# endif
    if ((ctx = EVP_MD_CTX_new()) == NULL
        || EVP_DigestInit_ex(ctx, md, NULL) <= 0
        || EVP_DigestUpdate(ctx, hashin, hashin_len) <= 0
        || EVP_DigestFinal_ex(ctx, hashval, &hashlen) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(ctx);
    ctx = NULL;
    if (!WPACKET_put_bytes_u8(&tpkt, SSL3_MT_MESSAGE_HASH)
        || !WPACKET_put_bytes_u24(&tpkt, hashlen)
        || !WPACKET_memcpy(&tpkt, hashval, hashlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (for_hrr == 0) { /* after 2nd SH */
        if (!WPACKET_memcpy(&tpkt, s->ext.ech.kepthrr,
                            s->ext.ech.kepthrr_len)
            || !WPACKET_memcpy(&tpkt, s->ext.ech.innerch,
                               s->ext.ech.innerch_len)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (!WPACKET_get_length(&tpkt, chend)
        || !WPACKET_memcpy(&tpkt, fixedshbuf, *fixedshbuf_len)
        || !WPACKET_get_length(&tpkt, tlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *tbuf = OPENSSL_malloc(*tlen);
    if (*tbuf == NULL)
        goto err;
    memcpy(*tbuf, WPACKET_get_curr(&tpkt) - *tlen, *tlen);
    /* don't double-free */
    if (for_hrr == 0 && s->ext.ech.kepthrr != fixedshbuf)
        OPENSSL_free(fixedshbuf);
    WPACKET_cleanup(&tpkt);
    BUF_MEM_free(tpkt_mem);
    return 1;
err:
    if (s->ext.ech.kepthrr != fixedshbuf) /* don't double-free */
        OPENSSL_free(fixedshbuf);
    WPACKET_cleanup(&tpkt);
    BUF_MEM_free(tpkt_mem);
    EVP_MD_CTX_free(ctx);
    return 0;
}

/*
 * reset the handshake buffer for transcript after ECH is good
 * buf is the data to put into the transcript (inner CH if no HRR)
 * blen is the length of buf
 * return 1 for success
 */
int ech_reset_hs_buffer(SSL_CONNECTION *s, const unsigned char *buf,
                        size_t blen)
{
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("RESET transcript to", buf, blen);
# endif
    if (s->s3.handshake_buffer != NULL) {
        (void)BIO_set_close(s->s3.handshake_buffer, BIO_CLOSE);
        BIO_free(s->s3.handshake_buffer);
        s->s3.handshake_buffer = NULL;
    }
    EVP_MD_CTX_free(s->s3.handshake_dgst);
    s->s3.handshake_dgst = NULL;
    s->s3.handshake_buffer = BIO_new(BIO_s_mem());
    if (s->s3.handshake_buffer == NULL)
        return 0;
    /* providing nothing at all is a real use (mid-HRR) */
    if (buf != NULL || blen > 0)
        BIO_write(s->s3.handshake_buffer, (void *)buf, (int)blen);
    return 1;
}

/*
 * To control the number of zeros added after an EncodedClientHello - we pad
 * to a target number of octets or, if there are naturally more, to a number
 * divisible by the defined increment (we also do the spec-recommended SNI
 * padding thing first)
 */
# define OSSL_ECH_PADDING_TARGET 128 /* ECH cleartext padded to at least this */
# define OSSL_ECH_PADDING_INCREMENT 32 /* ECH padded to a multiple of this */

/*
 * figure out how much padding for cleartext (on client)
 * ee is the chosen ECHConfig
 * return overall length to use including padding or zero on error
 *
 * "Recommended" inner SNI padding scheme as per spec (section 6.1.3)
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
static size_t ech_calc_padding(SSL_CONNECTION *s, OSSL_ECHSTORE_ENTRY *ee)
{
    int length_of_padding = 0, length_with_snipadding = 0;
    int innersnipadding = 0, length_with_padding = 0;
    size_t mnl = 0, clear_len = 0, isnilen = 0;

    if (s == NULL || ee == NULL)
        return 0;
    mnl = ee->max_name_length;
    if (mnl != 0) {
        /* do weirder padding if SNI present in inner */
        if (s->ext.hostname != NULL) {
            isnilen = strlen(s->ext.hostname) + 9;
            innersnipadding = mnl - isnilen;
        } else {
            innersnipadding = mnl + 9;
        }
        if (innersnipadding < 0)
            innersnipadding = 0;
    }
    /* padding is after the inner client hello has been encoded */
    length_with_snipadding = innersnipadding + s->ext.ech.encoded_innerch_len;
    length_of_padding = 31 - ((length_with_snipadding - 1) % 32);
    length_with_padding = s->ext.ech.encoded_innerch_len
        + length_of_padding + innersnipadding;
    /*
     * Finally - make sure final result is longer than padding target
     * and a multiple of our padding increment.
     * TODO(ECH): This is a local addition - we might take it out if
     * it makes us stick out; or if we take out the above more (uselessly:-)
     * complicated scheme, we may only need this in the end.
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

/*
 * Calculate AAD and do ECH encryption
 * pkt is the packet to send
 * return 1 for success, other otherwise
 *
 * 1. Make up the AAD: the encoded outer, with ECH ciphertext octets zero'd
 * 2. Do the encryption
 * 3. Put the ECH back into the encoding
 * 4. Encode the outer (again!)
 */
int ech_aad_and_encrypt(SSL_CONNECTION *s, WPACKET *pkt)
{
    int rv = 0, hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char config_id_to_use = 0x00, info[SSL3_RT_MAX_PLAIN_LENGTH];
    unsigned char *clear = NULL, *cipher = NULL, *aad = NULL, *mypub = NULL;
    size_t cipherlen = 0, aad_len = 0, lenclen = 0, mypub_len = 0;
    size_t info_len = SSL3_RT_MAX_PLAIN_LENGTH, clear_len = 0;

    if (s == NULL)
        return 0;
    if (s->ext.ech.es == NULL || s->ext.ech.es->entries == NULL
        || pkt == NULL || s->ssl.ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = ech_pick_matching_cfg(s, &ee, &hpke_suite);
    if (rv != 1 || ee == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    s->ext.ech.attempted_type = ee->version;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: selected: version: %4x, config %2x\n",
                   ee->version, ee->config_id);
    } OSSL_TRACE_END(TLS);
    config_id_to_use = ee->config_id; /* if requested, use a random config_id instead */
    if (s->ssl.ctx->options & SSL_OP_ECH_IGNORE_CID
        || s->options & SSL_OP_ECH_IGNORE_CID) {
        if (RAND_bytes_ex(s->ssl.ctx->libctx, &config_id_to_use, 1,
                          RAND_DRBG_STRENGTH) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("EAAE: random config_id", &config_id_to_use, 1);
# endif
    }
    s->ext.ech.attempted_cid = config_id_to_use;
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: peer pub", ee->pub, ee->pub_len);
    ech_pbuf("EAAE: clear", s->ext.ech.encoded_innerch,
             s->ext.ech.encoded_innerch_len);
    ech_pbuf("EAAE: ECHConfig", ee->encoded, ee->encoded_len);
# endif
    /*
     * The AAD is the full outer client hello but with the correct number of
     * zeros for where the ECH ciphertext octets will later be placed. So we
     * add the ECH extension to the |pkt| but with zeros for ciphertext, that
     * forms up the AAD, then after we've encrypted, we'll splice in the actual
     * ciphertext.
     * Watch out for the "4" offsets that remove the type and 3-octet length
     * from the encoded CH as per the spec.
     */
    clear_len = ech_calc_padding(s, ee);
    if (clear_len == 0)
        goto err;
    lenclen = OSSL_HPKE_get_public_encap_size(hpke_suite);
    if (s->ext.ech.hpke_ctx == NULL) { /* 1st CH */
        if (ech_helper_make_enc_info(ee->encoded, ee->encoded_len,
                                     info, &info_len) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("EAAE info", info, info_len);
# endif
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
        rv = OSSL_HPKE_encap(s->ext.ech.hpke_ctx, mypub, &mypub_len,
                             ee->pub, ee->pub_len, info, info_len);
        if (rv != 1) {
            OPENSSL_free(mypub);
            mypub = NULL;
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        s->ext.ech.pub = mypub;
        s->ext.ech.pub_len = mypub_len;
    } else { /* HRR - retrieve public */
        mypub = s->ext.ech.pub;
        mypub_len = s->ext.ech.pub_len;
        if (mypub == NULL || mypub_len == 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: mypub", mypub, mypub_len);
    WPACKET_get_total_written(pkt, &aad_len); /* use aad_len for tracing */
    ech_pbuf("EAAE pkt b4", WPACKET_get_curr(pkt) - aad_len, aad_len);
# endif
    cipherlen = OSSL_HPKE_get_ciphertext_size(hpke_suite, clear_len);
    if (cipherlen <= clear_len || cipherlen > OSSL_ECH_MAX_PAYLOAD_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    cipher = OPENSSL_zalloc(cipherlen);
    if (cipher == NULL)
        goto err;
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ech)
        || !WPACKET_start_sub_packet_u16(pkt)
        || !WPACKET_put_bytes_u8(pkt, OSSL_ECH_OUTER_CH_TYPE)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
        || !WPACKET_put_bytes_u8(pkt, config_id_to_use)
        || (s->hello_retry_request == SSL_HRR_PENDING
            && !WPACKET_put_bytes_u16(pkt, 0x00)) /* no pub */
        || (s->hello_retry_request != SSL_HRR_PENDING
            && !WPACKET_sub_memcpy_u16(pkt, mypub, mypub_len))
        || !WPACKET_sub_memcpy_u16(pkt, cipher, cipherlen)
        || !WPACKET_close(pkt)
        || !WPACKET_get_total_written(pkt, &aad_len)
        || aad_len < 4) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    aad_len -= 4; /* aad starts after type + 3-octet len */
    aad = WPACKET_get_curr(pkt) - aad_len;
    /*
     * close the extensions of the CH - we skipped doing this
     * earler when encoding extensions, to allow for adding the
     * ECH here (when doing ECH) - see tls_construct_extensions()
     * towards the end
     */
    if (!WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: aad", aad, aad_len);
# endif
    clear = OPENSSL_zalloc(clear_len); /* zeros incl. padding */
    if (clear == NULL)
        goto err;
    memcpy(clear, s->ext.ech.encoded_innerch, s->ext.ech.encoded_innerch_len);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: padded clear", clear, clear_len);
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
    /* re-use aad_len for tracing */
    WPACKET_get_total_written(pkt, &aad_len);
    ech_pbuf("EAAE pkt aftr", WPACKET_get_curr(pkt) - aad_len, aad_len);
# endif
    OPENSSL_free(cipher);
    return 1;
err:
    OPENSSL_free(cipher);
    return 0;
}

/*
 * print info about the ECH-status of an SSL connection
 * out is the BIO to use (e.g. stdout/whatever)
 * selector OSSL_ECH_SELECT_ALL or just one of the SSL_ECH values
 */
static void ech_status_print(BIO *out, SSL_CONNECTION *s, int selector)
{
    int num = 0, i, has_priv, for_retry;
    size_t j;
    time_t secs = 0;
    char *pn = NULL, *ec = NULL;
    OSSL_ECHSTORE *es = NULL;

# ifdef OSSL_ECH_SUPERVERBOSE
    BIO_printf(out, "ech_status_print\n");
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
# endif
    BIO_printf(out, "ech_backend=%d\n", s->ext.ech.backend);
    BIO_printf(out, "ech_success=%d\n", s->ext.ech.success);
    es = s->ext.ech.es;
    if (es == NULL || es->entries == NULL) {
        BIO_printf(out, "ECH cfg=NONE\n");
    } else {
        num = sk_OSSL_ECHSTORE_ENTRY_num(es->entries);
        BIO_printf(out, "%d ECHConfig values loaded\n", num);
        for (i = 0; i != num; i++) {
            if (selector != OSSL_ECHSTORE_ALL && selector != i)
                continue;
            BIO_printf(out, "cfg(%d): ", i);
            if (OSSL_ECHSTORE_get1_info(es, i, &secs, &pn, &ec,
                                        &has_priv, &for_retry) != 1) {
                OPENSSL_free(pn); /* just in case */
                OPENSSL_free(ec);
                continue;
            }
            BIO_printf(out, "ECH entry: %d public_name: %s age: %d%s\n",
                       i, pn, (int)secs, has_priv ? " (has private key)" : "");
            BIO_printf(out, "\t%s\n", ec);
            OPENSSL_free(pn);
            OPENSSL_free(ec);
        }
    }
    if (s->ext.ech.returned) {
        BIO_printf(out, "ret=");
        for (j = 0; j != s->ext.ech.returned_len; j++) {
            if ((j != 0) && (j % 16 == 0))
                BIO_printf(out, "\n    ");
            BIO_printf(out, "%02x:", (unsigned)(s->ext.ech.returned[j]));
        }
        BIO_printf(out, "\n");
    }
    return;
}

/* size of string buffer returned via ECH callback */
#  define OSSL_ECH_PBUF_SIZE 8 * 1024

/*
 * Swap the inner and outer after ECH success on the client
 * return 0 for error, 1 for success
 */
int ech_swaperoo(SSL_CONNECTION *s)
{
    unsigned char *curr_buf = NULL, *new_buf = NULL;
    size_t curr_buflen = 0, new_buflen = 0, outer_chlen = 0, other_octets = 0;

    if (s == NULL)
        return 0;
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_ptranscript("ech_swaperoo, b4", s);
# endif
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
     * TODO(ECH): I suggest re-factoring transcript handling (which
     * is probably needed) after/with the PR that includes the server
     * side ECH code. That should be much easier as at that point the
     * full set of tests can be run, whereas for now, we're limited
     * to testing the client side really works via bodged s_client
     * scripts, so there'd be a bigger risk of breaking something
     * subtly if we try re-factor now.
     *
     * When not doing HRR... fix up the transcript to reflect the inner CH.
     * If there's a client hello at the start of the buffer, then that's
     * the outer CH and we want to replace that with the inner. We need to
     * be careful that there could be a server hello following and can't
     * lose that.
     *
     * For HRR... HRR processing code has already done the necessary.
     */
    if (s->hello_retry_request == SSL_HRR_NONE) {
        curr_buflen = BIO_get_mem_data(s->s3.handshake_buffer,
                                       &curr_buf);
        if (curr_buflen > 4 && curr_buf[0] == SSL3_MT_CLIENT_HELLO) {
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
            if (other_octets > 0)
                OPENSSL_free(new_buf);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (ssl3_finish_mac(s, new_buf, new_buflen) == 0) {
            if (other_octets > 0)
                OPENSSL_free(new_buf);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (other_octets > 0)
            OPENSSL_free(new_buf);
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_ptranscript("ech_swaperoo, after", s);
# endif
    /* Declare victory! */
    s->ext.ech.attempted = 1;
    s->ext.ech.success = 1;
    s->ext.ech.done = 1;
    s->ext.ech.grease = OSSL_ECH_NOT_GREASE;
    /* time to call an ECH callback, if there's one */
    if (s->ext.ech.es != NULL && s->ext.ech.done == 1
        && s->hello_retry_request != SSL_HRR_PENDING
        && s->ext.ech.cb != NULL) {
        char pstr[OSSL_ECH_PBUF_SIZE + 1];
        BIO *biom = BIO_new(BIO_s_mem());
        unsigned int cbrv = 0;

        memset(pstr, 0, OSSL_ECH_PBUF_SIZE + 1);
        ech_status_print(biom, s, OSSL_ECHSTORE_ALL);
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
 * do the HKDF for ECH acceptannce checking
 * md is the h/s hash
 * for_hrr is 1 if we're doing a HRR
 * return 1 for good, 0 for error
 */
static int ech_hkdf_extract_wrap(SSL_CONNECTION *s, EVP_MD *md, int for_hrr,
                                 unsigned char *hashval, size_t hashlen,
                                 unsigned char *hoval)
{
    int rv = 0;
    unsigned char notsecret[EVP_MAX_MD_SIZE], zeros[EVP_MAX_MD_SIZE];
    size_t retlen = 0, labellen = 0;
    EVP_PKEY_CTX *pctx = NULL;
    const char *label = NULL;
    unsigned char *p = NULL;

    if (for_hrr == 1) {
        label = OSSL_ECH_HRR_CONFIRM_STRING;
    } else {
        label = OSSL_ECH_ACCEPT_CONFIRM_STRING;
    }
    labellen = strlen(label);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cc: label", (unsigned char *)label, labellen);
# endif
    memset(zeros, 0, EVP_MAX_MD_SIZE);
    /* We don't seem to have an hkdf-extract that's exposed by libcrypto */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL
        || EVP_PKEY_derive_init(pctx) != 1
        || EVP_PKEY_CTX_hkdf_mode(pctx,
                                  EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1
        || EVP_PKEY_CTX_hkdf_mode(pctx,
                                  EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1
        || EVP_PKEY_CTX_set_hkdf_md(pctx, md) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* pick correct client_random */
    if (s->server)
        p = s->s3.client_random;
    else
        p = s->ext.ech.client_random;
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cc: client_random", p, SSL3_RANDOM_SIZE);
# endif
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, p, SSL3_RANDOM_SIZE) != 1
        || EVP_PKEY_CTX_set1_hkdf_salt(pctx, zeros, hashlen) != 1
        || EVP_PKEY_derive(pctx, NULL, &retlen) != 1
        || hashlen != retlen
        || EVP_PKEY_derive(pctx, notsecret, &retlen) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cc: notsecret", notsecret, hashlen);
# endif
    if (hashlen < 8
        || !tls13_hkdf_expand(s, md, notsecret,
                              (const unsigned char *)label, labellen,
                              hashval, hashlen, hoval, 8, 1)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    return rv;
}

/*
 * ECH accept_confirmation calculation
 * for_hrr is 1 if this is for an HRR, otherwise for SH
 * ac is (a caller allocated) 8 octet buffer
 * shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * shlen is the length of the SH buf
 * return: 1 for success, 0 otherwise
 *
 * This is a magic value in the ServerHello.random lower 8 octets
 * that is used to signal that the inner worked.
 *
 * As per spec:
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
 */
int ech_calc_confirm(SSL_CONNECTION *s, int for_hrr, unsigned char *acbuf,
                     const unsigned char *shbuf, const size_t shlen)
{
    int rv = 0;
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned char *tbuf = NULL, *conf_loc = NULL;
    unsigned char *fixedshbuf = NULL;
    size_t fixedshbuf_len = 0, tlen = 0, chend = 0;
    size_t shoffset = 6 + 24, extoffset = 0, echoffset = 0;
    uint16_t echtype;
    unsigned int hashlen = 0;
    unsigned char hashval[EVP_MAX_MD_SIZE], hoval[EVP_MAX_MD_SIZE];

    if (ech_get_md_from_hs(s, &md, shbuf, shlen) != 1
        || (hashlen = EVP_MD_size(md)) > EVP_MAX_MD_SIZE)
        goto err;
    if (ech_make_transcript_buffer(s, for_hrr, shbuf, shlen, &tbuf, &tlen,
                                   &chend, &fixedshbuf_len) != 1)
        goto err; /* SSLfatal called already */
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: tbuf b4", tbuf, tlen);
# endif
    /* put zeros in correct place */
    if (for_hrr == 0) { /* zap magic octets at fixed place for SH */
        conf_loc = tbuf + chend + shoffset;
    } else {
        if (s->server == 1) { /* we get to say where we put ECH:-) */
            conf_loc = tbuf + tlen - 8;
        } else {
            if (ech_helper_get_sh_offsets(shbuf, shlen, &extoffset,
                                          &echoffset, &echtype) != 1) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
                goto err;
            }
            if (echoffset == 0 || extoffset == 0 || echtype == 0
                || tlen < (chend + 4 + echoffset + 4 + 8)) {
                /* No ECH found so we'll exit, but set random output */
                if (RAND_bytes_ex(s->ssl.ctx->libctx, acbuf, 8,
                                  RAND_DRBG_STRENGTH) <= 0) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
                    goto err;
                }
                rv = 1;
                goto err;
            }
            conf_loc = tbuf + chend + 4 + echoffset + 4;
        }
    }
    memset(conf_loc, 0, 8);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: tbuf after", tbuf, tlen);
# endif
    hashlen = EVP_MD_size(md);
    if ((ctx = EVP_MD_CTX_new()) == NULL
        || EVP_DigestInit_ex(ctx, md, NULL) <= 0
        || EVP_DigestUpdate(ctx, tbuf, tlen) <= 0
        || EVP_DigestFinal_ex(ctx, hashval, &hashlen) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(ctx);
    ctx = NULL;
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: hashval", hashval, hashlen);
# endif
    if (ech_hkdf_extract_wrap(s, md, for_hrr, hashval, hashlen, hoval) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(acbuf, hoval, 8); /* Finally, set the output */
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: result", acbuf, 8);
# endif
    /* put confirm value back into transcript vars */
    if (s->hello_retry_request != SSL_HRR_NONE && s->ext.ech.kepthrr != NULL
        && for_hrr == 1 && s->server == 1)
        memcpy(s->ext.ech.kepthrr + s->ext.ech.kepthrr_len - 8, acbuf, 8);
    memcpy(conf_loc, acbuf, 8);
    /* on a server, we need to reset the hs buffer now */
    if (s->server && s->hello_retry_request == SSL_HRR_NONE)
        ech_reset_hs_buffer(s, s->ext.ech.innerch, s->ext.ech.innerch_len);
    if (s->server && s->hello_retry_request == SSL_HRR_COMPLETE)
        ech_reset_hs_buffer(s, tbuf, tlen - fixedshbuf_len);
    rv = 1;
err:
    OPENSSL_free(fixedshbuf);
    OPENSSL_free(tbuf);
    EVP_MD_CTX_free(ctx);
    return rv;
}
#endif