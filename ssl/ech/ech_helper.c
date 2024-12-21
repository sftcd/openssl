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
#include "internal/ech_helpers.h"

/* used in ECH crypto derivations (odd format for EBCDIC goodness) */
/* "tls ech" */
static const char OSSL_ECH_CONTEXT_STRING[] = "\x74\x6c\x73\x20\x65\x63\x68";

/*
 * Given a SH (or HRR) find the offsets of the ECH (if any)
 * sh is the SH buffer
 * sh_len is the length of the SH
 * exts points to offset of extensions
 * echoffset points to offset of ECH
 * echtype points to the ext type of the ECH
 * return 1 for success, zero otherwise
 *
 * Offsets are returned to the type or length field in question.
 * Offsets are set to zero if relevant thing not found.
 *
 * Note: input here is untrusted!
 */
int ossl_ech_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                            size_t *exts, size_t *echoffset,
                            uint16_t *echtype)
{
    unsigned int etype = 0, pi_tmp = 0;
    const unsigned char *pp_tmp = NULL, *shstart = NULL;
    PACKET pkt, session_id, extpkt, oneext;
    size_t extlens = 0;
    int done = 0;
#ifdef OSSL_ECH_SUPERVERBOSE
    size_t echlen = 0; /* length of ECH, including type & ECH-internal length */
    size_t sessid_offset = 0, sessid_len = 0;
#endif

    if (sh == NULL || sh_len == 0 || exts == NULL || echoffset == NULL
        || echtype == NULL)
        return 0;
    *exts = *echoffset = *echtype = 0;
    if (!PACKET_buf_init(&pkt, sh, sh_len))
        return 0;
    shstart = PACKET_data(&pkt);
    if (!PACKET_get_net_2(&pkt, &pi_tmp))
        return 0;
    /*
     * TODO(ECH): we've had a TLSv1.2 test in the past where we add an
     * ECH to a TLSv1.2 CH to ensure server code ignores that properly.
     * We might or might not keep that, if we don't then the test below
     * should allow TLSv1.3 only.
     */
    /* if we're not TLSv1.2+ then we can bail, but it's not an error */
    if (pi_tmp != TLS1_2_VERSION && pi_tmp != TLS1_3_VERSION)
        return 1;
    if (!PACKET_get_bytes(&pkt, &pp_tmp, SSL3_RANDOM_SIZE)
#ifdef OSSL_ECH_SUPERVERBOSE
        || (sessid_offset = PACKET_data(&pkt) - shstart) == 0
#endif
        || !PACKET_get_length_prefixed_1(&pkt, &session_id)
#ifdef OSSL_ECH_SUPERVERBOSE
        || (sessid_len = PACKET_remaining(&session_id)) == 0
#endif
        || !PACKET_get_net_2(&pkt, &pi_tmp) /* ciphersuite */
        || !PACKET_get_1(&pkt, &pi_tmp) /* compression */
        || (*exts = PACKET_data(&pkt) - shstart) == 0
        || !PACKET_as_length_prefixed_2(&pkt, &extpkt)
        || PACKET_remaining(&pkt) != 0)
        return 0;
    extlens = PACKET_remaining(&extpkt);
    if (extlens == 0) /* not an error, in theory */
        return 1;
    while (PACKET_remaining(&extpkt) > 0 && done < 1) {
        if (!PACKET_get_net_2(&extpkt, &etype)
            || !PACKET_get_length_prefixed_2(&extpkt, &oneext))
            return 0;
        if (etype == TLSEXT_TYPE_ech) {
            if (PACKET_remaining(&oneext) != 8)
                return 0;
            *echoffset = PACKET_data(&oneext) - shstart - 4;
            *echtype = etype;
#ifdef OSSL_ECH_SUPERVERBOSE
            echlen = PACKET_remaining(&oneext) + 4; /* type/length included */
#endif
            done++;
        }
    }
#ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig SH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
    ossl_ech_pbuf("orig SH", (unsigned char *)sh, sh_len);
    ossl_ech_pbuf("orig SH session_id", (unsigned char *)sh + sessid_offset,
                  sessid_len);
    ossl_ech_pbuf("orig SH exts", (unsigned char *)sh + *exts, extlens);
    ossl_ech_pbuf("orig SH/ECH ", (unsigned char *)sh + *echoffset, echlen);
#endif
    return 1;
}

/*
 * make up HPKE "info" input as per spec
 * encoding is the ECHconfig being used
 * encodinglen is the length of ECHconfig being used
 * info is a caller-allocated buffer for results
 * info_len is the buffer size on input, used-length on output
 * return 1 for success, zero otherwise
 */
int ossl_ech_make_enc_info(unsigned char *encoding, size_t encoding_length,
                           unsigned char *info, size_t *info_len)
{
    WPACKET ipkt = { 0 };
    BUF_MEM *ipkt_mem = NULL;

    if (encoding == NULL || info == NULL || info_len == NULL)
        return 0;
    if (*info_len < (sizeof(OSSL_ECH_CONTEXT_STRING) + encoding_length))
        return 0;
    if ((ipkt_mem = BUF_MEM_new()) == NULL
        || !WPACKET_init(&ipkt, ipkt_mem)
        || !WPACKET_memcpy(&ipkt, OSSL_ECH_CONTEXT_STRING,
                           sizeof(OSSL_ECH_CONTEXT_STRING) - 1)
        /*
         * the zero valued octet is required by the spec, section 7.1 so
         * a tiny bit better to add it explicitly rather than depend on
         * the context string being NUL terminated
         */
        || !WPACKET_put_bytes_u8(&ipkt, 0)
        || !WPACKET_memcpy(&ipkt, encoding, encoding_length)) {
        WPACKET_cleanup(&ipkt);
        BUF_MEM_free(ipkt_mem);
        return 0;
    }
    *info_len = sizeof(OSSL_ECH_CONTEXT_STRING) + encoding_length;
    memcpy(info, WPACKET_get_curr(&ipkt) - *info_len, *info_len);
    WPACKET_cleanup(&ipkt);
    BUF_MEM_free(ipkt_mem);
    return 1;
}

/*
 * Given a CH find the offsets of the session id, extensions and ECH
 * ch is the encoded client hello
 * ch_len is the length of ch
 * sessid returns offset of session_id length
 * exts points to offset of extensions
 * extlens returns length of extensions
 * echoffset returns offset of ECH
 * echtype returns the ext type of the ECH
 * echlen returns the length of the ECH
 * snioffset returns offset of (outer) SNI
 * snilen returns the length of the SNI
 * inner 1 if the ECH is marked as an inner, 0 for outer
 * return 1 for success, other otherwise
 *
 * Offsets are set to zero if relevant thing not found.
 * Offsets are returned to the type or length field in question.
 *
 * Note: input here is untrusted!
 */
int ech_helper_get_ch_offsets(const unsigned char *ch, size_t ch_len,
                              size_t *sessid, size_t *exts, size_t *extlens,
                              size_t *echoffset, uint16_t *echtype,
                              size_t *echlen,
                              size_t *snioffset, size_t *snilen, int *inner)
{
    unsigned int elen = 0, etype = 0, pi_tmp = 0;
    const unsigned char *pp_tmp = NULL, *chstart = NULL, *estart = NULL;
    PACKET pkt;
    int done = 0;

    if (ch == NULL || ch_len == 0 || sessid == NULL || exts == NULL
        || echoffset == NULL || echtype == NULL || echlen == NULL
        || inner == NULL
        || snioffset == NULL)
        return 0;
    *sessid = *exts = *echoffset = *snioffset = *snilen = *echlen = 0;
    *echtype = 0xffff;
    if (!PACKET_buf_init(&pkt, ch, ch_len))
        return 0;
    chstart = PACKET_data(&pkt);
    if (!PACKET_get_net_2(&pkt, &pi_tmp))
        return 0;
    /* if we're not TLSv1.2+ then we can bail, but it's not an error */
    if (pi_tmp != TLS1_2_VERSION && pi_tmp != TLS1_3_VERSION)
        return 1;
    /* chew up the packet to extensions */
    if (!PACKET_get_bytes(&pkt, &pp_tmp, SSL3_RANDOM_SIZE)
        || (*sessid = PACKET_data(&pkt) - chstart) == 0
        || !PACKET_get_1(&pkt, &pi_tmp) /* sessid len */
        || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* sessid */
        || !PACKET_get_net_2(&pkt, &pi_tmp) /* ciphersuite len */
        || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* suites */
        || !PACKET_get_1(&pkt, &pi_tmp) /* compression meths */
        || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* comp meths */
        || (*exts = PACKET_data(&pkt) - chstart) == 0
        || !PACKET_get_net_2(&pkt, &pi_tmp) /* len(extensions) */
        || (*extlens = (size_t) pi_tmp) == 0)
        /*
         * unexpectedly, we return 1 here, as doing otherwise will
         * break some non-ECH test code that truncates CH messages
         * The same is true below when looking through extensions.
         * That's ok though, we'll only set those offsets we've
         * found.
         */
        return 1;
    /* no extensions is theoretically ok, if uninteresting */
    if (*extlens == 0)
        return 1;
    /* find what we want from extensions */
    estart = PACKET_data(&pkt);
    while (PACKET_remaining(&pkt) > 0
           && (size_t)(PACKET_data(&pkt) - estart) < *extlens
           && done < 2) {
        if (!PACKET_get_net_2(&pkt, &etype)
            || !PACKET_get_net_2(&pkt, &elen))
            return 1; /* see note above */
        if (etype == TLSEXT_TYPE_ech) {
            if (elen == 0)
                return 0;
            *echoffset = PACKET_data(&pkt) - chstart - 4;
            *echtype = etype;
            *echlen = elen;
            done++;
        }
        if (etype == TLSEXT_TYPE_server_name) {
            *snioffset = PACKET_data(&pkt) - chstart - 4;
            *snilen = elen;
            done++;
        }
        if (!PACKET_get_bytes(&pkt, &pp_tmp, elen))
            return 1; /* see note above */
        if (etype == TLSEXT_TYPE_ech)
            *inner = pp_tmp[0];
    }
    return 1;
}
