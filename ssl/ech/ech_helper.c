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

/* TODO(ECH): move more code that's used by internals and test here */

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
 * return 1 for success, other otherwise
 *
 * Offsets are returned to the type or length field in question.
 * Offsets are set to zero if relevant thing not found.
 *
 * Note: input here is untrusted!
 */
int ech_helper_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                              size_t *exts, size_t *echoffset,
                              uint16_t *echtype)
{
    unsigned int elen = 0, etype = 0, pi_tmp = 0;
    const unsigned char *pp_tmp = NULL, *shstart = NULL, *estart = NULL;
    PACKET pkt;
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
        || !PACKET_get_1(&pkt, &pi_tmp) /* sessid len */
#ifdef OSSL_ECH_SUPERVERBOSE
        || (sessid_len = (size_t)pi_tmp) == 0
#endif
        || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* sessid */
        || !PACKET_get_net_2(&pkt, &pi_tmp) /* ciphersuite */
        || !PACKET_get_1(&pkt, &pi_tmp) /* compression */
        || (*exts = PACKET_data(&pkt) - shstart) == 0
        || !PACKET_get_net_2(&pkt, &pi_tmp)) /* len(extensions) */
        return 0;
    extlens = (size_t)pi_tmp;
    if (extlens == 0) /* not an error, in theory */
        return 1;
    estart = PACKET_data(&pkt);
    while (PACKET_remaining(&pkt) > 0
           && (size_t)(PACKET_data(&pkt) - estart) < extlens
           && done < 1) {
        if (!PACKET_get_net_2(&pkt, &etype)
            || !PACKET_get_net_2(&pkt, &elen))
            return 0;
        if (etype == TLSEXT_TYPE_ech) {
            if (elen == 0)
                return 0;
            *echoffset = PACKET_data(&pkt) - shstart - 4;
            *echtype = etype;
#ifdef OSSL_ECH_SUPERVERBOSE
            echlen = elen + 4; /* type and length included */
#endif
            done++;
        }
        if (!PACKET_get_bytes(&pkt, &pp_tmp, elen))
            return 0;
    }
#ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig SH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
    ech_pbuf("orig SH", (unsigned char *)sh, sh_len);
    ech_pbuf("orig SH session_id", (unsigned char *)sh + sessid_offset,
             sessid_len);
    ech_pbuf("orig SH exts", (unsigned char *)sh + *exts, extlens);
    ech_pbuf("orig SH/ECH ", (unsigned char *)sh + *echoffset, echlen);
#endif
    return 1;
}

/*
 * make up HPKE "info" input as per spec
 * encoding is the ECHconfig being used
 * encodinglen is the length of ECHconfig being used
 * info is a caller-allocated buffer for results
 * info_len is the buffer size on input, used-length on output
 * return 1 for success, other otherwise
 */
int ech_helper_make_enc_info(unsigned char *encoding, size_t encoding_length,
                             unsigned char *info, size_t *info_len)
{
    unsigned char *ip = info;

    if (encoding == NULL || info == NULL || info_len == NULL)
        return 0;
    if (*info_len < (sizeof(OSSL_ECH_CONTEXT_STRING) + encoding_length))
        return 0;
    memcpy(ip, OSSL_ECH_CONTEXT_STRING, sizeof(OSSL_ECH_CONTEXT_STRING) - 1);
    ip += sizeof(OSSL_ECH_CONTEXT_STRING) - 1;
    *ip++ = 0x00;
    memcpy(ip, encoding, encoding_length);
    *info_len = sizeof(OSSL_ECH_CONTEXT_STRING) + encoding_length;
    return 1;
}
