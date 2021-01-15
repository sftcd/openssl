/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl_local.h"
#include "record_local.h"
#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_ECH
static int tls13_enc_ech(SSL *s_in, SSL3_RECORD *recs, size_t n_recs, int sending);
#endif

/*-
 * tls13_enc encrypts/decrypts |n_recs| in |recs|. Will call SSLfatal() for
 * internal errors, but not otherwise.
 *
 * Returns:
 *    0: (in non-constant time) if the record is publicly invalid (i.e. too
 *        short etc).
 *    1: if the record encryption was successful.
 *   -1: if the record's AEAD-authenticator is invalid or, if sending,
 *       an internal error occurred.
 */
int tls13_enc(SSL *s, SSL3_RECORD *recs, size_t n_recs, int sending)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH], recheader[SSL3_RT_HEADER_LENGTH];
    size_t ivlen, taglen, offset, loop, hdrlen;
    unsigned char *staticiv;
    unsigned char *seq;
    int lenu, lenf;
    SSL3_RECORD *rec = &recs[0];
    uint32_t alg_enc;
    WPACKET wpkt;

    if (n_recs != 1) {
        /* Should not happen */
        /* TODO(TLS1.3): Support pipelining */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                 ERR_R_INTERNAL_ERROR);
        return -1;
    }

#ifndef OPENSSL_NO_ECH

#if 0
    /*
     * Only do new stuff if needed - fancy trial decryption (draft-05) version
     */
    if (!sending && !s->server && ( s->ext.inner_s || s->ext.outer_s) && !s->ext.inner_s_ftd) {
        s->ext.inner_s_ftd=1;
        printf("fancy trial decryption coming up - only trying once!\n");
        fflush(stdout);
        return tls13_enc_ech(s,recs,n_recs,sending);
    }
    printf("no fancy trial decryption here\n");
    fflush(stdout);
#endif

#endif

    if (sending) {
        ctx = s->enc_write_ctx;
        staticiv = s->write_iv;
        seq = RECORD_LAYER_get_write_sequence(&s->rlayer);
    } else {
        ctx = s->enc_read_ctx;
        staticiv = s->read_iv;
        seq = RECORD_LAYER_get_read_sequence(&s->rlayer);
    }

    /*
     * If we're sending an alert and ctx != NULL then we must be forcing
     * plaintext alerts. If we're reading and ctx != NULL then we allow
     * plaintext alerts at certain points in the handshake. If we've got this
     * far then we have already validated that a plaintext alert is ok here.
     */
    if (ctx == NULL || rec->type == SSL3_RT_ALERT) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
        return 1;
    }

    ivlen = EVP_CIPHER_CTX_iv_length(ctx);

    if (s->early_data_state == SSL_EARLY_DATA_WRITING
            || s->early_data_state == SSL_EARLY_DATA_WRITE_RETRY) {
        if (s->session != NULL && s->session->ext.max_early_data > 0) {
            alg_enc = s->session->cipher->algorithm_enc;
        } else {
            if (!ossl_assert(s->psksession != NULL
                             && s->psksession->ext.max_early_data > 0)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                         ERR_R_INTERNAL_ERROR);
                return -1;
            }
            alg_enc = s->psksession->cipher->algorithm_enc;
        }
    } else {
        /*
         * To get here we must have selected a ciphersuite - otherwise ctx would
         * be NULL
         */
        if (!ossl_assert(s->s3.tmp.new_cipher != NULL)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                     ERR_R_INTERNAL_ERROR);
            return -1;
        }
        alg_enc = s->s3.tmp.new_cipher->algorithm_enc;
    }

    if (alg_enc & SSL_AESCCM) {
        if (alg_enc & (SSL_AES128CCM8 | SSL_AES256CCM8))
            taglen = EVP_CCM8_TLS_TAG_LEN;
         else
            taglen = EVP_CCM_TLS_TAG_LEN;
         if (sending && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen,
                                         NULL) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                     ERR_R_INTERNAL_ERROR);
            return -1;
        }
    } else if (alg_enc & SSL_AESGCM) {
        taglen = EVP_GCM_TLS_TAG_LEN;
    } else if (alg_enc & SSL_CHACHA20) {
        taglen = EVP_CHACHAPOLY_TLS_TAG_LEN;
    } else {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                 ERR_R_INTERNAL_ERROR);
        return -1;
    }

    if (!sending) {
        /*
         * Take off tag. There must be at least one byte of content type as
         * well as the tag
         */
        if (rec->length < taglen + 1)
            return 0;
        rec->length -= taglen;
    }

    /* Set up IV */
    if (ivlen < SEQ_NUM_SIZE) {
        /* Should not happen */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                 ERR_R_INTERNAL_ERROR);
        return -1;
    }
    offset = ivlen - SEQ_NUM_SIZE;
    memcpy(iv, staticiv, offset);
    for (loop = 0; loop < SEQ_NUM_SIZE; loop++)
        iv[offset + loop] = staticiv[offset + loop] ^ seq[loop];

    /* Increment the sequence counter */
    for (loop = SEQ_NUM_SIZE; loop > 0; loop--) {
        ++seq[loop - 1];
        if (seq[loop - 1] != 0)
            break;
    }
    if (loop == 0) {
        /* Sequence has wrapped */
        return -1;
    }

    /* TODO(size_t): lenu/lenf should be a size_t but EVP doesn't support it */
    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, sending) <= 0
            || (!sending && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                             taglen,
                                             rec->data + rec->length) <= 0)) {
        return -1;
    }

    /* Set up the AAD */
    if (!WPACKET_init_static_len(&wpkt, recheader, sizeof(recheader), 0)
            || !WPACKET_put_bytes_u8(&wpkt, rec->type)
            || !WPACKET_put_bytes_u16(&wpkt, rec->rec_version)
            || !WPACKET_put_bytes_u16(&wpkt, rec->length + taglen)
            || !WPACKET_get_total_written(&wpkt, &hdrlen)
            || hdrlen != SSL3_RT_HEADER_LENGTH
            || !WPACKET_finish(&wpkt)) {
        WPACKET_cleanup(&wpkt);
        return -1;
    }

    /*
     * For CCM we must explicitly set the total plaintext length before we add
     * any AAD.
     */
    if (((alg_enc & SSL_AESCCM) != 0
                 && EVP_CipherUpdate(ctx, NULL, &lenu, NULL,
                                     (unsigned int)rec->length) <= 0)
            || EVP_CipherUpdate(ctx, NULL, &lenu, recheader,
                                sizeof(recheader)) <= 0
            || EVP_CipherUpdate(ctx, rec->data, &lenu, rec->input,
                                (unsigned int)rec->length) <= 0
            || EVP_CipherFinal_ex(ctx, rec->data + lenu, &lenf) <= 0
            || (size_t)(lenu + lenf) != rec->length) {
        return -1;
    }
    if (sending) {
        /* Add the tag */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen,
                                rec->data + rec->length) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                     ERR_R_INTERNAL_ERROR);
            return -1;
        }
        rec->length += taglen;
    }

    return 1;
}

#ifndef OPENSSL_NO_ECH
/*-
 * tls13_enc encrypts/decrypts |n_recs| in |recs|. Will call SSLfatal() for
 * internal errors, but not otherwise.
 *
 * Returns:
 *    0: (in non-constant time) if the record is publicly invalid (i.e. too
 *        short etc).
 *    1: if the record encryption was successful.
 *   -1: if the record's AEAD-authenticator is invalid or, if sending,
 *       an internal error occurred.
 *
 * This version will, as appropriate, check if the keys based on the
 * inner or outer CH are working and, if so, mess with the SSL* so
 * things are good from then on.
 */
int tls13_enc_ech(SSL *s_in, SSL3_RECORD *recs, size_t n_recs, int sending)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH], recheader[SSL3_RT_HEADER_LENGTH];
    size_t ivlen, taglen, offset, loop, hdrlen;
    unsigned char *staticiv;
    unsigned char *seq;
    int lenu, lenf;
    SSL3_RECORD *rec = &recs[0];
    uint32_t alg_enc;
    WPACKET wpkt;
    size_t reclength=0;
    unsigned char *ciphertext_stash=NULL;

    /*
     * If we're sending an alert and ctx != NULL then we must be forcing
     * plaintext alerts. If we're reading and ctx != NULL then we allow
     * plaintext alerts at certain points in the handshake. If we've got this
     * far then we have already validated that a plaintext alert is ok here.
     */
    if (rec->type == SSL3_RT_ALERT) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
        return 1;
    }

    /*
     * New ECH code, vars
     *
     * Here's the ECH plan. If we're a client and this client sent 
     * an inner CH then the client has two sets of keys, the outer 
     * based on the server's public share and the outer CH public
     * share. The 2nd is the inner (in s_in->ext.inner_s) based
     * on the server's public share (likely from DNS) and the inner 
     * CH public share. We'll try both. If there was no inner, then 
     * we'll do the outer one twice for constant time so an observer
     * can't tell if the inner or outer worked just based on
     * this timing. When one of 'em has worked, then we'll
     * modify s_in to have the required keys for later processing.
     * This trickery should only be needed for decrypting the
     * first EncryptedExtension received, we use 
     * s_in->ext.inner_s_checked for that.
     */
    int which_worked=-1;
    int num2try=2;
    SSL *two_sses[2]={NULL,NULL};
    two_sses[0]=s_in;
    if (!s_in->ext.outer_s) two_sses[1]=s_in->ext.inner_s;
    if (!s_in->ext.inner_s) two_sses[1]=s_in->ext.outer_s;

    /*
     * We gotta stash the ciphertext (for now) as the 
     * code below decrypts in-place (when it works)
     * so we need to put things back for 2nd attempt
     */
    ciphertext_stash=OPENSSL_malloc(rec->length);
    if (ciphertext_stash==NULL) {
        SSLfatal(s_in, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC, ERR_R_INTERNAL_ERROR);
        return -1;
    }
    memcpy(ciphertext_stash,rec->data,rec->length);

    int s_cnt=0;
    SSL *s=NULL;
    for (s_cnt=0;s_cnt!=num2try;s_cnt++) {

        s=two_sses[s_cnt];
        printf("trying decryption with s_cnt==%d\n",s_cnt);

	    if (sending) {
	        ctx = s->enc_write_ctx;
	        staticiv = s->write_iv;
            seq = RECORD_LAYER_get_write_sequence(&s->rlayer);
	    } else {
	        ctx = s->enc_read_ctx;
	        staticiv = s->read_iv;
            seq = RECORD_LAYER_get_read_sequence(&s->rlayer);
	    }

	    /*
	     * If we're sending an alert and ctx != NULL then we must be forcing
	     * plaintext alerts. If we're reading and ctx != NULL then we allow
	     * plaintext alerts at certain points in the handshake. If we've got this
	     * far then we have already validated that a plaintext alert is ok here.
	     */
	    if (ctx == NULL) {
	        memmove(rec->data, rec->input, rec->length);
	        rec->input = rec->data;
            printf("Exiting at %d\n",__LINE__);fflush(stdout);
            if (ciphertext_stash!=NULL) {
                OPENSSL_free(ciphertext_stash); 
                ciphertext_stash=NULL;
            }
	        return 1;
	    }

	    ivlen = EVP_CIPHER_CTX_iv_length(ctx);
	
	    if (s->early_data_state == SSL_EARLY_DATA_WRITING
	            || s->early_data_state == SSL_EARLY_DATA_WRITE_RETRY) {
	        if (s->session != NULL && s->session->ext.max_early_data > 0) {
	            alg_enc = s->session->cipher->algorithm_enc;
	        } else {
	            if (!ossl_assert(s->psksession != NULL
	                             && s->psksession->ext.max_early_data > 0)) {
	                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
	                         ERR_R_INTERNAL_ERROR);
                    printf("Exiting at %d\n",__LINE__);fflush(stdout);
	                goto err;
	            }
	            alg_enc = s->psksession->cipher->algorithm_enc;
	        }
	    } else {
	        /*
	         * To get here we must have selected a ciphersuite - otherwise ctx would
	         * be NULL
	         */
	        if (!ossl_assert(s->s3.tmp.new_cipher != NULL)) {
	            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
	                     ERR_R_INTERNAL_ERROR);
                printf("Exiting at %d\n",__LINE__);fflush(stdout);
                goto err;
	        }
	        alg_enc = s->s3.tmp.new_cipher->algorithm_enc;
	    }
	
	    if (alg_enc & SSL_AESCCM) {
	        if (alg_enc & (SSL_AES128CCM8 | SSL_AES256CCM8))
	            taglen = EVP_CCM8_TLS_TAG_LEN;
	         else
	            taglen = EVP_CCM_TLS_TAG_LEN;
	         if (sending && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen,
	                                         NULL) <= 0) {
	            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
	                     ERR_R_INTERNAL_ERROR);
                printf("Exiting at %d\n",__LINE__);fflush(stdout);
	            goto err;
	        }
	    } else if (alg_enc & SSL_AESGCM) {
	        taglen = EVP_GCM_TLS_TAG_LEN;
	    } else if (alg_enc & SSL_CHACHA20) {
	        taglen = EVP_CHACHAPOLY_TLS_TAG_LEN;
	    } else {
	        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
	                 ERR_R_INTERNAL_ERROR);
            printf("Exiting at %d\n",__LINE__);fflush(stdout);
            goto err;
	    }

        if (!sending) {
            /*
             * Reduce by taglen. 
             * There must be at least one byte of content type as well as the tag
             */
            if (rec->length < taglen + 1)
                return 0;
            reclength = rec->length-taglen;
        } else {
            reclength = rec->length;
        }

        /* Set up IV */
        if (ivlen < SEQ_NUM_SIZE) {
            /* Should not happen */
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                    ERR_R_INTERNAL_ERROR);
            printf("Exiting at %d\n",__LINE__);fflush(stdout);
            goto err;
        }
        offset = ivlen - SEQ_NUM_SIZE;
        memcpy(iv, staticiv, offset);
        for (loop = 0; loop < SEQ_NUM_SIZE; loop++)
            iv[offset + loop] = staticiv[offset + loop] ^ seq[loop];

        /* Increment the sequence counter but not twice */
        for (loop = SEQ_NUM_SIZE; loop > 0; loop--) {
            ++seq[loop - 1];
            if (seq[loop - 1] != 0)
                break;
        }
        if (loop == 0) {
             /* Sequence has wrapped */
            printf("Exiting at %d\n",__LINE__);fflush(stdout);
            goto err;
        }

        /* TODO(size_t): lenu/lenf should be a size_t but EVP doesn't support it */
	    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, sending) <= 0
	            || (!sending && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
	                                             taglen,
	                                             rec->data + reclength) <= 0)) {
            printf("Exiting at %d\n",__LINE__);fflush(stdout);
            goto err;
	    }
	
	    /* Set up the AAD */
	    if (!WPACKET_init_static_len(&wpkt, recheader, sizeof(recheader), 0)
	            || !WPACKET_put_bytes_u8(&wpkt, rec->type)
	            || !WPACKET_put_bytes_u16(&wpkt, rec->rec_version)
	            || !WPACKET_put_bytes_u16(&wpkt, reclength + taglen)
	            || !WPACKET_get_total_written(&wpkt, &hdrlen)
	            || hdrlen != SSL3_RT_HEADER_LENGTH
	            || !WPACKET_finish(&wpkt)) {
	        WPACKET_cleanup(&wpkt);
            printf("Exiting at %d\n",__LINE__);fflush(stdout);
            goto err;
	    }
	
	    /*
	     * For CCM we must explicitly set the total plaintext length before we add
	     * any AAD.
	     */
	    if (((alg_enc & SSL_AESCCM) != 0
	                 && EVP_CipherUpdate(ctx, NULL, &lenu, NULL,
	                                     (unsigned int)reclength) <= 0)
	            || EVP_CipherUpdate(ctx, NULL, &lenu, recheader,
	                                sizeof(recheader)) <= 0
	            || EVP_CipherUpdate(ctx, rec->data, &lenu, rec->input,
	                                (unsigned int)reclength) <= 0
	            || EVP_CipherFinal_ex(ctx, rec->data + lenu, &lenf) <= 0
	            || (size_t)(lenu + lenf) != reclength) {
            /*
             * encryption or decryption failed, but maybe try the next one
             */
            printf("decryption failed with s_cnt==%d\n",s_cnt);
            /*
             * Put back ciphertext
             */
            memcpy(rec->data,ciphertext_stash,rec->length);
	    } else {
            printf("fancy trial decryption worked with s_cnt==%d\n",s_cnt);
            which_worked=s_cnt;
            if (!sending) break; // ok bugger constant time for now;-)
        }
	    if (sending) {
	        /* Add the tag */
	        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen,
	                                rec->data + rec->length) <= 0) {
	            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
	                     ERR_R_INTERNAL_ERROR);
	            goto err;
	        }
	        rec->length += taglen;
	    }

    }

    // more new ECH code
    if (ciphertext_stash!=NULL) {
        OPENSSL_free(ciphertext_stash); 
        ciphertext_stash=NULL;
    }
    if (which_worked==-1) {
        /* 
         * do the error thing
         */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (which_worked<0 || which_worked >1) {
        // shouldn't happen, but who knows what the future holds? :-)
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_ENC,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    // fixup rec->length
    if (!sending) rec->length=reclength;

    // now swap out the s_in content as needed
    if (which_worked==1) {
        /*
         * try copy the record layer and see what happens
         */
        s_in->ech_done=1;
        SSL tmp_s=*s_in; // stash outer fields
        two_sses[which_worked]->rlayer=s_in->rlayer;
        *s_in=*two_sses[which_worked];
        *s_in->ext.inner_s=tmp_s; // re-stash outer fields (so we can free later)

        /*
         * Yay - success (for now). This likely belongs
         * elsewhere
         */
        s_in->ech_done=1;
        printf("Success with ECH\n");
        fflush(stdout);
    }

    return 1;
err:
    if (ciphertext_stash!=NULL) {
        OPENSSL_free(ciphertext_stash); 
        ciphertext_stash=NULL;
    }
    return -1;
}

#endif
