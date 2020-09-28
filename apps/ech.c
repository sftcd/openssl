/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ech.h>
#include <crypto/hpke.h>

#ifndef OPENSSL_NO_ECH

typedef enum OPTION_choice {
    /* 
     * standard openssl options
     */
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_PUBOUT, OPT_PRIVOUT, OPT_PEMOUT, 
    /*
     * ECHCOnfig specifics
     */
    OPT_PUBLICNAME, OPT_ECHVERSION
} OPTION_CHOICE;

const OPTIONS ech_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"pemout", OPT_PEMOUT, '>', "PEM output file with private key and ECHConfig - default echconfig.pem"},
    {"pubout", OPT_PUBOUT, '>', "Public key output file - default unset"},
    {"privout", OPT_PRIVOUT, '>', "Private key output file - default unset"},
    {"public_name", OPT_PUBLICNAME, 's', "public_name value"},
    {"ech_version", OPT_ECHVERSION, 'n', "ECHConfig version (default=0xff07)"},
    {NULL}
};

/**
 * @brief map version string like 0xff01 or 65291 to uint16_t
 * @param arg is the version string, from command line
 * @return is the uint16_t value (with zero for error cases)
 */
static uint16_t verstr2us(char *arg)
{
    long lv=strtol(arg,NULL,0);
    uint16_t rv=0;
    if (lv < 0xffff && lv > 0 ) {
        rv=(uint16_t)lv;
    }
    return(rv);
}

/**
 * @brief Make an X25519 key pair and ECHConfig structure 
 * @param ekversion is the version to make
 * @param public_name is for inclusion within the ECHConfig
 *
 * @return 1 for success, error otherwise
 */
static int mk_echconfig(
        uint16_t ekversion,
        const char *public_name,
        size_t *echconfig_len, unsigned char *echconfig,
        size_t *privlen, unsigned char *priv)
{
    size_t pnlen=0; ///< length of public_name

    switch(ekversion) {
        case ECH_DRAFT_07_VERSION: 
        case ECH_DRAFT_PRE08_VERSION: 
            pnlen=(public_name==NULL?0:strlen(public_name));
            break;
        default:
            return 0;
    }

    /*
     * We don't need no crazy extensions... yet;-(
     */
    size_t extlen=0;
    unsigned char *extvals=NULL;

    /* new private key please... */
    if (priv==NULL) { return (__LINE__); }

    int hpke_mode=HPKE_MODE_BASE;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    size_t publen=HPKE_MAXSIZE; unsigned char pub[HPKE_MAXSIZE];
    int rv=hpke_kg(
        hpke_mode, hpke_suite,
        &publen, pub,
        privlen, priv); 
    if (rv!=1) { return(__LINE__); }
 
    /*
     * This is what's in draft-07:
     *
     *
     *  opaque HpkePublicKey<1..2^16-1>;
     *  uint16 HkpeKemId;  // Defined in I-D.irtf-cfrg-hpke
     *  uint16 HkpeKdfId;  // Defined in I-D.irtf-cfrg-hpke
     *  uint16 HkpeAeadId; // Defined in I-D.irtf-cfrg-hpke
     *  struct {
     *      HkpeKdfId kdf_id;
     *      HkpeAeadId aead_id;
     *  } HpkeCipherSuite;
     *  struct {
     *      opaque public_name<1..2^16-1>;
     *      HpkePublicKey public_key;
     *      HkpeKemId kem_id;
     *      HpkeCipherSuite cipher_suites<4..2^16-2>;
     *      uint16 maximum_name_length;
     *      Extension extensions<0..2^16-1>;
     *  } ECHConfigContents;
     *  struct {
     *      uint16 version;
     *      uint16 length;
     *      select (ECHConfig.version) {
     *        case 0xff07: ECHConfigContents;
     *      }
     *  } ECHConfig;
     *  ECHConfig ECHConfigs<1..2^16-1>;
     */

    unsigned char bbuf[ECH_MAX_ECHCONFIGS_BUFLEN]; ///< binary buffer
    unsigned char *bp=bbuf;
    memset(bbuf,0,ECH_MAX_ECHCONFIGS_BUFLEN);
    *bp++=0x00; // leave space for overall length
    *bp++=0x00; // leave space for overall length
    *bp++=(ekversion>>8)%256; 
    *bp++=(ekversion%256); 
    *bp++=0x00; // leave space for almost-overall length
    *bp++=0x00; // leave space for almost-overall length
    if (pnlen > 0 ) {
        *bp++=(pnlen>>8)%256;
        *bp++=pnlen%256;
        memcpy(bp,public_name,pnlen); bp+=pnlen;
    }
    /* keys */
    *bp++=0x00;
    *bp++=0x24; // length=36
    *bp++=0x00;
    *bp++=0x1d; // curveid=X25519= decimal 29
    *bp++=0x00;
    *bp++=0x20; // length=32
    memcpy(bp,pub,32); bp+=32;
    /* HPKE KEM id */
    *bp++=(HPKE_KEM_ID_25519/16);
    *bp++=(HPKE_KEM_ID_25519%16);
    /* cipher_suite */
    *bp++=0x00;
    *bp++=0x04;
    *bp++=(HPKE_KDF_ID_HKDF_SHA256/16);
    *bp++=(HPKE_KDF_ID_HKDF_SHA256%16);
    *bp++=(HPKE_AEAD_ID_AES_GCM_128/16);
    *bp++=(HPKE_AEAD_ID_AES_GCM_128%16);
    /* maximum_name_length */
    *bp++=0x00;
    *bp++=0x00; 
    if (extlen==0) {
        *bp++=0x00;
        *bp++=0x00; // no extensions
    } else {
        if (!extvals) {
            return(__LINE__);
        }
        memcpy(bp,extvals,extlen);
        bp+=extlen;
        free(extvals);
    }
    size_t bblen=bp-bbuf;

    /*
     * Add back in the length
     */
    bbuf[0]=(bblen-2)/256;
    bbuf[1]=(bblen-2)%256;
    bbuf[4]=(bblen-4)/256;
    bbuf[5]=(bblen-4)%256;

    int b64len = EVP_EncodeBlock((unsigned char*)echconfig, (unsigned char *)bbuf, bblen);
    if (b64len >=(*echconfig_len-1)) {
        return(__LINE__);
    }
    echconfig[b64len]='\0';
    *echconfig_len=b64len;

    return(1);
}

int ech_main(int argc, char **argv)
{
    BIO *pemf=NULL;
    char *prog=NULL;
    OPTION_CHOICE o;
    char *echconfig_file = NULL, *keyfile = NULL, *pemfile=NULL;
    char *public_name=NULL;
    uint16_t ech_version=ECH_DRAFT_PRE08_VERSION;

    prog = opt_init(argc, argv, ech_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(ech_options);
            goto end;
        case OPT_PUBOUT:
            echconfig_file = opt_arg();
            break;
        case OPT_PRIVOUT:
            keyfile = opt_arg();
            break;
        case OPT_PEMOUT:
            pemfile = opt_arg();
            break;
        case OPT_PUBLICNAME:
            public_name = opt_arg();
            break;
        case OPT_ECHVERSION:
            ech_version = verstr2us(opt_arg());
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    if (argc != 0) {
        BIO_printf(bio_err, "%s: Unknown parameter %s\n", prog, argv[0]);
        goto opthelp;
    }

    /* 
     * Check ECH-specific inputs
     */
    switch (ech_version) {
        case 0xff02:
        case 0xff01:
            BIO_printf(bio_err, "Unsupported version (0x%04x) - try using mk_esnikeys instead\n",ech_version);
            goto end;
        case ECH_DRAFT_07_VERSION:
        case ECH_DRAFT_PRE08_VERSION:
            break;
        default:
            BIO_printf(bio_err, "Unsupported version (0x%04x) - exiting\n",ech_version);
            goto end;
    }

    /*
     * Set default if needed
     */
    if (pemfile==NULL) {
        pemfile="echconfig.pem";
    }

    /*
     * Generate a new ECHConfig and spit that out
     */

    size_t echconfig_len=ECH_MAX_ECHCONFIGS_BUFLEN;
    unsigned char echconfig[ECH_MAX_ECHCONFIGS_BUFLEN];
    size_t privlen=HPKE_MAXSIZE; unsigned char priv[HPKE_MAXSIZE];
    int rv=mk_echconfig(ech_version, public_name, &echconfig_len, echconfig, &privlen, priv);
    if (rv!=1) {
        BIO_printf(bio_err,"mk_echconfig error: %d\n",rv);
        goto end;
    }
    
    /*
     * Write stuff to files, "proper" OpenSSL code needed
     */
    if (echconfig_file!=NULL) {
        BIO *ecf=BIO_new_file(echconfig_file,"w");
        if (ecf==NULL) goto end;
        BIO_write(ecf,echconfig,echconfig_len);
        BIO_printf(ecf,"\n");
        BIO_free_all(ecf);
        BIO_printf(bio_err,"Wrote ECHConfig to %s\n",echconfig_file);
    }
    if (keyfile!=NULL) {
        BIO *kf=BIO_new_file(keyfile,"w");
        if (kf==NULL) goto end;
        BIO_write(kf,priv,privlen);
        BIO_free_all(kf);
        BIO_printf(bio_err,"Wrote ECH private key to %s\n",keyfile);
    }
    /*
     * If we didn't write out either of the above then
     * we'll create a PEM file
     */
    if (keyfile==NULL && echconfig_file==NULL) {
        if ((pemf = BIO_new_file(pemfile, "w")) == NULL) goto end;
        BIO_write(pemf,priv,privlen);
        BIO_printf(pemf,"-----BEGIN ECHCONFIG-----\n");
        BIO_write(pemf,echconfig,echconfig_len);
        BIO_printf(pemf,"\n");
        BIO_printf(pemf,"-----END ECHCONFIG-----\n");
        BIO_free_all(pemf);
        BIO_printf(bio_err,"Wrote ECH key pair to %s\n",pemfile);
    } else {
        if (keyfile==NULL) 
            BIO_printf(bio_err,"Didn't write private key anywhere! That's a bit silly\n");
        if (echconfig_file==NULL) 
            BIO_printf(bio_err,"Didn't write ECHConfig anywhere! That's a bit silly\n");
    }
    return(1);
end:
    return(0);
}

#endif

