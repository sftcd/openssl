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
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ech.h>
#include <crypto/hpke.h>

#include <openssl/objects.h>
#include <openssl/x509.h>

#ifndef OPENSSL_NO_ECH

#define ECH_MAX_ECHCONFIGS_BUFLEN 2000  /**< max PEM encoded ECHConfigs we'll emit */

typedef enum OPTION_choice {
    /* 
     * standard openssl options
     */
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_PUBOUT, OPT_PRIVOUT, OPT_PEMOUT, 
    /*
     * ECHConfig specifics
     */
    OPT_PUBLICNAME, OPT_ECHVERSION, 
    OPT_MAXNAMELENGTH, OPT_HPKESUITE,
    OPT_ECHEXTFILE
} OPTION_CHOICE;

const OPTIONS ech_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"pemout", OPT_PEMOUT, '>', "PEM output file with private key and ECHConfig - default echconfig.pem"},
    {"pubout", OPT_PUBOUT, '>', "Public key output file - default unset"},
    {"privout", OPT_PRIVOUT, '>', "Private key output file - default unset"},
    {"public_name", OPT_PUBLICNAME, 's', "public_name value"},
    {"mlen", OPT_MAXNAMELENGTH, 'n', "maximum name length value"},
    {"suite", OPT_HPKESUITE, 's', "HPKE ciphersuite: e.g. \"0x20,1,3\""},
    {"ech_version", OPT_ECHVERSION, 'n', "ECHConfig draft version(default=0xff0a (10), also supported: 0xff09 (9))"},
    {"extfile", OPT_ECHEXTFILE, 's', "Name fo a file containing encoded extensions\n"},
    {NULL}
};

/*
 * TODO: figure out how to get that much text into a help string... 
 *
 *  fprintf(stderr,"- Ciphersuites are specified using a comma-separated list of numbers\n");
 *  fprintf(stderr,"  e.g. \"-c 0x20,1,3\" or a comma-separated list of strings from:\n");
 *  fprintf(stderr,"      KEMs: %s, %s, %s, %s or %s\n",
 *          HPKE_KEMSTR_P256, HPKE_KEMSTR_P384, HPKE_KEMSTR_P521, HPKE_KEMSTR_X25519, HPKE_KEMSTR_X448);
 *  fprintf(stderr,"      KDFs: %s, %s or %s\n",
 *          HPKE_KDFSTR_256, HPKE_KDFSTR_384, HPKE_KDFSTR_512);
 *  fprintf(stderr,"      AEADs: %s, %s or %s\n",
 *          HPKE_AEADSTR_AES128GCM, HPKE_AEADSTR_AES256GCM, HPKE_AEADSTR_CP);
 *  fprintf(stderr,"  For example \"-c %s,%s,%s\" (the default)\n",
 *          HPKE_KEMSTR_X25519, HPKE_KDFSTR_256, HPKE_AEADSTR_AES128GCM);
 *
 *  The above is code from the usage() function in happykey/hpkemain.c
 */

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


/*
 * @brief string matching for suites
 */
#define HPKE_MSMATCH(inp,known) (strlen(inp)==strlen(known) && !strcasecmp(inp,known))

#define ECH_MAXSUITESTR 32 /* a max suitestr len just for sanity checking */
#define ECH_MAXEXTLEN 513 /* a max extensions len just for sanity checking */

/**
 * @brief parse a string into an HPKE ciphersuite
 * @param suitestr is from the command line
 * @param hpke_suite is the hpke_suite_t result
 * @return 1 for success something else otherwise
 */
static int suitestr2suite(char *instr, hpke_suite_t *hpke_suite)
{
    uint16_t kem=0,kdf=0,aead=0;
    char *suitestr=NULL;
    char *st=NULL;
    if (!instr) return(0);
    if (!hpke_suite) return(0);
    if (strlen(instr)>ECH_MAXSUITESTR) return(0);
    suitestr=OPENSSL_strdup(instr);
    /* See if it contains a mix of our strings and numbers  */
    st=strtok(suitestr,",");
    if (!st) { free(suitestr); return(0); }
    while (st!=NULL) {
        /* check if string is known or number and if so handle appropriately */
        if (kem==0) {
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_P256)) kem=HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_P384)) kem=HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_P521)) kem=HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_X25519)) kem=HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_X448)) kem=HPKE_KEM_ID_448;
            if (HPKE_MSMATCH(st,"0x10")) kem=HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st,"16")) kem=HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st,"0x11")) kem=HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st,"17")) kem=HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st,"0x12")) kem=HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st,"18")) kem=HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st,"0x20")) kem=HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st,"32")) kem=HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st,"0x21")) kem=HPKE_KEM_ID_448;
            if (HPKE_MSMATCH(st,"33")) kem=HPKE_KEM_ID_448;
        } else if (kem!=0 && kdf==0) {
            if (HPKE_MSMATCH(st,HPKE_KDFSTR_256)) kdf=1;
            if (HPKE_MSMATCH(st,HPKE_KDFSTR_384)) kdf=2;
            if (HPKE_MSMATCH(st,HPKE_KDFSTR_512)) kdf=3;
            if (HPKE_MSMATCH(st,"1")) kdf=1;
            if (HPKE_MSMATCH(st,"2")) kdf=2;
            if (HPKE_MSMATCH(st,"3")) kdf=3;
            if (HPKE_MSMATCH(st,"0x01")) kdf=1;
            if (HPKE_MSMATCH(st,"0x02")) kdf=2;
            if (HPKE_MSMATCH(st,"0x03")) kdf=3;
        } else if (kem!=0 && kdf!=0 && aead==0) {
            if (HPKE_MSMATCH(st,HPKE_AEADSTR_AES128GCM)) aead=1;
            if (HPKE_MSMATCH(st,HPKE_AEADSTR_AES256GCM)) aead=2;
            if (HPKE_MSMATCH(st,HPKE_AEADSTR_CP)) aead=3;
            if (HPKE_MSMATCH(st,"1")) aead=1;
            if (HPKE_MSMATCH(st,"2")) aead=2;
            if (HPKE_MSMATCH(st,"0x01")) aead=1;
            if (HPKE_MSMATCH(st,"0x02")) aead=2;
            if (HPKE_MSMATCH(st,"0x03")) aead=3;
        }
        st=strtok(NULL,",");
    }
    OPENSSL_free(suitestr);
    if (kem==0||kdf==0||aead==0) return(0);
    hpke_suite->kem_id=kem;
    hpke_suite->kdf_id=kdf;
    hpke_suite->aead_id=aead;
    return 1;
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
        uint16_t max_name_length,
        const char *public_name,
        hpke_suite_t hpke_suite,
        size_t extlen, unsigned char *extvals,
        size_t *echconfig_len, unsigned char *echconfig,
        size_t *privlen, unsigned char *priv)
{
    size_t pnlen=0; 
    int hpke_mode=HPKE_MODE_BASE;
    size_t publen=HPKE_MAXSIZE; unsigned char pub[HPKE_MAXSIZE];
    int rv=0;
    unsigned char bbuf[ECH_MAX_ECHCONFIGS_BUFLEN]; 
    unsigned char *bp=bbuf;
    size_t bblen=0;
    unsigned int b64len = 0;

    switch(ekversion) {
        case ECH_DRAFT_09_VERSION: 
        case ECH_DRAFT_10_VERSION: 
            pnlen=(public_name==NULL?0:strlen(public_name));
            break;
        default:
            return 0;
    }

    /* new private key please... */
    if (priv==NULL) { return (__LINE__); }

    rv=hpke_kg(
        hpke_mode, hpke_suite,
        &publen, pub,
        privlen, priv); 
    if (rv!=1) { return(__LINE__); }
 
    /*
     * This is what's in draft-09:
     * 
     *   opaque HpkePublicKey<1..2^16-1>;
     *   uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
     *   struct {
     *       HpkeKdfId kdf_id;
     *       HpkeAeadId aead_id;
     *   } ECHCipherSuite;
     *   struct {
     *       opaque public_name<1..2^16-1>;
     *       HpkePublicKey public_key;
     *       HpkeKemId kem_id;
     *       ECHCipherSuite cipher_suites<4..2^16-4>;
     *       uint16 maximum_name_length;
     *       Extension extensions<0..2^16-1>;
     *   } ECHConfigContents;
     *   struct {
     *       uint16 version;
     *       uint16 length;
     *       select (ECHConfig.version) {
     *         case 0xfe09: ECHConfigContents contents;
     *       }
     *   } ECHConfig;
     *
     * And in draft-10 we find:
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
     *       uint16 maximum_name_length;
     *       opaque public_name<1..2^16-1>;
     *       Extension extensions<0..2^16-1>;
     *   } ECHConfigContents;
     *   struct {
     *       uint16 version;
     *       uint16 length;
     *       select (ECHConfig.version) {
     *         case 0xfe0a: ECHConfigContents contents;
     *       }
     *   } ECHConfig;
     *
     */

    memset(bbuf,0,ECH_MAX_ECHCONFIGS_BUFLEN);
    *bp++=0x00; /* leave space for overall length */
    *bp++=0x00; /* leave space for overall length */
    *bp++=(ekversion>>8)%256; 
    *bp++=(ekversion%256); 
    *bp++=0x00; /* leave space for almost-overall length */
    *bp++=0x00; /* leave space for almost-overall length */
    if (ekversion==ECH_DRAFT_10_VERSION) {
        uint8_t config_id=0;
        RAND_bytes(&config_id,1);
        *bp++=config_id;
        *bp++=(hpke_suite.kem_id>>8)%256;
        *bp++=(hpke_suite.kem_id%256);
        /* keys */
        *bp++=(publen>>8)%256;
        *bp++=(publen%256);
        memcpy(bp,pub,publen); bp+=publen;
        /* cipher_suite */
        *bp++=0x00;
        *bp++=0x04;
        *bp++=(hpke_suite.kdf_id>>8)%256;
        *bp++=(hpke_suite.kdf_id%256);
        *bp++=(hpke_suite.aead_id>>8)%256;
        *bp++=(hpke_suite.aead_id%256);
        /* maximum_name_length */
        *bp++=(max_name_length>>8)%256;
        *bp++=(max_name_length%256);
        /* public_name */
        if (pnlen > 0 ) {
            *bp++=(pnlen>>8)%256;
            *bp++=pnlen%256;
            memcpy(bp,public_name,pnlen); bp+=pnlen;
        }
    }

    if (ekversion==ECH_DRAFT_09_VERSION) {
        if (pnlen > 0 ) {
            *bp++=(pnlen>>8)%256;
            *bp++=pnlen%256;
            memcpy(bp,public_name,pnlen); bp+=pnlen;
        }
        /* keys */
        *bp++=(publen>>8)%256;
        *bp++=(publen%256);
        memcpy(bp,pub,publen); bp+=publen;
        /* HPKE KEM id */
        *bp++=(hpke_suite.kem_id>>8)%256;
        *bp++=(hpke_suite.kem_id%256);
        /* cipher_suite */
        *bp++=0x00;
        *bp++=0x04;
        *bp++=(hpke_suite.kdf_id>>8)%256;
        *bp++=(hpke_suite.kdf_id%256);
        *bp++=(hpke_suite.aead_id>>8)%256;
        *bp++=(hpke_suite.aead_id%256);
        /* maximum_name_length */
        *bp++=(max_name_length>>8)%256;
        *bp++=(max_name_length%256);
    }

    if (extlen==0) {
        *bp++=0x00;
        *bp++=0x00; /* no extensions */
    } else {
        if (!extvals) {
            return(__LINE__);
        }
        *bp++=(extlen>>8)%256;
        *bp++=(extlen%256);
        memcpy(bp,extvals,extlen); bp+=extlen;
    }
    bblen=bp-bbuf;

    /*
     * Add back in the length
     */
    bbuf[0]=(bblen-2)/256;
    bbuf[1]=(bblen-2)%256;
    bbuf[4]=(bblen-6)/256;
    bbuf[5]=(bblen-6)%256;

    b64len = EVP_EncodeBlock((unsigned char*)echconfig, (unsigned char *)bbuf, bblen);
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
    char *suitestr=NULL;
    char *extfile=NULL;
    unsigned char extvals[ECH_MAXEXTLEN];
    size_t extlen=ECH_MAXEXTLEN;
    uint16_t ech_version=ECH_DRAFT_10_VERSION;
    uint16_t max_name_length=0;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    size_t echconfig_len=ECH_MAX_ECHCONFIGS_BUFLEN;
    unsigned char echconfig[ECH_MAX_ECHCONFIGS_BUFLEN];
    size_t privlen=HPKE_MAXSIZE; unsigned char priv[HPKE_MAXSIZE];
    int rv=0;

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
        case OPT_MAXNAMELENGTH:
            {
            long tmp = strtol(opt_arg(),NULL,10);
            if (tmp<0 || tmp>65535) {
                BIO_printf(bio_err, "max name length out of range [0,65553] (%ld)\n", tmp);
                goto opthelp;
            } else {
                max_name_length=(uint16_t)tmp;
            }
            }
            break;
        case OPT_HPKESUITE:
            suitestr=opt_arg();
            break;
        case OPT_ECHEXTFILE:
            extfile=opt_arg();
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
        case 0xff01: /* ESNI precursors */
        case 0xff02: /* ESNI precursors */
        case 1:
        case 2:
            BIO_printf(bio_err, "No longer supported older version (0x%04x) - try using mk_esnikeys instead\n",ech_version);
            goto end;
        case ECH_DRAFT_09_VERSION:
            break;
        case 9:
            ech_version=0xfe09;
            break;
        case ECH_DRAFT_10_VERSION:
            break;
        case 10:
            ech_version=0xfe0a;
            break;
        default:
            BIO_printf(bio_err, "Unsupported version (0x%04x) - exiting\n",ech_version);
            ERR_print_errors(bio_err);
            goto end;
    }

    if (max_name_length>TLSEXT_MAXLEN_host_name) {
        BIO_printf(bio_err, 
                "Weird max name length (0x%04x) - biggest is (0x%04x) - exiting\n",
                max_name_length,TLSEXT_MAXLEN_host_name);
        ERR_print_errors(bio_err);
        goto end;
    }

    if (suitestr!=NULL) {
        if (suitestr2suite(suitestr,&hpke_suite)!=1) {
            BIO_printf(bio_err, "Bad HPKE_SUITE (%s)\n",suitestr);
            ERR_print_errors(bio_err);
            goto end;
        }
    }
 
    if (extfile!=NULL) {
        BIO *eb=BIO_new_file(extfile,"rb");
        if (!eb) {
            BIO_printf(bio_err, "Can't open ECH extensions file %s\n",extfile);
            ERR_print_errors(bio_err);
            goto end;
        }
        extlen = BIO_read(eb, extvals, extlen);
        BIO_free(eb);
        if (extlen <= 0) {
            BIO_printf(bio_err, "Error reading ECH extensions file %s\n", extfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    } else {
        extlen=0;
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

    rv=mk_echconfig(ech_version, max_name_length, public_name, hpke_suite, extlen, extvals, &echconfig_len, echconfig, &privlen, priv);
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

