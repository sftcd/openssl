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

//#include <ssl/echo_local.h>

typedef enum OPTION_choice {
    /* 
     * standard openssl options
     */
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_IN, OPT_OUT, OPT_INFORM, OPT_OUTFORM, OPT_KEYFORM, OPT_PASSIN,
    OPT_ENGINE,
    /*
     * ECHOCOnfig specifics
     */
    OPT_PUBLICNAME, OPT_ECHOVERSION
} OPTION_CHOICE;

const OPTIONS echo_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {"inform", OPT_INFORM, 'f',
     "Input format - default PEM (one of DER or PEM)"},
    {"in", OPT_IN, '<', "Input file - default stdin"},
    {"outform", OPT_OUTFORM, 'f',
     "Output format - default PEM (one of DER or PEM)"},
    {"out", OPT_OUT, '>', "Output file - default stdout"},
    {"keyform", OPT_KEYFORM, 'E', "Private key format - default PEM"},

    {"public_name", OPT_PUBLICNAME, 's', "public_name value"},
    {"echo_version", OPT_ECHOVERSION, 'n', "ECHOConfig version (default=0xff03)"},

    {NULL}
};

int echo_main(int argc, char **argv)
{
    BIO *out = NULL;
    char *prog;
    char *passin = NULL, *passinarg = NULL;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyformat = FORMAT_PEM;
    char *pkeyfile = NULL;
    EVP_PKEY *pkey = NULL;
    OPTION_CHOICE o;
    ENGINE *e = NULL;

    char *public_name = NULL;
    int echo_version=0xff03;

    int ret=0;

    prog = opt_init(argc, argv, echo_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(echo_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
                goto opthelp;
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PUBLICNAME:
            public_name = opt_arg();
            break;
        case OPT_ECHOVERSION:
            echo_version = atoi(opt_arg());
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
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
     * Not sure we even want this - ESNI/ECHO private keys are
     * for TLS servers only so passwords seem undesirable really.
     * BUT, it could be this is needed if we're using an "engine"
     * that's a HSM. TODO: check
     */
    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    /* 
     * Check ECHO-specific inputs
     */
    switch (echo_version) {
        case 0xff03:
        case 0xff02:
            break;
        default:
            BIO_printf(bio_err, "Unsupported version (0x%04x)- exiting\n",echo_version);
            goto end;
    }

    BIO_printf(bio_err,"ECHOConfig generation is not yet implemented:-)\n");

    /*
     * The plan:
     * If input files are provided, then map those to the chosen output format.
     * If not, generate a new ECHOConfig and spit that out
     */

 end:
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    release_engine(e);
    OPENSSL_free(passin);
    return ret;
}

