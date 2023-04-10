/*
 * Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include <openssl/ech.h>
#include <internal/ech_helpers.h>

#ifndef OPENSSL_NO_ECH

# define OSSL_ECH_MAX_LINELEN 1000 /* for a sanity check */
# define DEF_CERTS_DIR "test/certs"

static int verbose = 0;
static int testcase = 0;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *echkeyfile = NULL;
static char *echconfig = NULL;
static size_t echconfiglen = 0;
static unsigned char *bin_echconfig;
static size_t bin_echconfiglen = 0;
static unsigned char *hpke_info = NULL;
static size_t hpke_infolen = 0;
static int short_test = 0;

/*
 * For client hello, we use a set of test vectors for each test:
 *  - encoded inner CH prefix
 *  - encoded inner CH for borking (esp. outer extensions)
 *  - encoded inner CH postfix
 *  - expected result (1 for good, 0 for bad)
 *  - expected error reason in the case of bad
 *
 * For each test, we replace the ECH ciphertext with a value
 * that's the HPKE seal/enc of an encoded inner-CH made up of
 * the three parts above and then see if we get the expected
 * error (reason).
 *
 * Whenever we re-seal we will get an error due to using the
 * wrong inner client random, which we don't know. But that
 * differs from errors in handling decoding after decryption.
 *
 * The inner CH is split in 3 variables so we can re-use pre
 * and post values, making it easier to understand/manipulate
 * a corrupted-or-not value.
 *
 * Note that the overall length of the encoded inner needs to
 * be mainained as otherwise outer length fields that are not
 * re-computed will be wrong. (We include a test of that as
 * well.) A radical change in the content of encoded inner
 * values (e.g. eliminating compression entirely) could break
 * these tests, but minor changes should have no effect due to
 * padding. (Such a radical change showing up as a fail of
 * these tests is arguably a good outcome.)
 */
typedef struct {
    const unsigned char *pre;
    size_t prelen;
    const unsigned char *forbork;
    size_t fblen;
    const unsigned char *post;
    size_t postlen;
    int rv_expected; /* expected result */
    int err_expected; /* expected error */
} TEST_ECHINNER;

/* a full padded, encoded inner client hello */
static const unsigned char entire_encoded_inner[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x34, 0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* a full padded, encoded inner client hello with no extensions */
static const unsigned char no_ext_encoded_inner[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* a too-short, encoded inner client hello */
static const unsigned char outer_short_encoded_inner[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x34, 0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01,
};

/* inner prefix up as far as outer_exts */
static const unsigned char encoded_inner_pre[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x34
};

/* inner prefix with mad length of suites (0xDDDD) */
static const unsigned char badsuites_inner_pre[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0xDD, 0xDD, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x34
};

/* outer extensions - we play with variations of this */
static const unsigned char encoded_inner_outers[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* outers with repetition of one extension (0x0B) */
static const unsigned char borked_outer1[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0B, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33
};

/* outers including a non-used extension (0xFFAB) */
static const unsigned char borked_outer2[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0xFF, 0xAB, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33
};

/* refer to SNI in outers! 2nd-last is 0x0000 */
static const unsigned char borked_outer3[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x33,
};

/* refer to ECH (0xfe0d) within outers */
static const unsigned char borked_outer4[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0xFE, 0x0D, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* refer to outers (0xfd00) within outers */
static const unsigned char borked_outer5[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0xFD, 0x00, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* no outers at all! include unknown ext 0xFF99 instead */
static const unsigned char borked_outer6[] = {
    0xFF, 0x99, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/*
 * outer with bad length (even number of octets)
 * we add a short bogus extension (0xFFFF) after
 * to ensure overall decode succeeds
 */
static const unsigned char borked_outer7[] = {
    0xfd, 0x00, 0x00, 0x0E, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0xFF, 0xFF, 0x00, 0x01, 0x00,
};

/* outer with bad inner length (odd number of octets)  */
static const unsigned char borked_outer8[] = {
    0xfd, 0x00, 0x00, 0x13, 0x11, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* outer with HUGE length (0xFF13) */
static const unsigned char borked_outer9[] = {
    0xfd, 0x00, 0xFF, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* outer with zero length, followed by bogus ext */
static const unsigned char borked_outer10[] = {
    0xfd, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00,
    0x0F, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

static const unsigned char encoded_inner_post[] = {
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* muck up the padding by including non-zero stuff */
static const unsigned char bad_pad_encoded_inner_post[] = {
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* an encoded inner that's just too short */
static const unsigned char short_encoded_inner[] = {
    0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* A set of test vectors */
static TEST_ECHINNER test_inners[] = {
    /* 1. basic case - copy to show test code works with no change */
    { NULL, 0, NULL, 0, NULL, 0, 1, SSL_ERROR_NONE},

    /* 2. too-short encoded inner */
    { NULL, 0,
      outer_short_encoded_inner, sizeof(outer_short_encoded_inner),
      NULL, 0,
      0, /* expected result */
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 3. otherwise-correct case that fails only due to client random */
    { NULL, 0,
      entire_encoded_inner, sizeof(entire_encoded_inner),
      NULL, 0,
      0, /* expected result */
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 4. otherwise-correct case that fails only due to client random */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      encoded_inner_outers, sizeof(encoded_inner_outers),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 5. fails HPKE decryption due to bad padding so treated as GREASE */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      encoded_inner_outers, sizeof(encoded_inner_outers),
      bad_pad_encoded_inner_post, sizeof(bad_pad_encoded_inner_post),
      0, /* expected result */
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},

    /*
     * 6. unsupported extension instead of outers - resulting decoded
     * inner missing so much it seems to be the wrong protocol
     */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer6, sizeof(borked_outer6),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_UNSUPPORTED_PROTOCOL},

    /* 7. madly long ciphersuites in inner */
    { badsuites_inner_pre, sizeof(badsuites_inner_pre),
      encoded_inner_outers, sizeof(encoded_inner_outers),
      encoded_inner_post, sizeof(bad_pad_encoded_inner_post),
      0, /* expected result */
      SSL_R_TLSV1_ALERT_DECODE_ERROR},
    /* 8. so many padding bytes recovered clear is short */
    { NULL, 0,
      short_encoded_inner, sizeof(short_encoded_inner),
      NULL, 0,
      0, /* expected result */
      SSL_R_BAD_EXTENSION},

    /* 9. repeated codepoint inside outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer1, sizeof(borked_outer1),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 10. non-existent codepoint inside outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer2, sizeof(borked_outer2),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 11. include SNI in outers as well as both inner and outer */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer3, sizeof(borked_outer3),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 12. refer to ECH within outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer4, sizeof(borked_outer4),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 13. refer to outers within outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer5, sizeof(borked_outer5),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 14. bad length of outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer7, sizeof(borked_outer7),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 15. bad inner length in outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer8, sizeof(borked_outer8),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 16. HUGE length in outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer9, sizeof(borked_outer9),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 17. zero length in outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer10, sizeof(borked_outer10),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 18. case with no extensions at all */
    { NULL, 0,
      no_ext_encoded_inner, sizeof(no_ext_encoded_inner),
      NULL, 0,
      0, /* expected result */
      SSL_R_BAD_EXTENSION},

};

/*
 * For server hello, we use a set of test vectors for each test:
 *
 * - borkage encodes what we're breaking and is the XOR
 *   of some #define'd OSSL_ECH_BORK_* values
 * - bork is the value to use instead of the real one (or NULL)
 * - blen is the size of bork
 * - rv_expected is the return value expected for the connection
 * - err_expected is the reason code we expect to see
 */
typedef struct {
    int borkage; /* type of borkage */
    unsigned char *bork; /* borked value */
    size_t blen; /* len(bork) */
    int rv_expected; /* expected result */
    int err_expected; /* expected error */
} TEST_SH;

# define OSSL_ECH_BORK_NONE 0
# define OSSL_ECH_BORK_FLIP_CONFIRM 1
# define OSSL_ECH_BORK_HRR (1 << 1)
# define OSSL_ECH_BORK_SHORT_HRR_CONFIRM (1 << 2)
# define OSSL_ECH_BORK_LONG_HRR_CONFIRM (1 << 3)
# define OSSL_ECH_BORK_GREASE (1 << 4)

static TEST_SH test_shs[] = {
    /* 1. no messing about, should succeed */
    {OSSL_ECH_BORK_NONE, NULL, 0, 1, SSL_ERROR_NONE},
    /* 2. trigger HRR but no other borkage */
    {OSSL_ECH_BORK_HRR, NULL, 0, 1, SSL_ERROR_NONE},
    /* 3. GREASE and trigger HRR */
    {OSSL_ECH_BORK_HRR | OSSL_ECH_BORK_GREASE,
     NULL, 0, 1, SSL_ERROR_NONE},

    /* 4. flip bits in SH.random ECH confirmation value */
    {OSSL_ECH_BORK_FLIP_CONFIRM, NULL, 0, 0,
     SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 5. flip bits in HRR.exts ECH confirmation value */
    {OSSL_ECH_BORK_HRR | OSSL_ECH_BORK_FLIP_CONFIRM,
     NULL, 0, 0, SSL_R_BAD_EXTENSION},

};

/* Do a HPKE seal of a padded encoded inner */
static int seal_encoded_inner(char **out, int *outlen,
                              unsigned char *ei, size_t eilen,
                              const char *ch, int chlen,
                              size_t echoffset, size_t echlen)
{
    int res = 0;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *hctx = NULL;
    unsigned char *mypub = NULL;
    static size_t mypublen = 0;
    unsigned char *theirpub = NULL;
    size_t theirpublen = 0;
    unsigned char *ct = NULL;
    size_t ctlen = 0;
    unsigned char *aad = NULL;
    size_t aadlen = 0;
    unsigned char *chout = NULL;
    size_t choutlen = 0;

    hctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, hpke_suite,
                             OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    if (!TEST_ptr(hctx))
        goto err;
    mypublen = OSSL_HPKE_get_public_encap_size(hpke_suite);
    if (!TEST_ptr(mypub = OPENSSL_malloc(mypublen)))
        goto err;
    theirpub = bin_echconfig + 11;
    theirpublen = 0x20;
    if (!TEST_true(OSSL_HPKE_encap(hctx, mypub, &mypublen,
                                   theirpub, theirpublen,
                                   hpke_info, hpke_infolen)))
        goto err;
    /* form up aad which is entire outer CH: zero's instead of ECH ciphertext */
    choutlen = chlen;
    if (!TEST_ptr(chout = OPENSSL_malloc(choutlen)))
        goto err;
    memcpy(chout, ch, chlen);
    memcpy(chout + echoffset + 12, mypub, mypublen);
    ct = chout + echoffset + 12 + mypublen + 2;
    ctlen = OSSL_HPKE_get_ciphertext_size(hpke_suite, eilen);
    chout[echoffset + 12 + mypublen] = (ctlen >> 8) & 0xff;
    chout[echoffset + 12 + mypublen + 1] = ctlen & 0xff;
    /* the 9 skips the record layer header */
    aad = chout + 9;
    aadlen = chlen - 9;
    if (short_test == 0 && ct + ctlen != aad + aadlen) {
        TEST_info("length oddity");
        goto err;
    }
    memset(ct, 0, ctlen);
    if (!TEST_true(OSSL_HPKE_seal(hctx, ct, &ctlen, aad, aadlen, ei, eilen)))
        goto err;
    *out = (char *)chout;
    *outlen = choutlen;
    res = 1;
err:
    OPENSSL_free(mypub);
    OSSL_HPKE_CTX_free(hctx);
    return res;

}

/*
 * We'll either corrupt or copy the CH based on the test index
 */
static int corrupt_or_copy(const char *ch, const int chlen,
                           char **chout, int *choutlen)
{
    TEST_ECHINNER *ti = NULL;
    TEST_SH *ts = NULL;
    int is_ch = 0, is_sh = 0;
    unsigned char *encoded_inner = NULL;
    size_t prelen, fblen, postlen;
    size_t encoded_innerlen = 0;
    size_t sessid = 0, exts = 0, extlens = 0, echoffset = 0, echlen = 0;
    size_t snioffset = 0, snilen = 0;
    uint16_t echtype;
    int inner, rv = 0;

    /* is it a ClientHello or not? */
    if (chlen > 10 && ch[0] == SSL3_RT_HANDSHAKE
        && ch[5] == SSL3_MT_CLIENT_HELLO)
        is_ch = 1;
    /* is it a ServerHello or not? */
    if (chlen > 10 && ch[0] == SSL3_RT_HANDSHAKE
        && ch[5] == SSL3_MT_SERVER_HELLO)
        is_sh = 1;

    if (is_ch == 1) {
        if (testcase >= (int)OSSL_NELEM(test_inners))
            return 0;
        ti = &test_inners[testcase];
        prelen = ti->pre == NULL ? 0 : ti->prelen;
        fblen = ti->forbork == NULL ? 0 : ti->fblen;
        postlen = ti->post == NULL ? 0 : ti->postlen;
        /* check for editing errors */
        if (testcase != 0 && testcase != 1
            && prelen + fblen + postlen != sizeof(entire_encoded_inner)) {
            TEST_info("manual sizing error");
            return 0;
        }
        if (testcase == 1) /* the only case with a short ciphertext for now */
            short_test = 1;
        /* the 9 is the offset of the start of the CH in the record layer */
        if (!TEST_true(ech_helper_get_ch_offsets((const unsigned char *)ch + 9,
                                                 chlen - 9,
                                                 &sessid, &exts, &extlens,
                                                 &echoffset, &echtype, &echlen,
                                                 &snioffset, &snilen, &inner)))
            return 0;
        /* that better be an outer ECH :-) */
        if (echoffset > 0 && !TEST_int_eq(inner, 0)) {
            TEST_info("better send outer");
            return 0;
        }
        /* bump offsets by 9 */
        echoffset += 9;
        snioffset += 9;
        /*
         * if it doesn't have an ECH, or if the forbork value in our test
         * array is NULL, just copy the entire input to output
         */
        if (echoffset == 9 || ti->forbork == NULL) {
            if (!TEST_ptr(*chout = OPENSSL_memdup(ch, chlen)))
                return 0;
            *choutlen = chlen;
            return 1;
        }
        /* in this case, construct the encoded inner, then seal that */
        encoded_innerlen = prelen + fblen + postlen;
        if (!TEST_ptr(encoded_inner = OPENSSL_malloc(encoded_innerlen)))
            return 0;
        if (ti->pre != NULL) /* keep fuzz checker happy */
            memcpy(encoded_inner, ti->pre, prelen);
        if (ti->forbork != NULL)
            memcpy(encoded_inner + prelen, ti->forbork, fblen);
        if (ti->post != NULL)
            memcpy(encoded_inner + prelen + fblen, ti->post, postlen);
        if (!TEST_true(seal_encoded_inner(chout, choutlen,
                                          encoded_inner, encoded_innerlen,
                                          ch, chlen, echoffset, echlen)))
            return 0;
        OPENSSL_free(encoded_inner);
        return 1;
    }

    if (is_sh == 1) {
        if (testcase >= (int)OSSL_NELEM(test_shs))
            return 0;
        ts = &test_shs[testcase];
        if (ts->borkage == 0) {
            if (!TEST_ptr(*chout = OPENSSL_memdup(ch, chlen)))
                return 0;
            *choutlen = chlen;
            return 1;
        }
        /* simple starter, flip bits in ECH confirmation */
        if (ts->borkage & OSSL_ECH_BORK_FLIP_CONFIRM) {
            if (!TEST_ptr(*chout = OPENSSL_memdup(ch, chlen)))
                return 0;
            if (ts->borkage & OSSL_ECH_BORK_HRR) {
                rv = ech_helper_get_sh_offsets((unsigned char *)ch + 9,
                                               chlen -9,
                                               &exts, &echoffset, &echtype);
                if (!TEST_int_eq(rv, 1))
                    return 0;
                if (echoffset > 0) {
                    (*chout)[9 + echoffset + 4] =
                        (*chout)[9 + echoffset + 4] ^ 0xaa;
                }
            } else {
                (*chout)[9 + 2 + SSL3_RANDOM_SIZE - 4] =
                    (*chout)[9 + 2 + SSL3_RANDOM_SIZE - 4] ^ 0xaa;
            }
            *choutlen = chlen;
            return 1;
        }
    }

    /* if doing nothing, do that... */
    if (!TEST_ptr(*chout = OPENSSL_memdup(ch, chlen)))
        return 0;
    *choutlen = chlen;
    return 1;
}

/*
 * return the bas64 encoded ECHConfigList from an ECH PEM file
 *
 * note - this isn't really needed as an offical API because
 * real clients will use DNS or scripting clients who need
 * this can do it easier with shell commands
 *
 * the caller should free the returned string
 */
static char *echconfiglist_from_PEM(const char *file)
{
    BIO *in = NULL;
    char *ecl_string = NULL;
    char lnbuf[OSSL_ECH_MAX_LINELEN];
    int readbytes = 0;

    if (!TEST_ptr(in = BIO_new(BIO_s_file()))
        || !TEST_int_ge(BIO_read_filename(in, file), 0))
        goto out;
    /* read 4 lines before the one we want */
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    ecl_string = OPENSSL_malloc(readbytes + 1);
    if (ecl_string == NULL)
        goto out;
    memcpy(ecl_string, lnbuf, readbytes);
    /* zap any '\n' or '\r' at the end if present */
    while (readbytes >= 0
           && (ecl_string[readbytes - 1] == '\n'
               || ecl_string[readbytes - 1] == '\r')) {
        ecl_string[readbytes - 1] = '\0';
        readbytes--;
    }
    if (readbytes == 0)
        goto out;
    BIO_free_all(in);
    return ecl_string;
out:
    BIO_free_all(in);
    return NULL;
}

static void copy_flags(BIO *bio)
{
    int flags;
    BIO *next = BIO_next(bio);

    flags = BIO_test_flags(next, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_set_flags(bio, flags);
}

static int tls_corrupt_read(BIO *bio, char *out, int outl)
{
    int ret;
    BIO *next = BIO_next(bio);

    ret = BIO_read(next, out, outl);
    copy_flags(bio);

    return ret;
}

static int tls_corrupt_write(BIO *bio, const char *in, int inl)
{
    int ret;
    BIO *next = BIO_next(bio);
    char *copy = NULL;
    int copylen = 0;

    ret = corrupt_or_copy(in, inl, &copy, &copylen);
    if (ret == 0)
        return 0;
    ret = BIO_write(next, copy, inl);
    OPENSSL_free(copy);
    copy_flags(bio);

    return ret;
}

static long tls_corrupt_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret;
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;

    switch (cmd) {
    case BIO_CTRL_DUP:
        ret = 0L;
        break;
    default:
        ret = BIO_ctrl(next, cmd, num, ptr);
        break;
    }
    return ret;
}

static int tls_corrupt_gets(BIO *bio, char *buf, int size)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int tls_corrupt_puts(BIO *bio, const char *str)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int tls_corrupt_new(BIO *bio)
{
    BIO_set_init(bio, 1);

    return 1;
}

static int tls_corrupt_free(BIO *bio)
{
    BIO_set_init(bio, 0);

    return 1;
}

# define BIO_TYPE_CUSTOM_FILTER (0x80 | BIO_TYPE_FILTER)

static BIO_METHOD *method_tls_corrupt = NULL;

/* Note: Not thread safe! */
static const BIO_METHOD *bio_f_tls_corrupt_filter(void)
{
    if (method_tls_corrupt == NULL) {
        method_tls_corrupt = BIO_meth_new(BIO_TYPE_CUSTOM_FILTER,
                                          "TLS corrupt filter");
        if (method_tls_corrupt == NULL
            || !BIO_meth_set_write(method_tls_corrupt, tls_corrupt_write)
            || !BIO_meth_set_read(method_tls_corrupt, tls_corrupt_read)
            || !BIO_meth_set_puts(method_tls_corrupt, tls_corrupt_puts)
            || !BIO_meth_set_gets(method_tls_corrupt, tls_corrupt_gets)
            || !BIO_meth_set_ctrl(method_tls_corrupt, tls_corrupt_ctrl)
            || !BIO_meth_set_create(method_tls_corrupt, tls_corrupt_new)
            || !BIO_meth_set_destroy(method_tls_corrupt, tls_corrupt_free))
            return NULL;
    }
    return method_tls_corrupt;
}

static void bio_f_tls_corrupt_filter_free(void)
{
    BIO_meth_free(method_tls_corrupt);
}

static int test_ch_corrupt(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *c_to_s_fbio;
    int testresult = 0;
    int err;
    TEST_ECHINNER *ti = NULL;
    int connrv = 0;
    int err_reason = 0;
    int exp_err = SSL_ERROR_NONE;

    testcase = testidx;
    ti = &test_inners[testidx];
    if (verbose)
        TEST_info("Starting #%d", testidx + 1);
    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        return 0;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile)))
        goto end;
    if (!TEST_ptr(c_to_s_fbio = BIO_new(bio_f_tls_corrupt_filter())))
        goto end;
    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL,
                                      c_to_s_fbio)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(client, "foo.example.com")))
        goto end;
    exp_err = SSL_ERROR_SSL;
    if (ti->err_expected == 0)
        exp_err = SSL_ERROR_NONE;
    connrv = create_ssl_connection(server, client, exp_err);
    if (!TEST_int_eq(connrv, ti->rv_expected))
        goto end;
    if (connrv == 0) {
        do {
            err = ERR_get_error();
            if (err == 0) {
                TEST_error("ECH corruption: Unexpected error");
                goto end;
            }
            err_reason = ERR_GET_REASON(err);
            if (verbose)
                TEST_info("Error reason: %d", err_reason);
        } while (err_reason != ti->err_expected);
    }
    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_sh_corrupt(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *s_to_c_fbio;
    int testresult = 0;
    int err;
    TEST_SH *ts = NULL;
    int connrv = 0;
    int err_reason = 0;
    int exp_err = SSL_ERROR_NONE;

    testcase = testidx;
    ts = &test_shs[testidx];
    if (verbose)
        TEST_info("Starting #%d", testidx + 1);
    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        return 0;
    if (ts->borkage & OSSL_ECH_BORK_GREASE) {
        if (!TEST_true(SSL_CTX_set_options(cctx, SSL_OP_ECH_GREASE)))
            goto end;
    } else {
        if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx,
                                                  (unsigned char *)echconfig,
                                                  echconfiglen)))
            goto end;
    }
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile)))
        goto end;
    if (!TEST_ptr(s_to_c_fbio = BIO_new(bio_f_tls_corrupt_filter())))
        goto end;
    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client,
                                      s_to_c_fbio, NULL)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(client, "foo.example.com")))
        goto end;
    if (ts->borkage & OSSL_ECH_BORK_HRR
        && !TEST_true(SSL_set1_groups_list(server, "P-384")))
        goto end;
    exp_err = SSL_ERROR_SSL;
    if (ts->err_expected == 0)
        exp_err = SSL_ERROR_NONE;
    connrv = create_ssl_connection(server, client, exp_err);
    if (!TEST_int_eq(connrv, ts->rv_expected))
        goto end;
    if (connrv == 0) {
        do {
            err = ERR_get_error();
            if (err == 0) {
                TEST_error("ECH corruption: Unexpected error");
                goto end;
            }
            err_reason = ERR_GET_REASON(err);
            if (verbose)
                TEST_info("Error reason: %d", err_reason);
        } while (err_reason != ts->err_expected);
    }
    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run ECH Corruption tests\n" },
        { NULL }
    };
    return test_options;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    certsdir = test_get_argument(0);
    if (certsdir == NULL)
        certsdir = DEF_CERTS_DIR;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;

    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "echconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto err;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto err;
    echconfiglen = strlen(echconfig);
    bin_echconfiglen = ech_helper_base64_decode(echconfig, echconfiglen,
                                                &bin_echconfig);
    hpke_infolen = bin_echconfiglen + 200;
    if (!TEST_ptr(hpke_info = OPENSSL_malloc(hpke_infolen)))
        goto err;
    /* +/- 2 is to drop the ECHConfigList length at the start */
    if (!TEST_true(ech_helper_make_enc_info((unsigned char *)bin_echconfig + 2,
                                            bin_echconfiglen - 2,
                                            hpke_info, &hpke_infolen)))
        goto err;

    ADD_ALL_TESTS(test_ch_corrupt, OSSL_NELEM(test_inners));
    ADD_ALL_TESTS(test_sh_corrupt, OSSL_NELEM(test_shs));
    return 1;
err:
    return 0;
#else
    return 1;
#endif
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    bio_f_tls_corrupt_filter_free();
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    OPENSSL_free(bin_echconfig);
    OPENSSL_free(hpke_info);
#endif
}
