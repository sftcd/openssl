Encrypted ClientHello (ECH) APIs
================================

This fork has an implementation of ECH and these are design notes relating to
the current APIs for that, and an analysis of how these differ from those
currently in the boringssl library.

ECH involves creating an "inner" ClientHello (CH) that contains the potentially
sensitive content of a CH, primarily the SNI and perhaps the ALPN values. That
inner CH is then encrypted and embedded (as a CH extension) in an outer CH that
contains presumably less sensitive values. The spec includes a "compression"
scheme that allows the inner CH to refer to extensions from the outer CH where
the same value would otherwise be present in both.

ECH makes use of [HPKE](https://datatracker.ietf.org/doc/rfc9180/) for the
encryption of the inner CH. HPKE code was merged to the master branch in 
November 2022.

The current APIs implemented in this fork are also documented
[here](../man3/SSL_ech_set1_echconfig.pod). The descriptions here are less
formal and provide some justification for the API design.

Unless otherwise stated all APIs return 1 in the case of success and 0 for
error.

Prototypes are mostly in ``include/openssl/ech.h`` for now.

Specification
-------------

ECH is an IETF TLS WG specification. It has been stable since
[draft-13](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/13/), published
in August 2021.  The latest draft can be found
[here](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).

Once browsers and others have done sufficient testing the plan is to
proceed to publishing ECH as an RFC. That will likely include a change
of version code-points which have been tracking Internet-Draft version
numbers during the course of spec development. 

The current version used is 0xfe0d where the 0d reflects draft-13 with
the following symbol defined for this version:

```c
#  define OSSL_ECH_DRAFT_13_VERSION 0xfe0d /* version from draft-13 */
```

Server-side APIs
----------------

The main server-side APIs involve generating a key and the related
ECHConfigList structure that ends up published in the DNS, periodically loading
such keys into a server to prepare for ECH decryption and handling so-called
ECH split-mode where a server only does ECH decryption but passes along the
inner CH to another server that does the actual TLS handshake with the client.

### Key and ECHConfigList Generation

This API is for use by command line or other key management tools, for example
the ``openssl ech`` command documented [here](../man1/openssl-ech.pod.in).

The ECHConfigList structure contains the ECH public value (an ECC public key)
and other ECH related information, likely mainly the ``public_name`` that
will be used in outer CH messages. 

```c
int ossl_ech_make_echconfig(unsigned char *echconfig, size_t *echconfiglen,
                            unsigned char *priv, size_t *privlen,
                            uint16_t ekversion, uint16_t max_name_length,
                            const char *public_name, OSSL_HPKE_SUITE suite,
                            const unsigned char *extvals, size_t extlen);
```

The ``echconfig`` and ``priv`` buffer outputs are allocated by the caller
with the allocated size on input and the used-size on output. On output,
the ``echconfig`` contains the base64 encoded ECHConfigList and the 
``priv`` value contains the PEM encoded PKCS#8 private value.

The ``ekversion`` should be 0xfe0d or 13 for the current version.

The ``max_name_length`` is an element of the ECHConfigList that is used
by clients as part of a padding algorithm. (That design is part of the
spec, but isn't necessarily great - the idea is to include the longest
value that might be the length of a DNS name included as an inner CH
SNI.) A value of 0 is perhaps most likely to be used, indicating that
the maximum isn't known.

The ECHConfigList structure is extensible, but, to date, no extensions
have been defined. If provided, the ``extvals`` buffer should contain an
already TLS-encoded set of extensions for inclusion in the ECHConfigList.

The ``openssl ech`` command in this fork can write the private key and the
ECHConfigList values to a file that matches the ECH PEM file format we have
proposed to the IETF
([spec](https://datatracker.ietf.org/doc/draft-farrell-tls-pemesni/)).  Note
that that file format is not an "adopted" work item for the IETF TLS WG (but
should be:-). ``openssl ech`` also allows the two values to be output to
two separate files.

### Server Key Management

The APIs here are mainly designed for web servers and have been used in PoC
implementations of nginx, apache, lighttpd and haproxy in addition to the
``openssl s_server`` code in this fork.

As ECH is essentially an ephemeral-static DH scheme, it is likely servers will
fairly frequently update the ECH key pairs in use, to provide something more
akin to forward secrecy. So it is a goal to make it easy for web servers to
re-load keys without complicating their configuration file handling.

Cloudflare's test ECH service rotates published ECH public keys hourly
(re-verified on 2023-01-26). We expect other services to do similarly (and do
so for some services at defo.ie). 

```c
int SSL_CTX_ech_server_enable_file(SSL_CTX *ctx, const char *file);
int SSL_CTX_ech_server_enable_dir(SSL_CTX *ctx, int *loaded,
                                  const char *echdir);
int SSL_CTX_ech_server_enable_buffer(SSL_CTX *ctx, const unsigned char *buf,
                                     const size_t blen);
```

The three functions above support loading keys, the first attempts to load a
key based on an individual file name. The second attempts to load all files
from a directory that have a ``.ech`` file extension - this allows web server
configurations to simply name that directory and then trigger a configuration
reload periodically as keys in that directory have been updated by some
external key management process (likely managed via a cronjob).  The last
allows the application to load keys from a buffer (that should contain the same
content as a file) and was added for haproxy which prefers not to do disk reads
after initial startup (for resilience reasons apparently).

There are also functions to allow a server to see how many keys are currently
loaded and one to flush keys that are older than ``age`` seconds.

```c
int SSL_CTX_ech_server_get_key_status(SSL_CTX *ctx, int *numkeys);
int SSL_CTX_ech_server_flush_keys(SSL_CTX *ctx, time_t age);
```

### Split-mode handling

ECH split mode involves a server that only does ECH decryption and then passes
on the inner CH to another TLS server that actually negotiates the TLS session
with the client, based on the inner CH content. The function to support this
simply takes the outer CH and returns the inner CH and SNI values (allowing
routing to the correct backend) and whether or not decryption succeeded.

This has been tested in a PoC implementation with haproxy, which works for
nomimal operation but that can't handle the combination of split-mode with  HRR
as haproxy only supports examining the first (outer) CH seen, whereas ECH +
split-mode + HRR requires processing both outer CHs.

```c
int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            int *decrypted_ok,
                            char **inner_sni, char **outer_sni,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len);
```

Client-side APIs
----------------

Clients will generally provide an ECHConfigList or an HTTPS/SVCB resource
record value in order to enable ECH for an SSL connection.

Those may be provided in various encodings (base64, ascii hex or binary)
each of which may suit different applications. The APIs below can consume
each of these (via the ``ekfmt`` input) or the implementation can guess
based on the value provided.

``SSL_ech_set1_svcb`` additionally supports inputs in zone file presentation
format, i.e., extracting the ECHConfigList from the ``ech=`` value if one is
present.

If an HTTPS/SVCB resource record is provided then ``SSL_ech_set1_svcb`` will
only extract the ECHConfigList from that value and any ALPN information has
to be separtely extract by the client.

In each case the function returns the number of ECHConfig elements from
the list successfully decoded  in the ``num_echs`` output.

```c
int SSL_ech_set1_echconfig(SSL *s, int *num_echs,
                           int ekfmt, char *ekval, size_t eklen);
int SSL_ech_set1_svcb(SSL *s, int *num_echs,
                      int rrfmt, char *rrval, size_t rrlen);
int SSL_CTX_ech_set1_echconfig(SSL_CTX *ctx, int *num_echs,
                               int ekfmt, char *ekval, size_t eklen);
```

Clients can also more directly control the values to be used for
inner and outer SNI and ALPN values via specific APIs. This allows a client
to over-ride the ``public_name`` present in an ECHConfigList that will
by default be used for the outer SNI. The ``no_outer`` input allows a
client to emit an outer CH with no SNI at all.

```c
int SSL_ech_set_server_names(SSL *s, const char *inner_name,
                             const char *outer_name, int no_outer);
int SSL_ech_set_outer_server_name(SSL *s, const char *outer_name, int no_outer);
int SSL_CTX_ech_set_outer_alpn_protos(SSL *s, const unsigned char *protos,
                                       unsigned int protos_len);
```

If a client attempts ECH but that fails, or sends an ECH-GREASE'd CH, to 
an ECH-supporting server, then that server may return an ECH "retry-config"
value that the client could choose to use in a subsequent connection. The
client can detect this situation via the ``SSL_ech_get_status()`` API and
can access the retry config value via:

```c
int SSL_ech_get_retry_config(SSL *s, const unsigned char **ec, size_t *eclen);
```

Clients that need fine control over which ECHConfig (from those available) will
be used can query the SSL connection and down-select to one of those, e.g.,
based on the ``public_name`` that will be used. This could help a client that
selects the server address to use based on IP address hints that can also be
present in an HTTPS/SCVB resource record.

```c
/*
 * Application-visible form of ECH information from the DNS, from config
 * files, or from earlier API calls. APIs produce/process an array of these.
 */
typedef struct ossl_ech_info_st {
    int index; /* externally re-usable reference to this value */
    char *public_name; /* public_name from API or ECHConfig */
    char *inner_name; /* server-name (for inner CH if doing ECH) */
    char *outer_alpns; /* outer ALPN string */
    char *inner_alpns; /* inner ALPN string */
    char *echconfig; /* a JSON-like version of the associated ECHConfig */
} OSSL_ECH_INFO;

void OSSL_ECH_INFO_free(OSSL_ECH_INFO *info, int count);
int OSSL_ECH_INFO_print(BIO *out, OSSL_ECH_INFO *info, int count);
int SSL_ech_get_info(SSL *s, OSSL_ECH_INFO **info, int *count);
int SSL_ech_reduce(SSL *s, int index);
```

If a client wishes to GREASE ECH using a specific HPKE suite or
ECH version (represented by the TLS extension type code-point) then
it can set those values via:

```c
int SSL_ech_set_grease_suite(SSL *s, const char *suite);
int SSL_ech_set_grease_type(SSL *s, uint16_t type);
```

ECH Status API
--------------

Clients and servers can check the status of ECH processing
on an SSL connection using this API:

```c
int SSL_ech_get_status(SSL *s, char **inner_sni, char **outer_sni);

/* Return codes from SSL_ech_get_status */
#  define SSL_ECH_STATUS_BACKEND    4 /* ECH backend: saw an ech_is_inner */
#  define SSL_ECH_STATUS_GREASE_ECH 3 /* GREASEd and got an ECH in return */
#  define SSL_ECH_STATUS_GREASE     2 /* ECH GREASE happened  */
#  define SSL_ECH_STATUS_SUCCESS    1 /* Success */
#  define SSL_ECH_STATUS_FAILED     0 /* Some internal or protocol error */
#  define SSL_ECH_STATUS_BAD_CALL   -100 /* Some in/out arguments were NULL */
#  define SSL_ECH_STATUS_NOT_TRIED  -101 /* ECH wasn't attempted  */
#  define SSL_ECH_STATUS_BAD_NAME   -102 /* ECH ok but server cert bad */
#  define SSL_ECH_STATUS_NOT_CONFIGURED -103 /* ECH wasn't configured */
#  define SSL_ECH_STATUS_FAILED_ECH -105 /* We tried, failed and got an ECH */
```

The ``inner_sni`` and ``outer_sni`` values point at strings
with the relevant values. (They aren't allocated or free'd by the
caller.)

The function returns one of the status values above.


Call-backs and options
----------------------

Clients and servers can set a callback that will be triggered when
ECH is attempted and the result of ECH processing is known. The
callback function can access a string (``str``) that can be used
for logging (but not for branching). Callback functions might 
typically call ``SSL_ech_get_status()`` if branching is required.

```c
typedef unsigned int (*SSL_ech_cb_func)(SSL *s, const char *str);

void SSL_ech_set_callback(SSL *s, SSL_ech_cb_func f);
void SSL_CTX_ech_set_callback(SSL_CTX *ctx, SSL_ech_cb_func f);
```

The following options are defined for ECH:

```c
/* set this to tell client to emit greased ECH values when not doing
 * "real" ECH */
#define SSL_OP_ECH_GREASE                               SSL_OP_BIT(34)
/* If this is set then the server side will attempt trial decryption */
/* of ECHs even if there is no matching record_digest. That's a bit  */
/* inefficient, but more privacy friendly */
#define SSL_OP_ECH_TRIALDECRYPT                         SSL_OP_BIT(35)
/* If set, clients will ignore the supplied ECH config_id and replace
 * that with a random value */
#define SSL_OP_ECH_IGNORE_CID                           SSL_OP_BIT(36)
```

Build Options
-------------

All ECH code is protected via ``#ifndef OPENSSL_NO_ECH`` and there is
a ``no-ech`` option to build without this code.

BoringSSL APIs
--------------

Brief descriptions of boringssl APIs are below together with initial comments
comparing those to the above.

Just as this fork is under development, boring's ``include/openssl/ssl.h``
says: "ECH support in BoringSSL is still experimental and under development."

### GREASE

Boring uses an API to enable GREASEing rather than an option.

```c
OPENSSL_EXPORT void SSL_set_enable_ech_grease(SSL *ssl, int enable);
```

This could work as well for our fork, or boring could probably change to use an
option, unless there's some reason to prefer not adding new options.

### Setting an ECHConfigList

```c
OPENSSL_EXPORT int SSL_set1_ech_config_list(SSL *ssl,
                                            const uint8_t *ech_config_list,
                                            size_t ech_config_list_len);
```

This provides a subset of the equivalent client capabilities from our fork.

### Verifying the outer CH rather than inner

Boring seems to use this API to change the DNS name being verified in order to
validate a ``retry_config``.

```c
OPENSSL_EXPORT void SSL_get0_ech_name_override(const SSL *ssl,
                                               const char **out_name,
                                               size_t *out_name_len);
```

I'm not sure how this compares. Need to investigate.

### Create an ECHConfigList

The first function below outputs an ECHConfig, the second adds one of those to
an ``SSL_ECH_KEYS`` structure, the last emits an ECHConfigList from that
structure. There are other APIs for managing memory for ``SSL_ECH_KEYS``

These APIs also expose HPKE to the application via ``EVP_HPKE_KEY`` which is
defined in ``include/openssl/hpke.h``. HPKE handling differs quite a bit from
the HPKE APIs merged to OpenSSL.


```c
OPENSSL_EXPORT int SSL_marshal_ech_config(uint8_t **out, size_t *out_len,
                                          uint8_t config_id,
                                          const EVP_HPKE_KEY *key,
                                          const char *public_name,
                                          size_t max_name_len);
OPENSSL_EXPORT int SSL_ECH_KEYS_add(SSL_ECH_KEYS *keys, int is_retry_config,
                                    const uint8_t *ech_config,
                                    size_t ech_config_len,
                                    const EVP_HPKE_KEY *key);
OPENSSL_EXPORT int SSL_ECH_KEYS_marshal_retry_configs(const SSL_ECH_KEYS *keys,
                                                      uint8_t **out,
                                                      size_t *out_len);

```

Collectively these are similar to ``ossl_ech_make_echconfig()``.

### Setting ECH keys on a server

Again using the ``SSL_ECH_KEYS`` type and APIs, servers can build up a set of
ECH keys using:

```c
OPENSSL_EXPORT int SSL_CTX_set1_ech_keys(SSL_CTX *ctx, SSL_ECH_KEYS *keys);
```

This is similar to the ``SSL_CTX_ech_server_enable_*()`` APIs.

### Getting status

Boring has:

```c
OPENSSL_EXPORT int SSL_ech_accepted(const SSL *ssl);
```

That seems to be a subset of ``SSL_ech_get_status()``.

