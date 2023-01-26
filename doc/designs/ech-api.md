Encrypted ClientHello (ECH) APIs
================================

This fork has an implementation of ECH and these are design notes relating to
the current APIs for that, and an analysis of how differ from those currently
in the boringssl library.

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
[here](../man3/SSL_ech_set1_echconfig.pod).

Specification
-------------

ECH is an IETF TLS WG specification. It has been stable since
[draft-13](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/13/), published
in August 2021.  The latest draft can be found
[here](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).

Once browsers and others have done sufficient testing the plan is to
proceed to publishing ECH as an RFC. That will likely include a change
of version code-points which have been tracking Internet-Draft version
numbers during the course of spec development. (The current version used
is 0xff0d where the 0d reflects draft-13.)

Server-side APIs
----------------

The main server-side APIs involve generating a key and the related
ECHConfigList structure that ends up published in the DNS, periodically loading
such keys into a server to prepare for ECH decryption and handling so-called
ECH split-mode where a server only does ECH decryption but passes along the
inner CH to another server that does the actual TLS handshake with the client.

### Key and ECHConfigList Generation

This API is for use by command line or other key management tools, for example
the ``openssl ech`` command documented [here](../man1/openssl-ech.pod).

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

### Key Loading

### Split-mode handling

Client-side APIs
----------------

Call-backs and options
----------------------

Build Options
-------------

All ECH code is protected via ``#ifndef OPENSSL_NO_ECH`` and there is
a ``no-ech`` option to build without this code.

Internals
---------

BoringSSL APIs
--------------

