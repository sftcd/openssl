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
[here](../man3/SSL_ech_set1_echconfig.pod).

Unless otherwise stated all APIs return 1 in the case of success and 0 for
error.

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

The ``ekversion`` should be 0xff0d or 13 for the current version.

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

### Key Loading

The APIs here are mainly designed for web servers and have been used in PoC
implementations of nginx, apache, lighttpd and haproxy in addition to the
``openssl s_server`` code in this fork.

As ECH is essentially an ephemeral-static DH scheme, it is likely servers will
fairly frequently update the ECH key pairs in use, to provide something more
akin to forward secrecy. So it is a goal to make it easy for web servers to
re-load keys without complicating their configuration file handling.

Cloudflare's test ECH service in the past rotated published ECH public keys
hourly.  Currently checking if that's still the case...

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

