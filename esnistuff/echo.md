
# Some thoughts on Encrypted ClientHello (ECHO)

The encch branch has a hacked-together prediction of how ECHO might work.
These notes are the start of a non-haccky equivalent.

## Overview of Current State (20200202s - a palindrome day!)

On the client side, I messed with ``ssl/statem/statem_clnt.c`` adding a
``tls_construct_encrypted_client_hello()`` function, which (for now) repeats
all of ``tls_construct_client_hello()`` (to construct the inner CH) before
re-doing the process to make the outer CH. The only inner/outer variance so far
is the SNI differs, the ESNI extension in the inner has the esni-nonce, and the
ENCCH extension is added to the outer. The actual encryption calls are made
within the ENCCH client to server handler. Otherwise all extension values are
copied from the inner to outer CH when constructing the latter. There is no
compression, nor padding, in this code.

On the server side, the action kicks off inside ``tls_parse_ctos_encch()``
which decrypts the ENCCH, makes calls to parse the inner CH and then overwrites
some of the session parameters (in an ad-hoc manner, without real analysis as
to correctness) and sets the effective SNI. 

In the ``ssl/statem/extensions*.c`` files, extension handing code often has a
``context`` input parameter that determines which TLS protocol message is being
processed at a given moment. THat's a bit mask, and I added bit definitions for
the inner and outer CH in addition to the existing bit that indicates context
is CH processing.  That's not a bad way to distiguish the inner and outer.
That's done in ``include/openssl/ssl.h`` as those values are also used in the
external API (see below).  The new values are:

            #define SSL_EXT_CLIENT_HELLO_OUTER              0x8000
            #define SSL_EXT_CLIENT_HELLO_INNER              0x10000

This branch uses HPKE. The HPKE mode and suite are (for now) hardcoded and not
mapped from the TLS ciphersuite. The TLS session key share is used as the AAD.

I invented an ESNIKey version 0xff04/``ESNI_DRAFT_06_VERSION`` for this that's
used to get the pre-draft-06 behaviour, so earlier versions still work as
before.

A basic test on localhost works fine with not API changes needed.

## Obvious TBDs

- Think about how to use HPKE properly.
- Figure out what to pad (probably the overall ENCCH and not just the SNI now)
  and how (cf. padded_length in ESNIKeys - which is now therefore more wrong
  than ever:-)
- Consider compression for when same value in inner/outer.

## Nesting

If we can do one ENCCH, we could certainly do more than one. So would such
nesting be interesting or useful? Needs a ponder. 

## API issues

There is an
[API](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_add_custom_ext.html)
allowing applications to handle "custom" TLS extensions.  That could be bent
into shape to do what we want but more will be needed to provide fuller control
over what goes in the inner and outer CH's.

## Extension-specific handling

If a non-standard behaviour were needed then the "custom" extension API can be
used.  What we want though are standard behaviours for standard extensions.
The standard inner vs. outer behaviour, for any given ClientHello extension,
could be:

1. same value in both
1. unrelated internally generated values in inner/outer
1. unrelated application provided values in inner/outer
1. extension only present in outer
1. extension only present in inner

Default behaviour is to have the same value in inner and outer.  If inner/outer
values differ, then the values could be internally generated or
application-supplied.

The extensions where we're particularly interested in being able to use
different inner/outer values are considered below. (The list here is from
``ssl/ssl_local.h`` where there's an ``enum`` defining these.)

| Extension | Notes
| renegotiate | same
| server_name | differ or inner-only, application supplied
| max_fragment_length | same
| srp | dunno, perhaps: same or inner-only
| ec_point_formats | determined by inner/outer key_share, internally generated
| supported_groups | determined by inner/outer key_share, internally generated
| session_ticket | same or inner-only
| status_request | same
| next_proto_neg | differ or inner-only, application supplied
| application_layer_protocol_negotiation | differ or inner-only, application supplied
| use_srtp | dunno
| encrypt_then_mac | same
| signed_certificate_timestamp | dunno
| extended_master_secret | dunno
| signature_algorithms_cert | same
| post_handshake_auth | same
| signature_algorithms | same
| supported_versions | same (for now?)
| psk_kex_modes | determined by inner/outer key_share
| key_share | same or differ, internally generated
| cookie | dunno
| cryptopro_bug | same
| early_data | dunno
| esni | defunct, or if used as esni-nonce only used in EncryptedExtensions
| encch | outer only (or nesting?) 
| certificate_authorities | same
| padding | differ?
| psk | dunno - need to figure out "must be last" req

