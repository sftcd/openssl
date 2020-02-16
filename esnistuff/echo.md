
# Some thoughts on Encrypted ClientHello (ECHO)

The encch branch has a hacked-together prediction of how ECHO might work.
These notes are the start of a non-haccky equivalent.

## Overview of Current State (20200206)

On the client side, I messed with ``ssl/statem/statem_clnt.c`` adding a
``tls_construct_encrypted_client_hello()`` function, which (for now) repeats
all of ``tls_construct_client_hello()`` (to construct the inner CH) before
re-doing the process to make the outer CH. The only inner/outer variance so far
is the SNI differs, the ESNI extension in the inner has the esni-nonce, a
padding extension may be added (see below) and the
ENCCH extension is added to the outer. The actual encryption calls are made
within the ENCCH client to server handler. Otherwise all extension values are
copied from the inner to outer CH when constructing the latter. 

For padding, for the moment, I add padding to the inner CH so that the overall
inner CH plaintext length (in the PACKET passed to
``tls_process_client_hello()`` which I think is 9 octets shorter than what's
sent on the wire)  is the ``padded_length`` from the ESNIKey or if the inner CH
is longer than that, it is padded to a the nearest multiple of 16 octets plus a
randomly chosen 0 to 3 additional 16 octet blocks of padding, i.e. between 0
and 47 padding octets are added. I haven't done anything new with padding the
server's response messages.

There is no compression in this code.

On the server side, the action kicks off inside ``tls_parse_ctos_encch()``
which decrypts the ENCCH, makes calls to parse the inner CH and then overwrites
some of the session parameters (in an ad-hoc manner, without real analysis as
to correctness) and sets the effective SNI. 

In the ``ssl/statem/extensions*.c`` files, extension handing code often has a
``context`` input parameter that determines which TLS protocol message is being
processed at a given moment. That's a bit mask, and I added bit definitions for
the inner and outer CH in addition to the existing bit that indicates the
current context is CH processing.  That's not a bad way to distiguish the inner
and outer.  That's done in ``include/openssl/ssl.h`` as those values are also
used in the external API (see below).  The new values are:

            #define SSL_EXT_CLIENT_HELLO_OUTER              0x8000
            #define SSL_EXT_CLIENT_HELLO_INNER              0x10000

This branch uses HPKE. The HPKE mode and suite are (for now) hardcoded and not
mapped from the TLS ciphersuite. The TLS session key share is used as the AAD.

I invented an ESNIKey version 0xff04/``ESNI_DRAFT_06_VERSION`` for this that's
used to get the pre-draft-06 behaviour, so earlier versions still work as
before.

A basic test on localhost works fine with no API changes so far.

Many of the error handling cases are not well handled in this build so far.

## Obvious TBDs

These are obvious things to do, but I've not done 'em yet:-)

- Think about how to use HPKE properly.
- Consider compression for when same value in inner/outer.

## Nesting

If we can do one ENCCH, we could certainly do more than one. So would such
nesting be interesting or useful? 

The only case I can envisage where that might just be useful would be where we
have web-sites, A is the ``public_name`` in B's ESNIConfig and B is the
``public_name`` in C's ESNIConfig, but where we don't want the name B to ever
be used in a cleartext SNI. With such a setup a CH for C would have B in
the outer CH. However, it seems unlikely there'll be a way to indicate
somewhere in B's DNS that that name should never be in a cleartext SNI.
So probably ok to not support any nesting, IOW, the inner CH MUST NOT
contain another inner CH.

## ALPN handling

It seems desirable to be able to send different ALPN values in the inner and
outer CH.

For the ``s_client`` command line, I added a new option:

            -alpn-outer val     When doing ECHO, send different "outer" ALPN 
                                extension, considering named protocols supported 
                                (comma-separated list) - "NONE" is a special
                                value indicating to send no "outer" ALPN

For the APIs, I added:

            SSL_CTX_set_alpn_outer_protos(SSL_CTX *s, unsigned char *alpn, size_t alpn_len); 
            SSL_set_alpn_outer_protos(SSL_CTX *s, unsigned char *alpn, size_t alpn_len); 

...where those need a prior call to ``next_protos_parse()`` (as with the
current functions without the ``_outer_``) and where they'll fail unless ESNI
has already been setup and with a ``ESNI_DRAFT_06_VERSION`` key. 

## Inner CH Padding

Up to draft-06, padding only affected the ESNI extension. Now however, we could
in addition have (at least) ALPN, but maybe also NPN or PSK identities in inner
CH with different length values from the outer CH. So we're no longer
padding the name but the entire inner CH. There are too many variants to
reasonably determine the exact size of the padded inner CH when creating an
ESNIConfig so we should change that.

Perhaps a good change would be for the ESNIConfig ``padded_length`` to now be
optional and when present to mean "ensure the inner CH is at least this long
and if longer is an integer multiple of 16 octets." When
no ``padded_length`` is specified, or if ``padded_length`` is shorter than
the inner CH, then I pad as described above, with between 0 and 47 padding
octets to get to a multiple of 16.

## EncryptedExtensions now also call for padding

Since we can now send ALPN in inner padded CH, that means we may also need
record layer padding around EncryptedExtensions, as it's length varies based on
the selected ALPN value. The same would be true if/when we have other values
present in EncryptedExtensions that depend on lengths found in the inner CH.
Since RFC8446 says that the padding extension can only be present in the CH,
we need to do that padding via the record layer.

## API issues

There is an
[API](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_add_custom_ext.html)
allowing applications to handle "custom" TLS extensions.  That could be bent
into shape to do what we want but more will be needed to provide fuller control
over what goes in the inner and outer CH's.

At this point, I'm not sure that offering a fine-grained-control API to
the application is the right thing.

## Could we ever use inner CH without ESNI?

Would there ever be a real use for an inner CH if the SNI in
the outer CH is the same as the inner? Probably not.

## Extension-specific handling

If a non-standard behaviour were needed then the "custom" extension API can be
used.  What we want though are standard behaviours for standard extensions.
The standard inner vs. outer behaviour, for any given ClientHello extension,
could be:

1. same value in both
1. same value in both, inner compressed
1. unrelated internally generated values in inner/outer
1. unrelated application provided values in inner/outer
1. extension only present in outer
1. extension only present in inner

Default behaviour is to have the same value in inner and outer.  If inner/outer
values differ, then the values could be internally generated or
application-supplied.

The table below lists the extensions supported in this build (the list here is from
``ssl/ssl_local.h`` where there's an ``enum`` defining these) and notes on
whether different inner/outer values might make sense. The "considered" column
indicates whether or not I spent time thining that row, and the "implemented"
colum describes the current implementation ("yes" meaning I did what's in the
notes).
The full list of extensions it at [IANA](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1) so I guess I should look there too sometime.

| Extension | Considered | Implemented | Notes |
| --------- | ---------- | ----------- | ----- |
| renegotiate | yes | same | not allowed in TLS1.3 - maybe need to test if we tried one in inner CH though |
| server_name | yes | yes | differ or inner-only, application supplied |
| max_fragment_length | yes | same | same, probably has to be same for split-mode |
| srp | a bit | same | dunno, defined in RFC 5054, smells like inner-only (it has a user name in it) if this is allowed with TLS1.3 (is it?) 8446 doesn't reference 5054 |
| ec_point_formats | yes | same | same, not supposed to be used in TLS1.3, but is sent in CH by OpenSSL, hmm |
| supported_groups | yes | same | same, see notes on key_share |
| session_ticket | yes | same | not in TLS1.3 CH, even if handler code makes it seem it could be |
| status_request | yes | same | same, in case of split mode |
| next_proto_neg | yes | same | differ or inner-only, application supplied, not coded up yet - is it still important? |
| application_layer_protocol_negotiation | yes | same | differ or inner-only, application supplied |
| use_srtp | yes | same | same - only SRTP profile (ciphersuite) stuff and SRTP to follow, so no point in varying |
| encrypt_then_mac | yes | same | same would make no sense to vary, but not sure why it's being sent - TLS1.3 & only AEADs are two reasons to not |
| signed_certificate_timestamp | yes | same | same, can't see a benefit in varying |
| extended_master_secret | yes | same | same, shouldn't be in TLS1.3 but openssl sends, no harm though and no reason to vary |
| signature_algorithms_cert | yes | same | same, in principle varying this could make sense but in practice there's no benefit |
| post_handshake_auth | yes | same | differ or inner-only, application supplied - be good to hide the fact of client auth (not implemented yet) |
| signature_algorithms | yes | same | same, in principle varying this could make sense but in practice there's no benefit |
| supported_versions | yes | same | same, maybe when TLS1.4 exists there'll be a benefit in varying, but not yet |
| psk_kex_modes | yes | same | same, in principle varying this could make sense but in practice there's no benefit |
| key_share | yes | same | same seems to work for all cases, but see more below |
| cookie | yes | same | same, could, but unlikely to, change my mind if/when I think about HRR processing in detail again:-) |
| cryptopro_bug | yes | none | this non-standard extension won't be in any CH (apparently) and has no ctos function |
| early_data | no | same | dunno |
| esni | yes | yes | used as esni-nonce in CH and for nonce in EncryptedExtensions |
| encch | yes | yes | outer only |
| certificate_authorities | yes | same | could vary in principle to hide client info but not so important, for browsers at least |
| padding | yes | yes | added by ESNI processing to inner, not sure if I might be breaking any apps using the API |
| psk | yes | inner only | see (still tentative) discussion below |

## TLS session key share handling with ECHO

For the ``key_share`` extension and ``supported_groups``, while there's no
pressing reason to want different key shares for OpenSSL today, there are two
reasons to do a bit more than that.  Firstly, if/as new algorithms are
introduced, there may be a need for different key shares in split mode.
Secondly, if anyone else implemented a client using different key shares, then
an OpenSSL server might need to support that, which'd in turn create a need for
client support, at minimum for test purposes.  So if different key share values
are not ruled out by the spec, then I'll likely want to implement support.
There wouldn't be any need for a very easy to use API for clients though.  None
of this is done yet, and it might necessitate either biggish changes to the
``SSL`` struct or else keeping two of those about, would need to check how many
fields would be changed if the key shares differ.

## Tickets 

I managed to create a PSK fail. To reproduce, run the test client twice:

            $ cd $HOME/code/openssl/esnistuff
            $ # start server
            $ ./testserver.sh -c example.com -H foo.example.com -d -a
            $ # get rid of session/tickets
            $ rm -f lof.sess
            $ # run client acquiring session
            $ ./testclient.sh -v -p 8443 -s localhost -H lotsoffood.example.com -c example.com -P esnikeys.pub -d -a -S lof.sess
            ...lots of output...
            ESNI: success: clear sni: 'example.com', hidden: 'lotsoffood.example.com'
            $ # try re-use session
            $ ./testclient.sh -v -p 8443 -s localhost -H lotsoffood.example.com -c example.com -P esnikeys.pub -d -a -S lof.sess
            ...lots of output...
            ESNI: tried but failed

Reminders to self: the ``-S`` option will save the sessions 1st time as the
named file doesn't exist and try re-use it 2nd time. Also - there's timing
here, the lof.sess file won't be created if we don't hang about for the
tickets, but running using valgrind (the ``-v`` there) makes it all take long
enough.

Initially, the failure was because I just copied the PSK extensions from the
inner to outer, and that won't verify - and that fail happened before the
inner was decrypted.  First try was to just not copy the PSK from inner,
but see if re-calculation worked. It didn't, of course, as the outer CH
was being used to verify the binder in the inner CH. 
Next try was to only include the PSK in the inner and see what happens.
That needed changes in the ``tls_parse_ctos_psk()`` code to
fix the inputs to the binder checking. Then it appeared to work.

Really need to check with early data though to be sure. So will look
at that next. Added a ``-E`` option to ``testclient.sh`` for that.
Haven't really tested yet though.

I didn't do anything with the non-ticket PSK mode yet. That'd
likely fail if tried.

In the end what's the right behaviour? Perhaps:
- bind the psk to the esni only, if esni is part of the stored session that
  goes with the ticket
- if using a psk whenever esni was ever in the frame, then only put that in the
  inner ch alongside the esni and don't put a psk in the outer ch at all

## Tickets and Early data

Now that PSK decryption seems to work, time to start playing with using
tickets. To start I added early data handling to ``testclient.sh`` and
``testserver.sh`` but it didn't work - it did work ok without ESNI. With
ESNI/ECHO, it fails - the early data is being rejected and we fall back to a
full h/s.  But it's not just early data - the ticket, while being presented and
decrypted was not being used to abbreviate the h/s.

To test this, I made a ``tick.sh`` that plays with tickets. If you run
``./tick.sh NONE`` it'll get and re-use a ticket with no ESNI/ECHO involved.
Just ``./tick.sh`` tries to do the same using ESNI/ECHO.  That fell back to a
full h/s until I found that without ESNI there's a bit of looking ahead into
the extension to detect a PSK in the (now outer) CH - that sets the ``s->hit``
in what was to me an unexpected way. When I eventually figured that out, I just
set that before sucessfullly returning from ``tls_parse_ctos_psk()`` when I've
processed an inner CH.



