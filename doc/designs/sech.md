

# encoding the server name
The server_name extension as described in RFC 6066 allows only
for host name type server names, but is designed for the possibility
of extension, i.e. adding different possible name types.

A question remains as to whether the host name type should be encoded
for SECH. On the one hand, there is currently only one host name type
defined and in use in IETF specifications (TODO sure about that?).
On the other hand, other name types may be introduced in future,
so it may be wise to preserve some bits for the purpose of
distinguishing different name types in future.

For now, let's just consider encoding HostName type names.
A HostName is a fully qualified DNS hostname, which is
case insensitive ASCII encoded byte-string without a trailing dot.

Structure of an FQDN:
- An FQDN must not exceed 253 characters (bytes) total.
- An FQDN is made up of "labels", which are the parts between the dots, and labels must have a length between 1 and 63.
- Labels can contain ASCII letters 'a' through 'z' (case insensitive), the digits '0' through '9', and the hyphen '-'.
- Labels must not start or end with a hypen '-'.
- The last label (the Top-Level Domain) must be at  least 2 characters long, and must not contain a hyphen.

We can enforce that SECH encodings of FQDNs exclude upper case 'A' through 'Z'.
Therefore the total number of symbols in a label is 26 + 10 + 1 = 37, and the total number
of possible symbols in a FQDN is 38.

### simple encoding
Given the 32 octets available in the ClientHello.random, a simple encoding would be to encode the FQDN
as ASCII bytes with a maximum length of 32, and with 0x00 padding. If all 32 symbols are used then there is no padding.
This is ok because none of the 38 ASCII symbols are 0x00.

### increasing max length with bit packing
Given the restrictions on FQDNs, it is possible to compress longer names into the 32x8 available bits.
A single symbol can be encoded with 6 bits, 2**6 = 64 > 38.
We terminate an FQDN with the zero 6-tet 0b000000, giving us a total of 39 symbols.
Therefore, we can pack 42 FQDN symbols into the 32x8 bits, with 4 remaining bits.

However, Shannon (TODO which theorem?) tells us that, given an arbitrarily long input string,
the ideal number of bits per symbol is log(38) which is less than 6.
So, an ideal encoder would allow us to send FQDNs of length 256/log(38)=48.7811
losslessly.

### increasing max length with a state machine
To leverage all of the restrictions on FQDNs, we can construct a state machine to
maximise the number of symbols we can encode in the 32x8 bits.

TODO: construct state machine

# design of the SECH server(s)
SECH, like ECH, provides anonymity relative to an anonynmity set,
i.e. the set of backend servers accessible via SECH.
These backend servers may be virtual (i.e. there is truly only one process
performing the functions of all servers), or they may be
truly distinct processes running on the same machine or a different machine.
