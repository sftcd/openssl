# The current padding scheme for ECH

These are some notes as to what I've currently implemented for OpenSSL
``s_client`` and ``s_server`` in this branch.

## Outer ClientHello

- No special action.

## Inner ClientHello

- Status quo ante was that CH padding was added iff a padding option was set.
- In that case, padding is added to ensure the CH works around the old F5 bug,
  meaning that the CH is between 0xff and 0x200 in lengta.
- For now the same CH padding alg is also run if we're doing a real or GREASE
  ECH.
- Result is padding ECH extension value to 0x1fc via inclusion of TLS padding
  extension in inner CH just making use of existing OpenSSL ``s_client``
padding code.

## GREASE ECH

- Now also padded to 0x1fc of fake ciphertext (length chosen for now based on
  the behaviour seen with inner CH padding, likely needs more consideration.)
- I added a command line option to fix the fake ECH KEM, absent which a random
  HPKE suite is chosen, which can vary the length some and stick out.
- I also coded up an option to add or subtract a random <=N octets of jitter
  for fake ciphertext, but currently setting N=0. (Maybe couple N=0 with CLA?)
- (That 0x1fc above is dependent on which inner CH extensions are "compressed",
  which is a compile-time option, so I ought re-calculate that based on the
same code used for real ECH inner padding.)

## ServerHello

- ``key_share`` extension can leak some information, if outer CH shares don't
  include one from the group chosen from inner CH shares.
- RFC8446 of course doesn't allow padding in SH, and it'd be in clear anyway.
- One could define an overly-complex scheme whereby we lengthen a too-short
  SH.key-share and signal which innerCH.key-share we picked via some bits in
  the ECH accept magic number, but you'd have to find a way to handle the case
  where the selected group shares are longer than anything in the outer CH, so
  that's clearly not a good plan.
- Seems like we could do with a MUST or SHOULD to the effect that the outer CH
  share groups ought be a superset of those in the inner CH if we want to avoid
  this length leak.
- (The SH.ciphersuite can cause a similar kind of leak so probably warrants a
  similar MUST or SHOULD.)

## Certificate

- This is padded to a multiple of 1800, via an ``s_server`` callback.

## CertificateVerify

- This is padded to a multiple of 500, via an ``s_server`` callback.

## EncryptedExtensions

- These are all padded to a multiple of 32, via an ``s_server`` callback.
- The selected ALPN is one of those.

