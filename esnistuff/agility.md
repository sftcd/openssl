
# ECH algorithm/parameter agility tests

This file documents a set of tests for the various algorithms
involved in ECH. The goal is just to test that we support all
the algorithm combinations we thing we support. The set of 
tests is likely to be extended over time. These tests should
(and, later, will) be part of the OpenSSL ``make test`` target.

## Degrees of freedom

The things that might vary include:

* number of SVCB/HTTPS RRs in DNS, 
* within each SVCB/HTTPS RR:
    * >1 ECHConfig?
    * differing SvcPriority
    * other SvcParamKeys: port, alpn, no-default-alpn, ipvXhint
        - not all will need tests/code but should ponder each
* number of ECHConfigContents in an ECHConfig is now just one! (check)
* combos of kem,kdf,aead as per HPKE
* multiple (kdf,aead) choices per ECHConfig
* use of invalid code-points and some from GREASEy ranges as 
  appropriate
* maybe some fuzz tests, with bogus encodings of e.g. ECHConfig
  (could be a mixture of random and hand-crafted)

Ideally, all of the above should be easy(ish) to port to the
``make test`` target environment later on.

## Scripting it up...

The [agiletest.sh](agiletest.sh) script has it all.

So far (20210622) that just tests key generation - more to come.


