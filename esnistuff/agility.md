
# ECH algorithm/parameter agility tests

This file documents a set of tests for the various algorithms
involved in ECH. The goal is to test that we support all
the algorithm combinations we thinl we support. The set of 
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
* session storage and resumption
* maybe some fuzz tests, with bogus encodings of e.g. ECHConfig
  (could be a mixture of random and hand-crafted)

Ideally, all of the above should be easy(ish) to port to the
``make test`` target environment later on.

## Scripting it up...

The [agiletest.sh](agiletest.sh) script does this.

So far (20210706) that run a test for each kem/kdf/aead algorithm
combination (45 in total):

- key generation 
- starting an ``openssl s_server`` and doing a nominal ``s_client`` ECH test 
- starting an ``openssl s_server`` and doing an intended to fail ``s_client``
  ECH test with the wrong ECHConfig 
- testing nominal session storage/resumption 

All seems well so far, i.e. tests pass as expected.

The script creates a temporary directory below /tmp where
PEM ECHConfig files for each kem, kdf and aead are created, as are
fake-CA keys and TLS server certs. Stored session files are also
created for each combination. There are a few environment
variables that can be set before running it:

- ``KEEP``: if set this won't delete the tmp dir at the 
end of the run.
- ``SCRATCHDIR``: you can use this to re-use a tmp dir
from a previous run
- ``VERBOSE``: gets more verbose output (what you get 
depends on how you build OpenSSL).

If an unexpected error is encountered the script exits
leaving the tmp dir behind, so you can examine things
and try re-produce errors. You might therefore need to remove
those manually if things have gone wrong.

There are some ``sleep`` statements in the script and
a whole pile of combinations to this may take a while to
finish fully, maybe 10 minutes.

Some example uses:

            $ ./agiletest.sh


