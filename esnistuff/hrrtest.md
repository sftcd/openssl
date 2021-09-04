# An ECH and HRR test setup

Since I'm figuring this out, I need notes... these are they.

To trigger HRR we need a client that claims to support the
usual set of groups (which is most of 'em), and for that
client to send no key_share that the server supports (so
we need a server with fewer than usual groups supported).

So, first we need a server, we can use the echsrv.sh 
script...

            $ cd $HOME/code/openssl/esnistuff
            $ ./echsvr.sh -vdTPR
            ...

In the above only the ``-R`` is really needed but:

    - -R is to trigger HRR by only supporting P-384 
    - -v is for valgrind
    - -d is for debug
    - -T is for trial decryption
    - -P is for server-side padding

## GREASEing

We'll start, as always, with GREASE.

            $ ./echcli.sh -dv -p 8443 -s localhost -H example.com -g
            ...
            ECH: only greasing, and got ECH in return
            $

The TLS h/s worked and valgrind is happy. 

Initially, the 2nd CH had a brand new GREASEy ECH. The spec says to re-tx the
same value though, apparently due to some 8446 restrictions that are taken too
seriously by some deployed code somewhere. (They barf if the 2nd CH changes
unexpectedly.) Added code to re-tx the same thing so all seems well. 
The background for this 
is [here](https://github.com/tlswg/draft-ietf-tls-esni/issues/358).

## Real ECH

If we run the usual client...

            $ ./echcli.sh -dv -p 8443 -s localhost -H foo.example.com -P d13.pem
            ... fail

            $ ./echcli.sh -dv -p 8443 -s localhost -H foo.example.com -P badkey.pem
            ... currently working

STATE:
- both sides appear to work locally
- interop - check transcript really as expected etc.
    - in the process of checking that with boringssl...
    - added seq input to HPKE APIs to enable incrementing
      nonce for 2nd CH encryption/decryption - doesn't yet
      make HRR interop work, but does seem to move it along
      a bit, suspect the transrcipt/AAD handling needs a
      change too...
