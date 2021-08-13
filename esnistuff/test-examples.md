
# ESNI test Command line examples

All these assume you're in $HOME/code/openssl/esnistuff

## Basic build confidence...

Sometimes a build goes bad after a git pull (and you gotta do "./config;make clean;make"
in $HOME/code/openssl). In such cases this basic test often demonstrates we're in that
situation:

            $ make test

## Local tests

I keep forgetting so, as this directory exists...

- Run a server...

            $ ./testserver.sh -c example.com -H foo.example.com 

- Run a server that fails if ESNI does - default is fall back to the cover (sorta) if ESNI tried but failed 

            $ ./testserver.sh -c example.com -H foo.example.com -F

- Run a server that does trial decryption if ESNI doesn't match - default is to not

            $ ./testserver.sh -c example.com -H foo.example.com -T

- Run a server that loads no keys but that'la react to grease 

            $ ./testserver.sh -c example.com -n

- Run a client, not really doing ESNI, with valgrind

            $ ./testclient.sh -p 8443 -s localhost -n -c example.com  -vd

- Run a client, not really doing ESNI, but greasing, with valgrind

            $ ./testclient.sh -p 8443 -s localhost -n -c example.com -g -vd

- Run a client, doing ESNI, with valgrind

            $ ./testclient.sh -p 8443 -s localhost -H foo.example.com -c example.net -P esnikeys.pub -vd

- Run a client, doing ESNI, with a specific version of ESNIKeyso

            $ ./testclient.sh -p 8443 -s localhost -H foo.example.com -c ff03.example.net -P esnikeydir/ff03.pub -vd

## Non local tests 

- Our basic bottom line test

            $ ./testclient -H ietf.org

- Nominal to defo.ie

            $ ./testclient.sh -H only.esni.defo.ie -c cover.defo.ie -d

- Nominal to defo.ie, for draft-04 (replace 04 with 03 or 02 as desired) 

            $ ./testclient.sh -V 04 -H only.esni.defo.ie -c cover.defo.ie -d

- Grease to defo.ie

            $ ./testclient.sh -c cover.defo.ie -ngd

