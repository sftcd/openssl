
# Command lines for local tests

I keep forgetting so, as this directory exists...

- Run a server...

            $ ./testserver.sh -c example.com -H foo.example.com 

- Run a server that fails if ESNI does - default is fall back to the cover (sorta) if ESNI tried but failed 

            $ ./testserver.sh -c example.com -H foo.example.com -F

- Run a client, not really doing ESNI

            $ ./testclient.sh -p 8443 -s localhost -n -c example.com  -vd

- Run a client, not really doing ESNI, but greasing

            $ ./testclient.sh -p 8443 -s localhost -n -c example.com -g -vd

- Run a client, doing ESNI

            $ ./testclient.sh -p 8443 -s localhost -H foo.example.com -c example.com -P esnikeys.pub -vd




