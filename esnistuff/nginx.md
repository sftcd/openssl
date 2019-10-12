
# Playing about with nginx

## Clone, Build and Run

Note that PRs against the github repo aren't desired. But I didn't check out
what they do desire yet:-)

            $ cd code
            $ git clone https://github.com/sftcd/nginx.git
            $ cd nginx
            $ ./auto/configure --with-debug --prefix=nginx --with-http_ssl_module --with-openssl=$HOME/code/openssl
            $ make
            ... go for coffee ...

- That seems to re-build openssl (inc. a ``make config; make clean``) within
  $HOME/code/openssl for some reason.
- And that includes creating a new "$HOME/code/openssl/.openssl" directory
  where it puts files from $HOME/openssl/include, static libraries and an
  openssl command line binary.
- And it doesn't detect if I change code e.g. $HOME/code/openssl/ssl/esni.c or
  $HOME/code/openssl/include/openssl/esni.h
- Odd. 

Other than that the "--prefix=nginx" setting there is to match our [testnginx.sh](testnginx.sh)
script.  The [nginxmin.conf](nginxmin.conf) file that uses has a minimal configuration to 
match out localhost test setup.

            $ cd $HOME/code/openssl/esnistuff
            $ ./testnginx.sh
            ... prints stuff, spawns server and exits ...
            $ curl  --connect-to baz.example.com:443:localhost:5443 https://baz.example.com/index.html --cacert cadir/oe.csr 
            
            <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
                "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
            <html xmlns="http://www.w3.org...

## ESNI configuration

I added an ESNI key directory configuration setting that can be within the ``http``
stanza (and maybe elsewhere too, I don't fully understand all that yet;-). Then,
with a bit of generic parameter handling and the addition of a ``load_esnikeys()`` 
function that's pretty much as done for [lighttpd](./lighttpd), ESNI... just worked!

You can see that configuration setting, called ``ssl_esnikeydir`` in our
test [nginxmin.confg](nginxmin.conf).

            $ ./testnginx.sh
            ... stuff ...
            $ /testclient.sh -p 5443 -s localhost -H baz.example.com -c example.net -P esnikeydir/ff03.pub
            Running ./testclient.sh at 20191012-125357
            ./testclient.sh Summary: 
            Looks like 1 ok's and 0 bad's.
            

