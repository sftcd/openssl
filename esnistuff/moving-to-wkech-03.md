
# Notes on test/debug/deployment of wkech-03.sh

2023-08-04, sf - useful to have notes of what happens as I test this...

[draft-ietf-tls-wkech](https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech) specifies
a method for updating ECH keys. The [git repp](https://github.com/sftcd/wkesni/) for
that includes a work-in-progress [bash script](https://github.com/sftcd/wkesni/blob/master/wkech-03.sh)
that aims to implement the spec. These notes describe the process of testing
that for my DEfO test setup.

We'll start though with the my-own.net deployment, which is simpler (and less
visible:-). That one is simpler as it only involves one nginx web server,
ECH-enabled on two ports (443 and 8443), compared to the defo.ie deployment
that has a bunch of different server implementations on different ports..

## Rebuilding ECH on foo.ie/my-own.net

First up, update binaries on the relevant machine...

This host has one ECH-enabled nginx running from the usual system config and
binary directories.

To test ECH is working, visit [https://my-own.net/ech-check.php](https://my-own.net/ech-check.php)
with an ECH-enabled browser and you should see a green check mark.

### Get $HOME/code/openssl-for-nginx and $HOME/code/nginx up to date.

On the web server, we want the ECH-draft-13c branch of openssl and the
ECH-experimental branch of nginx. Doing that from fresh would look like:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl openssl-for-nginx
            $ cd openssl-for-nginx
            $ git checkout ECH-draft-13c
            $ cd $HOME/code
            $ git clone https://github.com/sftcd/nginx
            $ cd $HOME/code/nginx
            $ git checkout ECH-experimental

The default is to re-build OpenSSL as a static library inside the
nginx binary. (Hence the use of ``openssl-for-nginx`` build dir.)

Re-build:

            $ cd $HOME/code/nginx
            $ ./auto/configure --with-debug --prefix=/var/lib/nginx --with-http_ssl_module --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module --with-openssl=$HOME/code/openssl-for-nginx  --with-openssl-opt="--debug" --with-http_v2_module
            $ make
            ...
            $ sudo make upgrade
            ...

If the ``make upgrade`` fails then after the build has worked...

            $ sudo cp $HOME/code/ngins/objs/nginx /var/lib/nginx/sbin/nginx
            $ sudo service nginx restart

The wkech script also needs openssl binaries, so good to update those
too, both on the web server and the zone factory:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl
            $ git checkout ECH-draft-13c
            $ ./config -d
            ...
            $ make
            ...
            

### Turn off old scripts on web server and zone factory

The old crontab entry for the web server:

            $ crontab -l
            ...
            10 * * * * /home/sftcd/bin/foo.ie-regen-echkeys.sh >>/home/sftcd/logs/regen-echkeys.log

The old crontab entry on the zone factory:

            $ crontab -l
            ...
            11 * * * * /home/sftcd/bin/foo.ie-repub-echkeys.sh >>/home/sftcd/logs/update-echkeys.log

Delete or comment out those lines. (But not right at 10 or 11 after the hour:-)

### Enable new scripts

Got here, more coming...

- I need to review the wkech-03.sh script to see it works for
  this paritcular config. (same binary, 2 ports, whatever 
  DocRoot settings I have)
- Changes made:
    - ``$ECHTOP`` default changed to ``$HOME/ech`` - not sure why I didn't
      use the same everywhere:-)
    - frontend changed to foo.ie, backends to my-own.net, my-own.net:8443
    - backend DocRoots changed similarly (both be's use same here!)
