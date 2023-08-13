
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

The new script is now working on my-own.net (ports 443 and 8443) with the
public name of foo.ie. That's an nginx build.  The ``wkech-03.sh`` script
imports vars from ``echvars.sh`` so, on my-own.net and the relevant zf I've put
the local ``echvars.sh`` file into $HOME/bin and then I run the script from
there via cron.

The new crontab entries for the fe and be is now:

            $ crontab -l
            ...
            40 * * * * (cd /home/sftcd/bin; /home/sftcd/code/wkesni/wkech-03.sh) >>/home/sftcd/logs/wkech-03.log

And for the zf:

            $ crontab -l
            ...
            42 * * * * (cd /home/sftcd/bin; /home/sftcd/code/wkesni/wkech-03.sh -r zf) >>/home/sftcd/logs/wkech-03.log

That's still publishing the most recent 3 public values, which is perhaps
not needed, but we'll keep that for the moment as it may turn up some 
bugs. (TODO: change to just publishing one public value but also setup a
range of HTTPS RRs that have good/bad values, i.e. revisit our DNS fuzzing
ideas.)

### Starting to re-build on defo.ie

2023-08-11: starting to refresh the builds on defo.ie and will then move
to using the new script.

Notes on rebuilds:

- updated $HOME/code/openssl to ECH-draft-13c 
- updated $HOME/code/openssl-for-nginx to ECH-draft-13c
- updated $HOME/code/nginx as per the above build 
    - both port 443 and 10413 redone ok
- updated $HOME/code/lighttpd1.4, needed to install ``libpcre2-dev`` and mess with git a bit
- updated $HOME/code/httpd (apache2)
- updated $HOME/code/haproxy

Notes on existing setup:

- Turned off cronjobs as above
- Be useful to document the current setup a bit (it's a bit all over the place:-)

script                    | server    |   port  | name                  | cfg file                 | docroot                             | ech key dir
--------------------------|-----------|---------|-----------------------|--------------------------|-------------------------------------|-------------------
nginx443.sh               | nginx     |   443   | cover.defo.ie         | nginx-443.conf           | /var/www/html/cover                 | ~/.ech/echkeydir
nginx443.sh               | nginx     |   443   | defo.ie               | nginx-443.conf           | /var/www/html/home                  | ~/.ech/echkeydir
defoserver-draft13.sh     | s_server  |  8413   | draft-13.esni.defo.ie | n/a                      | /var/www/html/cover                 | ~/.ech/echkeydir
defoserver-draft13-hrr.sh | s_server  |  8414   | draft-13.esni.defo.ie | n/a                      | /var/www/html/cover                 | ~/.ech/echkeydir
lighttpdserver-draft13.sh | lighttpd  |  9413   | draft-13.esni.defo.ie | lighttpd-9413.conf       | /var/www/draft-13/lighttpd/draft-13 | ~/.ech/echkeydir
nginx-draft-13.sh         | nginx     | 10413   | draft-13.esni.defo.ie | nginx-10413.conf         | /var/www/draft-13/nginx/draft-13    | ~/.ech/echkeydir
apache-draft-13.sh        | httpd     | 11413   | draft-13.esni.defo.ie | apache-11413.conf        | /var/www/draft-13/apache/draft-13   | ~/.ech/echkeydir
haproxyserver-12413.sh    | haproxy   | 12413   | draft-13.esni.defo.ie | haproxy-12413.conf       | shared, be via port 11413           | ~/.ech/echkeydir
haproxyserver-12414.sh    | haproxy   | 12414   | draft-13.esni.defo.ie | haproxy-12414.conf       | split, be via port 11413            | ~/.ech/echkeydir

- after changes made...

script                    | server    |   port  | name                  | cfg file            | docroot                             | ech key dir
--------------------------|-----------|---------|-----------------------|---------------------|-------------------------------------|-------------------
nginx443.sh               | nginx     |   443   | cover.defo.ie         | nginx-443.conf      | /var/www/html/cover                 | ~/ech/cover.defo.ie.443
nginx443.sh               | nginx     |   443   | defo.ie               | nginx-443.conf      | /var/www/html/home                  | ~/ech/cover.defo.ie.443
defoserver-draft13.sh     | s_server  |  8413   | draft-13.esni.defo.ie | n/a                 | /var/www/html/s_server              | ~/ech/cover.defo.ie.443
defoserver-draft13-hrr.sh | s_server  |  8414   | draft-13.esni.defo.ie | n/a                 | /var/www/html/s_server_hrr          | ~/ech/cover.defo.ie.443
lighttpdserver-draft13.sh | lighttpd  |  9413   | draft-13.esni.defo.ie | lighttpd-9413.conf  | /var/www/draft-13/lighttpd/draft-13 | ~/ech/cover.defo.ie.443
nginx-draft-13.sh         | nginx     | 10413   | draft-13.esni.defo.ie | nginx-10413.conf    | /var/www/draft-13/nginx/draft-13    | ~/ech/cover.defo.ie.443
apache-draft-13.sh        | httpd     | 11413   | draft-13.esni.defo.ie | apache-11413.conf   | /var/www/draft-13/apache/draft-13   | ~/ech/cover.defo.ie.443
haproxyserver-12413.sh    | haproxy   | 12413   | draft-13.esni.defo.ie | haproxy-12413.conf  | shared, be via port 11413           | ~/ech/cover.defo.ie.443
haproxyserver-12414.sh    | haproxy   | 12414   | draft-13.esni.defo.ie | haproxy-12414.conf  | split, be via port 11413            | ~/ech/cover.defo.ie.443

- Configured an ``echvars`.sh`` file on defo.ie to represent the above.
- re-did the scripts for ports 8413, 8414, 9413, 10413 and 11413
- manually published a new HTTPS RR for defo.ie to match landing place for wkech script
  (that should keep things working 'till we turn on new cronjobs)
- haproxy (ports 12413 and 12414) needs new backends (due to wkech URL)
    - added a 13413 apache as backend to 12413 and 13414 as backend to 12414


