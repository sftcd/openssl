
# Initial thoughts on web server ESNI configuration

stephen.farrell@cs.tcd.ie, 20190911

As we start to integrate ESNI into a web server, we need to ponder how we'd
configure such a server.

The [defo.ie](https://defo.ie) setup is basically chewing gum and string, which
wouldn't be ok with a real web server:-)

There's a high level issue first: is key managment done inside or outside the
web server. After that, there are issues with how to configure which origins
are hidden, and cover names.

In text below we use apache terms as we're familiar with how to configure
apache servers.

## Key Management Outside

This is like the defo.ie setup. The key manager drops the public and private
key files in a directory and the web server loads those on startup, so the
directory name is a server config item. 

Since the key manager will delete old keys and create new ones from time to
time, there's also a need to configure some refresh duration into the web
server.  That could be e.g. a number of seconds (say 3600) after which the web
server re-syncs with the content of the configured directory. (Other
fine-grained options could work too.)

## Key Management Inside

In this case the web server generates the keys and then has to arrange to get
the ESNIKeys structures published. 

Key generation parameters would include how many keys to generate, with what
parameters (e.g.  algorithm parameters, ESNIKeys.version, addresses,
desired-TTLs etc.) and for how long keys will be retained as "live".

For publication, the web server could either use DDDS or the well-known URI
approach we used for defo.ie and documented in
[draft-farrell-tls-wkesni](https://tools.ietf.org/html/draft-farrell-tls-wkesni).
For the former, configurtation would require DDNS parameters (usually, a
service-name and an API key). For wkesni, a simple flag would be enough, as the
web server itself can publish the public value at the well-known URI.

## Cover name configuration

The cover name could be a standard VirtualHost, or could be a special thing.
Likely better to just have it as a standard VirtualHost.

If no cover name is used (no cleartext SNI at all) but ESNI is present and
works, then that should just work.

There should be a configuration to say if it's the cleartext SNI will be
ignored, or if the server requires use of a cover name that would otherwise
work.

## Hidden site configuration

It should be possible to configure so that all VirtualHosts can use ESNI.

Some VirtualHosts could be explicitly marked as being available via ESNI. 

Some VirtualHosts could be configured to not support ESNI.  This could be for
policy reasons. It's unclear if there are technical reasons that'd call for
this, but there could be. There may be some reason related to migration or if
ESNI is too flakey in some deployment. 

There may be some VirtualHosts that should only be visible if ESNI is used.
This is a bit of a corner-case as the ESNIKeys are assumed to be visible in
DNS, but could be of use if a client loads ESNIKeys some other way (e.g. via
the well-known URI or some other way). That last might be useful for some
censorship resistance scenario.

## Initial take

Given what we have with defo.ie it seems that a good-enough starting point is
to do outside key managment, to treat all ESNIKeys as being usable with all
VirtualHosts and to not insist that the cover name used (if any) is a real
VirtualHost.

