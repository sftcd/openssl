# Testing ECH-draft-13a build with FF/nss 

## NSS Build

I have nss in $HOME/code/nss with a couple of additional
logging additions. 

I'll try a fresh clone from the git repo this time:

            $ cd $HOME/code
            $ git clone https://github.com/nss-dev/nss.git
            $ hg clone https://hg.mozilla.org/projects/nspr

To build with HPKE (and ECH) enabled:

            $ ./build.sh -Denable_draft_hpke=1

## FF nightly enable

To enable ECH in FF (nightly in my case), goto about:config
and enable ``network.dns.echconfig.enabled`` which if off
by default. I assume FF probably needs DoH enabled, so have
that done (with my own DoH recursive for now).

### Test FF nightly

Going to [https://crypto.cloudflare.com/cdn-cgi/trace](https://crypto.cloudflare.com/cdn-cgi/trace) works fine

### nss tstclnt

I had to make various changes to [nssdoech.sh](nssdoech.sh). Those
aren't complete but I did get basic ECH interop between my NSS build
and CF and draft-13.esni.defo.ie:8413.

