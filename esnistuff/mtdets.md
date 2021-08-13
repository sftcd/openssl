
# An exanple of checking out a ``make test`` fail.

I had just modified some code in ``ssl/ssl_lib.c`` with an
innoucous change (so I thought:-).

``make test`` produced a failure, for the ``90-test_sslapi.t``
test, so to get more info I ran that one test by itself:

            $ make V=1 TESTS=test_sslapi V=1 >xx 2>&1

Near the end of that file I saw the failing case (that
doesn't have to be at the end IIUC):

            ../../util/wrap.pl ../../test/sslapitest ../../test/certs ../../test/recipes/90-test_sslapi_data/passwd.txt /tmp/ZjTvv7YSDq default ../../test/default.cnf => 139
            not ok 1 - running sslapitest

That showed me which binary was being run where, in this
case it was the ``test/sslapitest`` binary, which was 
being run from within the ``test-runs/test_sslapi`` 
directory.

That allowed me to re-run just that binary, from within
that directory, without the perl wrapper:

            $ cd test-runs/test_sslapi
            $ ../../test/sslapitest ../../test/certs ../../test/recipes/90-test_sslapi_data/passwd.txt /tmp/ZjTvv7YSDq default ../../test/default.cnf

The result was a crash, so (having build the libarary in debug
mode), I could use gdb to see where it was crashing out:

            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            $ gdb ../../test/sslapitest
            ...
            (gdb) r ../../test/certs ../../test/recipes/90-test_sslapi_data/passwd.txt /tmp/ZjTvv7YSDq default ../../test/default.cnf
            ...
            Program received signal SIGSEGV, Segmentation fault.
            0x00007ffff7f239b4 in SSL_set0_rbio (s=0x0, rbio=0x555555838fd0) at ssl/ssl_lib.c:1404
            1404	    if (s->rbio)
            (gdb) bt
            #0  0x00007ffff7f239b4 in SSL_set0_rbio (s=0x0, rbio=0x555555838fd0) at ssl/ssl_lib.c:1404
            #1  0x000055555557e618 in test_ssl_dup () at test/sslapitest.c:8516
            #2  0x0000555555585343 in run_tests (test_prog_name=0x7fffffffdfc7 "/home/stephen/code/openssl/test/sslapitest")
                at test/testutil/driver.c:334
            #3  0x0000555555585f77 in main (argc=6, argv=0x7fffffffdc48) at test/testutil/main.c:30
            (gdb) 

And then I could see the stack trace and do the usual gdb stuff to figure out
what silly error I'd made. In this case, it turned out to be a call to
``OPENSSL_malloc(0)`` which doesn't work.

