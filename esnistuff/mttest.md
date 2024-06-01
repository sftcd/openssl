# ECH APIS, tests and threads

stephen.farrell@cs.tcd.ie, 2024-06-01

Viktor raised a reasonable question about multi-thread behaviour for some of
the new ECH APIs. This note has thinking about that and what to do in terms 
of changes and tests.

OpenSSL threading stuff is described [here](https://www.openssl.org/docs/manmaster/man7/openssl-threads.html)
@vdukhovni asked about locking [here](https://github.com/openssl/openssl/pull/20408#discussion_r1596376501)
@FDaSilvaYY raised the ``STACK_OF()`` issue [here](https://github.com/openssl/openssl/pull/22938#discussion_r1606106483)
``STACK_OF()`` is described [here](https://www.openssl.org/docs/manmaster/man3/DEFINE_STACK_OF.html)

Probably calls to ``SSL_CTX_ech_server_enable_dir()`` are the most likely to
hit issues with delays that might cause issues, given a directory could have a
lot of files (even if that's unexpecteded) and/or access to the file-system
might block for various reasons (much more likely). However, it's not clear to
me if an ``SSL_CTX`` is actaully allowed to be updated in different threads at
all.

It might well happen that client calls to ``SSL_ech_set1_echconfig()`` or any
of the other "setter" APIs happen either before or after a new thread is
created, i.e. that the ``SSL`` object is created in a parent and updated in a
child thread.

This could be related to a separate issue, related to our current non-use of
``STACK_OF()`` for storing the list of ECHConfig settings associated with an
``SSL_CTX`` or ``SSL`` structure. So, once we've figured out what
multi-threaded behaviour we'd like for ECH APIs, then we might wanna decide
whether or not to move to using ``STACK_OF`` before spending effort on
mutli-tread ECH tests. (Though the documentation for ``STACK_OF()`` warns
about thread-safety, so not sure if using it would be good or bad from the
multi-threaded perspective.)
