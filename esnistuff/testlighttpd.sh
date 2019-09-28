#!/bin/bash

# set -x

OSSL="$HOME/code/openssl"
LIGHTY="$HOME/code/lighttpd1.4"

export LD_LIBRARY_PATH=$OSSL

# make directories for lighttpd stuff if needed
mkdir -p $OSSL/lighttpd/logs
mkdir -p $OSSL/lighttpd/www

# check for/make a home page
if [ ! -f $OSSL/lighttpd/www/index.html ]
then
    cat >$OSSL/lighttpd/www/index.html <<EOF

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Lighttpd top page.</title>
</head>
<!-- Background white, links blue (unvisited), navy (visited), red
(active) -->
<body bgcolor="#FFFFFF" text="#000000" link="#0000FF"
vlink="#000080" alink="#FF0000">
<p>This is the pretty dumb top page for testing. </p>

</body>
</html>

EOF
fi

# set to run in foreground or as daemon -D => foreground
# unset =>daemon
FOREGROUND="-D "

# set to use valgrind, unset to not
# VALGRIND="valgrind "
VALGRIND=""

$VALGRIND $LIGHTY/src/lighttpd $FOREGROUND -f $OSSL/esnistuff/lighttpdmin.conf -m $LIGHTY/src/.libs
