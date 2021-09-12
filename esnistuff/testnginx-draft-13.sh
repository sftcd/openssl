#!/bin/bash

# set -x

OSSL="$HOME/code/openssl"
NGINX="$HOME/code/nginx-draft-13"

# nginx build seems to statically link openssl for now (ickky)
# export LD_LIBRARY_PATH=$OSSL

# Kill off old processes from the last test
killall nginx

# make directories for lighttpd stuff if needed
mkdir -p $OSSL/esnistuff/nginx/logs
mkdir -p $OSSL/esnistuff/nginx/www
mkdir -p $OSSL/esnistuff/nginx/baz

# in case we wanna dump core and get a backtrace, make a place for
# that (dir name is also in nginxmin-draft-13.conf)
mkdir -p /tmp/cores

# check for/make a home page for example.com and other virtual hosts
if [ ! -f $OSSL/esnistuff/nginx/www/index.html ]
then
    cat >$OSSL/esnistuff/nginx/www/index.html <<EOF

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>nginx top page.</title>
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

# check for/make a slightly different home page for baz.example.com
if [ ! -f $OSSL/esnistuff/nginx/baz/index.html ]
then
    cat >$OSSL/esnistuff/nginx/baz/index.html <<EOF

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>nginx top page.</title>
</head>
<!-- Background white, links blue (unvisited), navy (visited), red
(active) -->
<body bgcolor="#FFFFFF" text="#000000" link="#0000FF"
vlink="#000080" alink="#FF0000">
<p>This is the pretty dumb top page for baz.example.com testing. </p>

</body>
</html>

EOF
fi

# set to use valgrind, unset to not
# VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
# VALGRIND="valgrind --leak-check=full "
VALGRIND=""

echo "Executing: $VALGRIND $NGINX/objs/nginx -c $OSSL/esnistuff/nginxmin-draft-13.conf"
# move over there to run code, so config file can have relative paths
cd $OSSL/esnistuff
$VALGRIND $NGINX/objs/nginx -c $OSSL/esnistuff/nginxmin-draft-13.conf 
cd - 
