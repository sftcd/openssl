# The main targets ###################################################
#

all: esni mk_esnikeys

# While futzing with documentation/doxygen stuff this is handy
thelot:
	- (cd ..;make)
	- make esni
	- make test
	- make doc	
	- ./testclient.sh -H ietf.org

libssl.a: ../libssl.a
	cp ../libssl.a .

libcrypto.a: ../libcrypto.a
	cp ../libcrypto.a .

doc: 
	- doxygen esni.doxy
	- moxygen -a doxy/xml
	- cat api.md | sed -e 's/\(.*{#\)\(.*\)}/<p id="\2"><hr><\/p>\n\n\1/' | sed -e 's/{#//' >api2.md
	- mv api2.md api.md
	- multimarkdown api.md >api.html

docclean:
	- rm -rf doxy

# for some reason a symbol we need is not public in libssl.so but is in libssl.a
# so we'll just copy stuff down here for the moment - should be ok in the end as
# our final code won't be doing the direct call (I hope)
#

# change back to the line below when done debugging maybe
#${CC} -g -pthread -Wa,--noexecstack -Wall -O3 -o $@ $< -L. -lssl -lcrypto -ldl 

esnimain.o: esnimain.c ../include/openssl/esni.h ../include/openssl/esnierr.h
	$(CC) -g -I../apps -I. -I..  -I../include -I../ssl $(BIN_CFLAGS) $(BIN_CPPFLAGS) -MMD -MF $<.d.tmp -MT $@ -c -o $@ $< 

esni: esnimain.o libssl.a libcrypto.a
	${CC} -g -pthread -Wall -o $@ esnimain.o -L. -lssl -lcrypto -ldl 

test:
	./doit.sh fresh -v

staletest:
	./doit.sh

mk_esnikeys: mk_esnikeys.o

mk_esnikeys.o: mk_esnikeys.c ../include/openssl/esni.h 
	$(CC) -g -I../apps -I. -I..  -I../include -I../ssl $(BIN_CFLAGS) $(BIN_CPPFLAGS) -MMD -MF $<.d.tmp -MT $@ -c -o $@ $< 

mk_esnikeys: mk_esnikeys.o libssl.a libcrypto.a
	${CC} -g -pthread -Wall -o $@ mk_esnikeys.o -L. -lssl -lcrypto -ldl 

clean:
	- rm -f esni esnimain.o libssl.a libcrypto.a *.tmp 
	- rm -f mk_esnikeys.o mk_esnikeys 
	- rm -f nss.premaster.txt nss.ssl.debug

keys:
	- ./make-esnikeys.sh
	- ./testserver.sh -K

keyclean:
	- rm -f esnikeys.pub esnikeys.priv
	- rm -rf esnikeydir
	- rm -rf cadir

reallyclean: clean docclean keyclean

