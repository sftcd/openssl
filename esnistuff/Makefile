# The main targets ###################################################
#

all: esni

libssl.a: ../libssl.a
	cp ../libssl.a .

libcrypto.a: ../libcrypto.a
	cp ../libcrypto.a .

esnimain.o: esnimain.c ../include/openssl/esni.h ../include/openssl/esnierr.h
	$(CC) -g -I../apps -I. -I..  -I../include -I../ssl $(BIN_CFLAGS) $(BIN_CPPFLAGS) -MMD -MF $<.d.tmp -MT $@ -c -o $@ $< 

# for some reason a symbol we need is not public in libssl.so but is in libssl.a
# so we'll just copy stuff down here for the moment - should be ok in the end as
# our final code won't be doing the direct call (I hope)
#

# change back to the line below when done debugging maybe
#${CC} -g -pthread -Wa,--noexecstack -Wall -O3 -o $@ $< -L. -lssl -lcrypto -ldl 

esni: esnimain.o libssl.a libcrypto.a
	${CC} -g -pthread -Wall -o $@ esnimain.o -L. -lssl -lcrypto -ldl 

test:
	./doit.sh fresh

clean:
	- rm -f esni esnimain.o libssl.a libcrypto.a *.tmp
