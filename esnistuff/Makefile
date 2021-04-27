# The main targets ###################################################
#

all: 

# While futzing with documentation/doxygen stuff this is handy
thelot:
	- make doc	

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

clean:
	- rm -f libssl.a libcrypto.a *.tmp 
	- rm -f nss.premaster.txt nss.ssl.debug

keys:
	- ./make-example-ca.sh
	- ./doech.sh

keyclean:
	- rm -f echoconfig.pem
	- rm -rf cadir

reallyclean: clean docclean keyclean

