# ESNI and resumption notes

This is a separate file for now, when done and conclusions reached, I'll
summarise it in the design doc.

Server stays running in all tests so far. Check server restart affects later. 

The bottom line seems to be that there's a need to bind the HIDDEN to the
session, and maybe also the COVER. That isn't quite the current behaviour,
and it seems wrong that the server doesn't detect changes to HIDDEN, and 
that I get to confuse the client as to what the server saw. (Which seems
to be the case based on the tests below.)

So I think I want to add HIDDEN/COVER to sessions and to check that on
resumption in the server and client.

But if that's not current behaviour, it might break something.

So I might also want to keep the no ESNI and no SNI behaviour the same
as today, even if that's not quite the right idea.

Aside from ESNI-aware servers/clients dealing with unaware peers, we
also gotta worry about sessions that are stored and valid whilst the
peer's code is updated. Not sure how to handle that, probably need to
ask maintainers.

## Non-wildcard test cases:

- t1: no esni to HIDDEN
	- client connects without ESNI and stores session 
	- client re-connects without ESNI and reuses session 
	- commands:
			$ ./testclient.sh -p 4000 -s localhost -n -c foo.example.com -vd -S t1sess >t1log.first 2>&1
			$ ./testclient.sh -p 4000 -s localhost -n -c foo.example.com -vd -S t1sess >t1log.second 2>&1
	- works as planned - abbreviated h/s, correct cert
	- rechecked

- t2: no esni to COVER
	- client connects without ESNI and stores session 
	- client re-connects without ESNI and reuses session 
	- commands:
			$ ./testclient.sh -p 4000 -s localhost -n -c example.com -vd -S t2sess >t2log.first 2>&1
			$ ./testclient.sh -p 4000 -s localhost -n -c example.com -vd -S t2sess >t2log.second 2>&1
	- works as planned - abbreviated h/s, correct cert
	- rechecked

- t3: nomimal ESNI, no cover
	- client connects with ESNI and stores session 
	- client re-connects with same ESNI and reuses session 
	- commands:
			$ ./testclient.sh -p 4000 -s localhost -H foo.example.com -c NONE -vd -P esnikeys.pub -S t3sess >t3log.first 2>&1
			$ ./testclient.sh -p 4000 -s localhost -H foo.example.com -c NONE -vd -P esnikeys.pub -S t3sess >t3log.second 2>&1
	- yay! worked as planned too, 2nd h/s shorter, correct cert
	- rechecked

- t4: nomimal ESNI, with cover
	- client connects with ESNI and stores session 
	- client re-connects with same ESNI and reuses session 
	- commands:
			$ ./testclient.sh -p 4000 -s localhost -H foo.example.com -c example.com -P esnikeys.pub -vd -S t4sess >t4log.first 2>&1
			$ ./testclient.sh -p 4000 -s localhost -H foo.example.com -c example.com -P esnikeys.pub -vd -S t4sess >t4log.second 2>&1
	- yay! worked as planned too, 2nd h/s shorter, correct cert
	- rechecked

- t5: changed ESNI, no cover
	- client connects with ESNI and stores session 
	- client re-connects with different, bogus ESNI and reuses session 
	- commands:
			$ ./testclient.sh -p 4000 -s localhost -H foo.example.com -c NONE -P esnikeys.pub -vd -S t5sess >t5log.first 2>&1
			$ ./testclient.sh -p 4000 -s localhost -H bollox -c NONE -P esnikeys.pub -vd -S t5sess >t5log.second 2>&1
	- worked (unplanned!), 2nd h/s shorter, cert is foo.example.com, no error
	- rechecked
	- FIXME: 2nd case ESNI ("bollox") is sent to server and decrypted fine, but has no effect

- t6: changed ESNI, with cover
	- client connects with ESNI and stores session 
	- client re-connects with different, bogus ESNI and reuses session 
	- commands:
			$ ./testclient.sh -p 4000 -s localhost -H foo.example.com -c example.com -P esnikeys.pub -vd -S t6sess >t6log.first 2>&1
			$ ./testclient.sh -p 4000 -s localhost -H bollox -c example.com -P esnikeys.pub -vd -S t6sess >t6log.second 2>&1
	- h/s shorter, no error which is wrong as names don't match
	- without the resumed session, we do get a client-side generated error, as we should since bollox is not a good ESNI for our server
	  (on the server side in this case, the h/s succeeds but uses the default/cover cert)

- t7: forgot ESNI, without cover
	- client connects with ESNI and stores session 
	- client re-connects without ESNI and reuses session 
	- commands:
			$ ./testclient.sh -p 4000 -s localhost -H foo.example.com -c NONE -P esnikeys.pub -vd -S t7sess >t7log.first 2>&1
			$ ./testclient.sh -p 4000 -s localhost -n -c NONE -vd -S t7sess >t7log.second 2>&1
	- full h/s, cert is example.com (COVER, not HIDDEN)
	- redoing; abbrev. h/s, cert is foo.example.com
	- redoing2; abbrev. h/s, cert is foo.example.com
	- redoing3; abbrev. h/s, cert is foo.example.com
	- maybe error first time 'round? (though I suspect I've seen it before?)
	- could be single-use tickets, which I can test... (nope t7log.third & t7log.fourth are all short h/w)
	- Not sure if this behaviour is correct or not.

- t8: forgot ESNI, with cover
	- client connects with ESNI and stores session 
	- client re-connects without ESNI and reuses session 
	- commands:
			$ ./testclient.sh -p 4000 -s localhost -H foo.example.com -c example.com -P esnikeys.pub -vd -S t8sess >t8log.first 2>&1
			$ ./testclient.sh -p 4000 -s localhost -n -c example.com -vd -S t8sess >t8log.second 2>&1
	- short h/s, cert is foo.example.com

## Wildcard test cases

- t9: 1st request for a.foo.example.com, 2nd for b.foo.example.com
	- client connects with ESNI, no cover, and stores session 
	- client re-connects with different ESNI, but falling below cert, no cover, and reuses session 
	- commands:
			$ ./testclient.sh -p 4000 -s localhost -H a.foo.example.com -c NONE -P esnikeys.pub -vd -S t9sess >t9log.first 2>&1
			$ ./testclient.sh -p 4000 -s localhost -H b.foo.example.com -c NONE -P esnikeys.pub -vd -S t9sess >t9log.second 2>&1
	- 2nd h/s abbreviated, no error deteceted (whcih seems wrong) 

