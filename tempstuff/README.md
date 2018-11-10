
# Place for temp files...

I'll put stuff here that'll likely disappear if this
goes (much) further. So the plan would be to delete
all this before submitting any PR and to move any
related test code etc into the proper openssl test
framework.

For now [esni.c](./esni.c) has (what I think is;-) 
good OPENSSL-style code to decode and print the 
content of a TXT RR as described by the -02 I-D.
If/when doing this for-real, that code would be
distributed in a couple of library bits.
