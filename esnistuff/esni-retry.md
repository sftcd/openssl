
# Handling of ``esni_retry_requested``

Based on draft-04, SF/20190729

## ESNI-aware Client CH handling

- if ESNIKeys - do it
- if no ESNIKeys and thusly configured - do grease 

## Server with ESNIKeys

Hopefully, this'd be the nominal case, where a server can do ESNI

- if ESNI failed syntactically... alert
- if ESNI failed otherwise ... send ESNIKeys
- if ESNI worked send nonce

## Server without ESNIKeys

In this case the server has no ESNIKeys configured 

- If ESNI present, randonly send grease or fake-ESNIKeys ???

## Server not supporting ESNI at all

- Ignores the CH extension

## Client EncryptedExtensions handling

- if CH was greased, ignore
- if ``esni_retry_requested``:
    - if really tried and not timed-out, re-try with new keys
- else 
    - if really tried and nonce check not ok: fail
    - if grease fail

