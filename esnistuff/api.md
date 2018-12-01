# Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`define `[`SSL_ESNI_STATUS_SUCCESS`](#esni_8h_1a6a4d94b18577a453e7ca65273c75b110)            | Success.
`define `[`SSL_ESNI_STATUS_FAILED`](#esni_8h_1aff48e6059acca5bd4a3f9f2a926e9ffd)            | Some internal error.
`define `[`SSL_ESNI_STATUS_BAD_CALL`](#esni_8h_1a182a797bad43060760194c701c882fd0)            | Required in/out arguments were NULL.
`define `[`SSL_ESNI_STATUS_NOT_TRIED`](#esni_8h_1ac754df41295244baf3b951e9cec0a1db)            | ESNI wasn't attempted.
`define `[`SSL_ESNI_STATUS_BAD_NAME`](#esni_8h_1a4019c4a8f415a42a213cc0c657d9986b)            | ESNI succeeded but the TLS server cert used didn't match the hidden service name.
`define `[`ESNI_F_BASE64_DECODE`](#esnierr_8h_1a9c57a1b191c8fc44f0c9d33e1fa63096)            | 
`define `[`ESNI_F_NEW_FROM_BASE64`](#esnierr_8h_1a2292c05f5c24b23849789eb87f20bb0c)            | 
`define `[`ESNI_F_ENC`](#esnierr_8h_1a5e1e464c2d05b71de95e455a341f477f)            | 
`define `[`ESNI_F_CHECKSUM_CHECK`](#esnierr_8h_1ac8cec6cf839fa6b361bc6f9abc001201)            | 
`define `[`ESNI_R_BASE64_DECODE_ERROR`](#esnierr_8h_1a1c13aa91c93bd84f1f92101ddb9bc9eb)            | 
`define `[`ESNI_R_RR_DECODE_ERROR`](#esnierr_8h_1acc748e3e2af6dc12fead035b479c221f)            | 
`define `[`ESNI_R_NOT_IMPL`](#esnierr_8h_1aeb72e4451595e51885c8192c3c06e870)            | 
`public int `[`SSL_esni_checknames`](#esni_8h_1a55aedc0e921fd36dcc3327124f07da10)`(const char * encservername,const char * covername)`            | Make a basic check of names from CLI or API.
`public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_new_from_base64`](#esni_8h_1a672460fc59e13e81482f66c701d4bca7)`(const char * esnikeys)`            | Decode and check the value retieved from DNS (currently base64 encoded)
`public int `[`SSL_esni_enable`](#esni_8h_1a0ca4d48103270d6779cb2f6a608ba52a)`(SSL * s,const char * hidden,const char * cover,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int require_hidden_match)`            | Turn on SNI encryption for an TLS (upcoming) session.
`public int `[`SSL_ESNI_enc`](#esni_8h_1a1059808bc7c121128c470de41e2dc304)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` ** the_esni)`            | Do the client-side SNI encryption during a TLS handshake.
`public void `[`SSL_ESNI_free`](#esni_8h_1a6d6ea1b22339efdc370e6cbf251b277d)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys)`            | Memory management - free an SSL_ESNI.
`public void `[`CLIENT_ESNI_free`](#esni_8h_1a1a84158d3b21a24a5db6bac434a718dc)`(`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` * c)`            | Memory management - free a CLIENT_ESNI.
`public int `[`SSL_ESNI_get_esni`](#esni_8h_1ac214a7933d6e5fa9e2be5218b9537a63)`(SSL * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)`            | Debugging - print an SSL_ESNI structure note - can include sensitive values!
`public int `[`SSL_ESNI_print`](#esni_8h_1acf8aa08880982952d1faee2fedd1bc67)`(BIO * out,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni)`            | Print the content of an SSL_ESNI.
`public int `[`SSL_get_esni_status`](#esni_8h_1abc2468ba57b69ddaca0344481027d7a1)`(SSL * s,char ** hidden,char ** cover)`            | API to allow calling code know ESNI outcome, post-handshake.
`public int `[`SSL_ESNI_set_private`](#esni_8h_1a8df1af022d25fc0f7e72683b0bd4667f)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,char * private_str)`            | Allows caller to set the ECDH private value for ESNI.
`public int `[`SSL_ESNI_set_nonce`](#esni_8h_1a0f48da79909334acee7b24dec440eb4c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,unsigned char * nonce,size_t nlen)`            | Allows caller to set the nonce value for ESNI.
`public int `[`ERR_load_ESNI_strings`](#esnierr_8h_1ab6db8c60b35aacaa03550e6d9d9c2099)`(void)`            | Load strings into tables.
`public int `[`ERR_load_ESNI_strings`](#esni_8c_1ab6db8c60b35aacaa03550e6d9d9c2099)`(void)`            | Load strings into tables.
`public static uint64_t `[`uint64_from_bytes`](#esni_8c_1a83d195ea944e970d225ac1554c88c3d4)`(unsigned char * buf)`            | 
`public static int `[`esni_base64_decode`](#esni_8c_1a64c9d65c28e852557b2ac325335c6a83)`(const char * in,unsigned char ** out)`            | 
`public void `[`ESNI_RECORD_free`](#esni_8c_1a2af97ba7f8ebc58e04391bc845f21811)`(`[`ESNI_RECORD`](#esni_8h_1ab29e08d24d0eac604e0d6783dfbf1758)` * er)`            | 
`public void `[`SSL_ESNI_free`](#esni_8c_1a3a532dc18d8ea55c30b74529946f66c7)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys)`            | Memory management - free an SSL_ESNI.
`public static int `[`esni_checksum_check`](#esni_8c_1a4c8d42c0081cae34740804bb9c4fc88b)`(unsigned char * buf,size_t buf_len)`            | 
`public static unsigned char * `[`esni_make_rd`](#esni_8c_1a1a6df9cdee70887ac4c2492164155e83)`(const unsigned char * buf,const size_t blen,const EVP_MD * md,size_t * rd_len)`            | 
`public static unsigned char * `[`wrap_keyshare`](#esni_8c_1ade5f0e5d16fd7f3dc7e3852f2960804e)`(const unsigned char * keyshare,const size_t keyshare_len,const uint16_t curve_id,size_t * outlen)`            | 
`public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_new_from_base64`](#esni_8c_1a672460fc59e13e81482f66c701d4bca7)`(const char * esnikeys)`            | Decode and check the value retieved from DNS (currently base64 encoded)
`public static void `[`esni_pbuf`](#esni_8c_1ad619d10af828adf65d47682bdab514d1)`(BIO * out,char * msg,unsigned char * buf,size_t blen,int indent)`            | 
`public int `[`SSL_ESNI_print`](#esni_8c_1acf8aa08880982952d1faee2fedd1bc67)`(BIO * out,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni)`            | Print the content of an SSL_ESNI.
`public static unsigned char * `[`esni_nonce`](#esni_8c_1a50f8ca970c2ceb308dbf23fd0410ee3b)`(size_t nl)`            | 
`public static unsigned char * `[`esni_pad`](#esni_8c_1a3e85b60a8ef53ff8670c54af6e376c40)`(char * name,unsigned int padded_len)`            | 
`public static unsigned char * `[`esni_hkdf_extract`](#esni_8c_1a9f76caa6f579de747d413ee3e809650d)`(unsigned char * secret,size_t slen,size_t * olen,const EVP_MD * md)`            | 
`public static unsigned char * `[`esni_hkdf_expand_label`](#esni_8c_1a7dd32376e27d6c6aed533917093639e8)`(unsigned char * Zx,size_t Zx_len,const char * label,unsigned char * hash,size_t hash_len,size_t * expanded_len,const EVP_MD * md)`            | 
`public static unsigned char * `[`esni_aead_enc`](#esni_8c_1a5a36ed03fd4e8a351ed10b1296f3857b)`(unsigned char * key,size_t key_len,unsigned char * iv,size_t iv_len,unsigned char * aad,size_t aad_len,unsigned char * plain,size_t plain_len,unsigned char * tag,size_t tag_len,size_t * cipher_len,const SSL_CIPHER * ciph)`            | 
`public int `[`SSL_ESNI_enc`](#esni_8c_1a1059808bc7c121128c470de41e2dc304)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` ** the_esni)`            | Do the client-side SNI encryption during a TLS handshake.
`public int `[`SSL_esni_checknames`](#esni_8c_1a55aedc0e921fd36dcc3327124f07da10)`(const char * encservername,const char * covername)`            | Make a basic check of names from CLI or API.
`public int `[`SSL_esni_enable`](#esni_8c_1a0ca4d48103270d6779cb2f6a608ba52a)`(SSL * s,const char * hidden,const char * cover,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int require_hidden_match)`            | Turn on SNI encryption for an TLS (upcoming) session.
`public int `[`SSL_get_esni_status`](#esni_8c_1abc2468ba57b69ddaca0344481027d7a1)`(SSL * s,char ** hidden,char ** cover)`            | API to allow calling code know ESNI outcome, post-handshake.
`public void `[`SSL_set_esni_callback`](#esni_8c_1ac4fbad870f00b5b6cb84629c4995be02)`(SSL * s,SSL_esni_client_cb_func f)`            | 
`public int `[`SSL_ESNI_get_esni`](#esni_8c_1ac214a7933d6e5fa9e2be5218b9537a63)`(SSL * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)`            | Get access to the ESNI data from an SSL context (if that's the right term:-)
`public int `[`SSL_ESNI_set_private`](#esni_8c_1a8df1af022d25fc0f7e72683b0bd4667f)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,char * private_str)`            | Allows caller to set the ECDH private value for ESNI.
`public int `[`SSL_ESNI_set_nonce`](#esni_8c_1a0f48da79909334acee7b24dec440eb4c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,unsigned char * nonce,size_t nlen)`            | Allows caller to set the nonce value for ESNI.
`struct `[`client_esni_st`](#structclient__esni__st) | What we send in the esni CH extension:
`struct `[`esni_record_st`](#structesni__record__st) | If defined, this provides enough API, internals and tracing so we can ensure/check we're generating keys the same way as other code, in partocular the existing NSS code.
`struct `[`ssl_esni_st`](#structssl__esni__st) | The ESNI data structure that's part of the SSL structure (Client-only for now really.

## Members

#### `define `[`SSL_ESNI_STATUS_SUCCESS`](#esni_8h_1a6a4d94b18577a453e7ca65273c75b110) {#esni_8h_1a6a4d94b18577a453e7ca65273c75b110}

Success.

#### `define `[`SSL_ESNI_STATUS_FAILED`](#esni_8h_1aff48e6059acca5bd4a3f9f2a926e9ffd) {#esni_8h_1aff48e6059acca5bd4a3f9f2a926e9ffd}

Some internal error.

#### `define `[`SSL_ESNI_STATUS_BAD_CALL`](#esni_8h_1a182a797bad43060760194c701c882fd0) {#esni_8h_1a182a797bad43060760194c701c882fd0}

Required in/out arguments were NULL.

#### `define `[`SSL_ESNI_STATUS_NOT_TRIED`](#esni_8h_1ac754df41295244baf3b951e9cec0a1db) {#esni_8h_1ac754df41295244baf3b951e9cec0a1db}

ESNI wasn't attempted.

#### `define `[`SSL_ESNI_STATUS_BAD_NAME`](#esni_8h_1a4019c4a8f415a42a213cc0c657d9986b) {#esni_8h_1a4019c4a8f415a42a213cc0c657d9986b}

ESNI succeeded but the TLS server cert used didn't match the hidden service name.

#### `define `[`ESNI_F_BASE64_DECODE`](#esnierr_8h_1a9c57a1b191c8fc44f0c9d33e1fa63096) {#esnierr_8h_1a9c57a1b191c8fc44f0c9d33e1fa63096}

#### `define `[`ESNI_F_NEW_FROM_BASE64`](#esnierr_8h_1a2292c05f5c24b23849789eb87f20bb0c) {#esnierr_8h_1a2292c05f5c24b23849789eb87f20bb0c}

#### `define `[`ESNI_F_ENC`](#esnierr_8h_1a5e1e464c2d05b71de95e455a341f477f) {#esnierr_8h_1a5e1e464c2d05b71de95e455a341f477f}

#### `define `[`ESNI_F_CHECKSUM_CHECK`](#esnierr_8h_1ac8cec6cf839fa6b361bc6f9abc001201) {#esnierr_8h_1ac8cec6cf839fa6b361bc6f9abc001201}

#### `define `[`ESNI_R_BASE64_DECODE_ERROR`](#esnierr_8h_1a1c13aa91c93bd84f1f92101ddb9bc9eb) {#esnierr_8h_1a1c13aa91c93bd84f1f92101ddb9bc9eb}

#### `define `[`ESNI_R_RR_DECODE_ERROR`](#esnierr_8h_1acc748e3e2af6dc12fead035b479c221f) {#esnierr_8h_1acc748e3e2af6dc12fead035b479c221f}

#### `define `[`ESNI_R_NOT_IMPL`](#esnierr_8h_1aeb72e4451595e51885c8192c3c06e870) {#esnierr_8h_1aeb72e4451595e51885c8192c3c06e870}

#### `public int `[`SSL_esni_checknames`](#esni_8h_1a55aedc0e921fd36dcc3327124f07da10)`(const char * encservername,const char * covername)` {#esni_8h_1a55aedc0e921fd36dcc3327124f07da10}

Make a basic check of names from CLI or API.

Note: This may disappear as all the checks currently done would result in errors anyway. However, that could change, so we'll keep it for now.

#### Parameters
* `encservername` the hidden servie 

* `convername` the cleartext SNI to send (can be NULL if we don't want any) 

#### Returns
1 for success, other otherwise

#### `public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_new_from_base64`](#esni_8h_1a672460fc59e13e81482f66c701d4bca7)`(const char * esnikeys)` {#esni_8h_1a672460fc59e13e81482f66c701d4bca7}

Decode and check the value retieved from DNS (currently base64 encoded)

#### Parameters
* `esnikeys` is the base64 encoded value from DNS 

#### Returns
is an SSL_ESNI structure

#### `public int `[`SSL_esni_enable`](#esni_8h_1a0ca4d48103270d6779cb2f6a608ba52a)`(SSL * s,const char * hidden,const char * cover,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int require_hidden_match)` {#esni_8h_1a0ca4d48103270d6779cb2f6a608ba52a}

Turn on SNI encryption for an TLS (upcoming) session.

#### Parameters
* `s` is the SSL context 

* `hidde` is the hidden service name 

* `cover` is the cleartext SNI name to use 

* `esni` is the SSL_ESNI structure 

* `require_hidden_match` say whether to require (==1) the TLS server cert matches the hidden name 

#### Returns
1 for success, other otherwise

#### `public int `[`SSL_ESNI_enc`](#esni_8h_1a1059808bc7c121128c470de41e2dc304)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` ** the_esni)` {#esni_8h_1a1059808bc7c121128c470de41e2dc304}

Do the client-side SNI encryption during a TLS handshake.

This is an internal API called as part of the state machine dealing with this extension.

#### Parameters
* `esnikeys` is the SSL_ESNI structure 

* `client_random_len` is the number of bytes of  being the TLS h/s client random 

* `curve_id` is the curve_id of the client keyshare 

* `client_keyshare_len` is the number of bytes of 

* `client_keyshare` is the h/s client keyshare

#### `public void `[`SSL_ESNI_free`](#esni_8h_1a6d6ea1b22339efdc370e6cbf251b277d)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys)` {#esni_8h_1a6d6ea1b22339efdc370e6cbf251b277d}

Memory management - free an SSL_ESNI.

Free everything within an SSL_ESNI. Note that the caller has to free the top level SSL_ESNI, IOW the pattern here is: SSL_ESNI_free(esnikeys); OPENSSL_free(esnikeys);

#### Parameters
* `esnikeys` is an SSL_ESNI structure

#### `public void `[`CLIENT_ESNI_free`](#esni_8h_1a1a84158d3b21a24a5db6bac434a718dc)`(`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` * c)` {#esni_8h_1a1a84158d3b21a24a5db6bac434a718dc}

Memory management - free a CLIENT_ESNI.

This is called from within SSL_ESNI_free so isn't really needed externally at all.

#### Parameters
* `c` is a CLIENT_ESNI structure

#### `public int `[`SSL_ESNI_get_esni`](#esni_8h_1ac214a7933d6e5fa9e2be5218b9537a63)`(SSL * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)` {#esni_8h_1ac214a7933d6e5fa9e2be5218b9537a63}

Debugging - print an SSL_ESNI structure note - can include sensitive values!

Get access to the ESNI data from an SSL context (if that's the right term:-)

#### Parameters
* `out` is a BIO for printing 

* `esni` is an SSL_ESNI structure 

#### Returns
1 for success, anything else for failure

#### Parameters
* `s` the SSL context 

* `esni` the (ptr to) output SSL_ESNI structure 

#### Returns
1 for success, anything else for failure

Debugging - print an SSL_ESNI structure note - can include sensitive values!

#### Parameters
* `s` the SSL context 

* `esni` the (ptr to) output SSL_ESNI structure 

#### Returns
1 for success, anything else for failure

#### `public int `[`SSL_ESNI_print`](#esni_8h_1acf8aa08880982952d1faee2fedd1bc67)`(BIO * out,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni)` {#esni_8h_1acf8aa08880982952d1faee2fedd1bc67}

Print the content of an SSL_ESNI.

#### Parameters
* `out` is the BIO to use (e.g. stdout/whatever)  is an SSL_ESNI strucutre 

#### Returns
1 for success, anything else for failure

#### `public int `[`SSL_get_esni_status`](#esni_8h_1abc2468ba57b69ddaca0344481027d7a1)`(SSL * s,char ** hidden,char ** cover)` {#esni_8h_1abc2468ba57b69ddaca0344481027d7a1}

API to allow calling code know ESNI outcome, post-handshake.

This is intended to be called by applications after the TLS handshake is complete.

#### Parameters
* `s` The SSL context (if that's the right term) 

* `hidden` will be set to the address of the hidden service 

* `cover` will be set to the address of the hidden service 

#### Returns
1 for success, other otherwise

#### `public int `[`SSL_ESNI_set_private`](#esni_8h_1a8df1af022d25fc0f7e72683b0bd4667f)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,char * private_str)` {#esni_8h_1a8df1af022d25fc0f7e72683b0bd4667f}

Allows caller to set the ECDH private value for ESNI.

This is intended to only be used for interop testing - what was useful was to grab the value from the NSS implemtation, force it into mine and see which of the derived values end up the same.

#### Parameters
* `esni` is the SSL_ESNI struture 

* `private_str` is an ASCII-hex encoded X25519 point (essentially a random 32 octet value:-) 

#### Returns
1 for success, other otherwise

#### `public int `[`SSL_ESNI_set_nonce`](#esni_8h_1a0f48da79909334acee7b24dec440eb4c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,unsigned char * nonce,size_t nlen)` {#esni_8h_1a0f48da79909334acee7b24dec440eb4c}

Allows caller to set the nonce value for ESNI.

This is intended to only be used for interop testing - what was useful was to grab the value from the NSS implemtation, force it into mine and see which of the derived values end up the same.

#### Parameters
* `esni` is the SSL_ESNI struture 

* `nonce` points to a buffer with the network byte order value  nlen is the size of the nonce buffer 

#### Returns
1 for success, other otherwise

#### `public int `[`ERR_load_ESNI_strings`](#esnierr_8h_1ab6db8c60b35aacaa03550e6d9d9c2099)`(void)` {#esnierr_8h_1ab6db8c60b35aacaa03550e6d9d9c2099}

Load strings into tables.

Who the hell calls this?

#### `public int `[`ERR_load_ESNI_strings`](#esni_8c_1ab6db8c60b35aacaa03550e6d9d9c2099)`(void)` {#esni_8c_1ab6db8c60b35aacaa03550e6d9d9c2099}

Load strings into tables.

Who the hell calls this?

#### `public static uint64_t `[`uint64_from_bytes`](#esni_8c_1a83d195ea944e970d225ac1554c88c3d4)`(unsigned char * buf)` {#esni_8c_1a83d195ea944e970d225ac1554c88c3d4}

#### `public static int `[`esni_base64_decode`](#esni_8c_1a64c9d65c28e852557b2ac325335c6a83)`(const char * in,unsigned char ** out)` {#esni_8c_1a64c9d65c28e852557b2ac325335c6a83}

#### `public void `[`ESNI_RECORD_free`](#esni_8c_1a2af97ba7f8ebc58e04391bc845f21811)`(`[`ESNI_RECORD`](#esni_8h_1ab29e08d24d0eac604e0d6783dfbf1758)` * er)` {#esni_8c_1a2af97ba7f8ebc58e04391bc845f21811}

#### `public void `[`SSL_ESNI_free`](#esni_8c_1a3a532dc18d8ea55c30b74529946f66c7)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys)` {#esni_8c_1a3a532dc18d8ea55c30b74529946f66c7}

Memory management - free an SSL_ESNI.

Free everything within an SSL_ESNI. Note that the caller has to free the top level SSL_ESNI, IOW the pattern here is: SSL_ESNI_free(esnikeys); OPENSSL_free(esnikeys);

#### Parameters
* `esnikeys` is an SSL_ESNI structure

#### `public static int `[`esni_checksum_check`](#esni_8c_1a4c8d42c0081cae34740804bb9c4fc88b)`(unsigned char * buf,size_t buf_len)` {#esni_8c_1a4c8d42c0081cae34740804bb9c4fc88b}

#### `public static unsigned char * `[`esni_make_rd`](#esni_8c_1a1a6df9cdee70887ac4c2492164155e83)`(const unsigned char * buf,const size_t blen,const EVP_MD * md,size_t * rd_len)` {#esni_8c_1a1a6df9cdee70887ac4c2492164155e83}

#### `public static unsigned char * `[`wrap_keyshare`](#esni_8c_1ade5f0e5d16fd7f3dc7e3852f2960804e)`(const unsigned char * keyshare,const size_t keyshare_len,const uint16_t curve_id,size_t * outlen)` {#esni_8c_1ade5f0e5d16fd7f3dc7e3852f2960804e}

#### `public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_new_from_base64`](#esni_8c_1a672460fc59e13e81482f66c701d4bca7)`(const char * esnikeys)` {#esni_8c_1a672460fc59e13e81482f66c701d4bca7}

Decode and check the value retieved from DNS (currently base64 encoded)

#### Parameters
* `esnikeys` is the base64 encoded value from DNS 

#### Returns
is an SSL_ESNI structure

#### `public static void `[`esni_pbuf`](#esni_8c_1ad619d10af828adf65d47682bdab514d1)`(BIO * out,char * msg,unsigned char * buf,size_t blen,int indent)` {#esni_8c_1ad619d10af828adf65d47682bdab514d1}

#### `public int `[`SSL_ESNI_print`](#esni_8c_1acf8aa08880982952d1faee2fedd1bc67)`(BIO * out,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni)` {#esni_8c_1acf8aa08880982952d1faee2fedd1bc67}

Print the content of an SSL_ESNI.

#### Parameters
* `out` is the BIO to use (e.g. stdout/whatever)  is an SSL_ESNI strucutre 

#### Returns
1 for success, anything else for failure

#### `public static unsigned char * `[`esni_nonce`](#esni_8c_1a50f8ca970c2ceb308dbf23fd0410ee3b)`(size_t nl)` {#esni_8c_1a50f8ca970c2ceb308dbf23fd0410ee3b}

#### `public static unsigned char * `[`esni_pad`](#esni_8c_1a3e85b60a8ef53ff8670c54af6e376c40)`(char * name,unsigned int padded_len)` {#esni_8c_1a3e85b60a8ef53ff8670c54af6e376c40}

#### `public static unsigned char * `[`esni_hkdf_extract`](#esni_8c_1a9f76caa6f579de747d413ee3e809650d)`(unsigned char * secret,size_t slen,size_t * olen,const EVP_MD * md)` {#esni_8c_1a9f76caa6f579de747d413ee3e809650d}

#### `public static unsigned char * `[`esni_hkdf_expand_label`](#esni_8c_1a7dd32376e27d6c6aed533917093639e8)`(unsigned char * Zx,size_t Zx_len,const char * label,unsigned char * hash,size_t hash_len,size_t * expanded_len,const EVP_MD * md)` {#esni_8c_1a7dd32376e27d6c6aed533917093639e8}

#### `public static unsigned char * `[`esni_aead_enc`](#esni_8c_1a5a36ed03fd4e8a351ed10b1296f3857b)`(unsigned char * key,size_t key_len,unsigned char * iv,size_t iv_len,unsigned char * aad,size_t aad_len,unsigned char * plain,size_t plain_len,unsigned char * tag,size_t tag_len,size_t * cipher_len,const SSL_CIPHER * ciph)` {#esni_8c_1a5a36ed03fd4e8a351ed10b1296f3857b}

#### `public int `[`SSL_ESNI_enc`](#esni_8c_1a1059808bc7c121128c470de41e2dc304)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` ** the_esni)` {#esni_8c_1a1059808bc7c121128c470de41e2dc304}

Do the client-side SNI encryption during a TLS handshake.

This is an internal API called as part of the state machine dealing with this extension.

#### Parameters
* `esnikeys` is the SSL_ESNI structure 

* `client_random_len` is the number of bytes of  being the TLS h/s client random 

* `curve_id` is the curve_id of the client keyshare 

* `client_keyshare_len` is the number of bytes of 

* `client_keyshare` is the h/s client keyshare

#### `public int `[`SSL_esni_checknames`](#esni_8c_1a55aedc0e921fd36dcc3327124f07da10)`(const char * encservername,const char * covername)` {#esni_8c_1a55aedc0e921fd36dcc3327124f07da10}

Make a basic check of names from CLI or API.

Note: This may disappear as all the checks currently done would result in errors anyway. However, that could change, so we'll keep it for now.

#### Parameters
* `encservername` the hidden servie 

* `convername` the cleartext SNI to send (can be NULL if we don't want any) 

#### Returns
1 for success, other otherwise

#### `public int `[`SSL_esni_enable`](#esni_8c_1a0ca4d48103270d6779cb2f6a608ba52a)`(SSL * s,const char * hidden,const char * cover,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int require_hidden_match)` {#esni_8c_1a0ca4d48103270d6779cb2f6a608ba52a}

Turn on SNI encryption for an TLS (upcoming) session.

#### Parameters
* `s` is the SSL context 

* `hidde` is the hidden service name 

* `cover` is the cleartext SNI name to use 

* `esni` is the SSL_ESNI structure 

* `require_hidden_match` say whether to require (==1) the TLS server cert matches the hidden name 

#### Returns
1 for success, other otherwise

#### `public int `[`SSL_get_esni_status`](#esni_8c_1abc2468ba57b69ddaca0344481027d7a1)`(SSL * s,char ** hidden,char ** cover)` {#esni_8c_1abc2468ba57b69ddaca0344481027d7a1}

API to allow calling code know ESNI outcome, post-handshake.

This is intended to be called by applications after the TLS handshake is complete.

#### Parameters
* `s` The SSL context (if that's the right term) 

* `hidden` will be set to the address of the hidden service 

* `cover` will be set to the address of the hidden service 

#### Returns
1 for success, other otherwise

#### `public void `[`SSL_set_esni_callback`](#esni_8c_1ac4fbad870f00b5b6cb84629c4995be02)`(SSL * s,SSL_esni_client_cb_func f)` {#esni_8c_1ac4fbad870f00b5b6cb84629c4995be02}

#### `public int `[`SSL_ESNI_get_esni`](#esni_8c_1ac214a7933d6e5fa9e2be5218b9537a63)`(SSL * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)` {#esni_8c_1ac214a7933d6e5fa9e2be5218b9537a63}

Get access to the ESNI data from an SSL context (if that's the right term:-)

Debugging - print an SSL_ESNI structure note - can include sensitive values!

#### Parameters
* `s` the SSL context 

* `esni` the (ptr to) output SSL_ESNI structure 

#### Returns
1 for success, anything else for failure

#### `public int `[`SSL_ESNI_set_private`](#esni_8c_1a8df1af022d25fc0f7e72683b0bd4667f)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,char * private_str)` {#esni_8c_1a8df1af022d25fc0f7e72683b0bd4667f}

Allows caller to set the ECDH private value for ESNI.

This is intended to only be used for interop testing - what was useful was to grab the value from the NSS implemtation, force it into mine and see which of the derived values end up the same.

#### Parameters
* `esni` is the SSL_ESNI struture 

* `private_str` is an ASCII-hex encoded X25519 point (essentially a random 32 octet value:-) 

#### Returns
1 for success, other otherwise

#### `public int `[`SSL_ESNI_set_nonce`](#esni_8c_1a0f48da79909334acee7b24dec440eb4c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,unsigned char * nonce,size_t nlen)` {#esni_8c_1a0f48da79909334acee7b24dec440eb4c}

Allows caller to set the nonce value for ESNI.

This is intended to only be used for interop testing - what was useful was to grab the value from the NSS implemtation, force it into mine and see which of the derived values end up the same.

#### Parameters
* `esni` is the SSL_ESNI struture 

* `nonce` points to a buffer with the network byte order value  nlen is the size of the nonce buffer 

#### Returns
1 for success, other otherwise

# struct `client_esni_st` {#structclient__esni__st}

What we send in the esni CH extension:

The TLS presentation language version is: struct { CipherSuite suite; KeyShareEntry key_share; opaque record_digest<0..2^16-1>; opaque encrypted_sni<0..2^16-1>; } ClientEncryptedSNI;

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public const SSL_CIPHER * `[`ciphersuite`](#structclient__esni__st_1a7878b09e8518b555bc5de7e0cc0a680d) | 
`public size_t `[`encoded_keyshare_len`](#structclient__esni__st_1a5647ef9466b0de060a8fdbadeab16ca9) | 
`public unsigned char * `[`encoded_keyshare`](#structclient__esni__st_1ada7c87c8765f080c25255c336c8f3dd8) | 
`public size_t `[`record_digest_len`](#structclient__esni__st_1ab975fc71e1200e4e15462149377ea18c) | 
`public unsigned char * `[`record_digest`](#structclient__esni__st_1af3490c8abb917246296c8c7ce51106c3) | 
`public size_t `[`encrypted_sni_len`](#structclient__esni__st_1ae2811613d6126039a546db956858db5c) | 
`public unsigned char * `[`encrypted_sni`](#structclient__esni__st_1aafe13f76c23f8743e110c116eaaed174) | 

## Members

#### `public const SSL_CIPHER * `[`ciphersuite`](#structclient__esni__st_1a7878b09e8518b555bc5de7e0cc0a680d) {#structclient__esni__st_1a7878b09e8518b555bc5de7e0cc0a680d}

#### `public size_t `[`encoded_keyshare_len`](#structclient__esni__st_1a5647ef9466b0de060a8fdbadeab16ca9) {#structclient__esni__st_1a5647ef9466b0de060a8fdbadeab16ca9}

#### `public unsigned char * `[`encoded_keyshare`](#structclient__esni__st_1ada7c87c8765f080c25255c336c8f3dd8) {#structclient__esni__st_1ada7c87c8765f080c25255c336c8f3dd8}

#### `public size_t `[`record_digest_len`](#structclient__esni__st_1ab975fc71e1200e4e15462149377ea18c) {#structclient__esni__st_1ab975fc71e1200e4e15462149377ea18c}

#### `public unsigned char * `[`record_digest`](#structclient__esni__st_1af3490c8abb917246296c8c7ce51106c3) {#structclient__esni__st_1af3490c8abb917246296c8c7ce51106c3}

#### `public size_t `[`encrypted_sni_len`](#structclient__esni__st_1ae2811613d6126039a546db956858db5c) {#structclient__esni__st_1ae2811613d6126039a546db956858db5c}

#### `public unsigned char * `[`encrypted_sni`](#structclient__esni__st_1aafe13f76c23f8743e110c116eaaed174) {#structclient__esni__st_1aafe13f76c23f8743e110c116eaaed174}

# struct `esni_record_st` {#structesni__record__st}

If defined, this provides enough API, internals and tracing so we can ensure/check we're generating keys the same way as other code, in partocular the existing NSS code.

TODO: use this to protect the cryptovars are only needed for tracing representation of what goes in DNS

This is from the -02 I-D, what we find in DNS: struct { uint16 version; uint8 checksum[4]; KeyShareEntry keys<4..2^16-1>; CipherSuite cipher_suites<2..2^16-2>; uint16 padded_length; uint64 not_before; uint64 not_after; Extension extensions<0..2^16-1>; } ESNIKeys;

Note that I don't like the above, but it's what we have to work with at the moment.

This structure is purely used when decoding the RR value and is then discarded (selected values mapped into the SSL_ESNI structure).

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public unsigned int `[`version`](#structesni__record__st_1aa3c5b36b02f8154f6ced8a36f04d25c3) | 
`public unsigned char `[`checksum`](#structesni__record__st_1a2280cfc2817e94b494a3e120a44c82b3) | 
`public unsigned int `[`nkeys`](#structesni__record__st_1a128d54ebb6abfe2494da42b5706795d3) | 
`public uint16_t * `[`group_ids`](#structesni__record__st_1a323df5cbace94f73e1bbf922fb3cf64d) | 
`public EVP_PKEY ** `[`keys`](#structesni__record__st_1abc46d13be54f79110778946df8defbc6) | 
`public size_t * `[`encoded_lens`](#structesni__record__st_1ac6ab8f5ea17c69c4bd4bf51be55e30d3) | 
`public unsigned char ** `[`encoded_keys`](#structesni__record__st_1abe59c6e8bf0ff07cb3e4f185fabe1b07) | 
`public unsigned int `[`padded_length`](#structesni__record__st_1a4fa1f10a8635d5dfed501815f928570d) | 
`public uint64_t `[`not_before`](#structesni__record__st_1a4db76296d4da4dd2c202ced371859a29) | 
`public uint64_t `[`not_after`](#structesni__record__st_1ae9ee01b4d38d36242d8f4300d98416e9) | 
`public unsigned int `[`nexts`](#structesni__record__st_1ad0ae17a1a37af37fae9d8a70ea74a996) | 
`public unsigned int * `[`exttypes`](#structesni__record__st_1a12b5bdb880a6b035a62a62e297809ad0) | 
`public void ** `[`exts`](#structesni__record__st_1af8d605ba06bf8043967269ac36aff7c8) | 
`public  `[`STACK_OF`](#structesni__record__st_1ad903ec0a3fd758c79fd168f2ddf3bb41)`(SSL_CIPHER)` | 

## Members

#### `public unsigned int `[`version`](#structesni__record__st_1aa3c5b36b02f8154f6ced8a36f04d25c3) {#structesni__record__st_1aa3c5b36b02f8154f6ced8a36f04d25c3}

#### `public unsigned char `[`checksum`](#structesni__record__st_1a2280cfc2817e94b494a3e120a44c82b3) {#structesni__record__st_1a2280cfc2817e94b494a3e120a44c82b3}

#### `public unsigned int `[`nkeys`](#structesni__record__st_1a128d54ebb6abfe2494da42b5706795d3) {#structesni__record__st_1a128d54ebb6abfe2494da42b5706795d3}

#### `public uint16_t * `[`group_ids`](#structesni__record__st_1a323df5cbace94f73e1bbf922fb3cf64d) {#structesni__record__st_1a323df5cbace94f73e1bbf922fb3cf64d}

#### `public EVP_PKEY ** `[`keys`](#structesni__record__st_1abc46d13be54f79110778946df8defbc6) {#structesni__record__st_1abc46d13be54f79110778946df8defbc6}

#### `public size_t * `[`encoded_lens`](#structesni__record__st_1ac6ab8f5ea17c69c4bd4bf51be55e30d3) {#structesni__record__st_1ac6ab8f5ea17c69c4bd4bf51be55e30d3}

#### `public unsigned char ** `[`encoded_keys`](#structesni__record__st_1abe59c6e8bf0ff07cb3e4f185fabe1b07) {#structesni__record__st_1abe59c6e8bf0ff07cb3e4f185fabe1b07}

#### `public unsigned int `[`padded_length`](#structesni__record__st_1a4fa1f10a8635d5dfed501815f928570d) {#structesni__record__st_1a4fa1f10a8635d5dfed501815f928570d}

#### `public uint64_t `[`not_before`](#structesni__record__st_1a4db76296d4da4dd2c202ced371859a29) {#structesni__record__st_1a4db76296d4da4dd2c202ced371859a29}

#### `public uint64_t `[`not_after`](#structesni__record__st_1ae9ee01b4d38d36242d8f4300d98416e9) {#structesni__record__st_1ae9ee01b4d38d36242d8f4300d98416e9}

#### `public unsigned int `[`nexts`](#structesni__record__st_1ad0ae17a1a37af37fae9d8a70ea74a996) {#structesni__record__st_1ad0ae17a1a37af37fae9d8a70ea74a996}

#### `public unsigned int * `[`exttypes`](#structesni__record__st_1a12b5bdb880a6b035a62a62e297809ad0) {#structesni__record__st_1a12b5bdb880a6b035a62a62e297809ad0}

#### `public void ** `[`exts`](#structesni__record__st_1af8d605ba06bf8043967269ac36aff7c8) {#structesni__record__st_1af8d605ba06bf8043967269ac36aff7c8}

#### `public  `[`STACK_OF`](#structesni__record__st_1ad903ec0a3fd758c79fd168f2ddf3bb41)`(SSL_CIPHER)` {#structesni__record__st_1ad903ec0a3fd758c79fd168f2ddf3bb41}

# struct `ssl_esni_st` {#structssl__esni__st}

The ESNI data structure that's part of the SSL structure (Client-only for now really.

Server is TBD.)

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public char * `[`encservername`](#structssl__esni__st_1a2468815c9c565e18fd3c3bbe8deb5ac9) | 
`public char * `[`covername`](#structssl__esni__st_1a97b71311959fbdb7cd424106c9e2afab) | 
`public int `[`require_hidden_match`](#structssl__esni__st_1a37524b2d52a46fa9df7193a2efcae39c) | 
`public size_t `[`encoded_rr_len`](#structssl__esni__st_1a27ada5b21000aeb74ca5ed8e76bca329) | 
`public unsigned char * `[`encoded_rr`](#structssl__esni__st_1a71c8c509c7d198e8a719c65f99137f42) | 
`public size_t `[`rd_len`](#structssl__esni__st_1a14dda82e4a3ff57fe2dc856e67a2c971) | 
`public unsigned char * `[`rd`](#structssl__esni__st_1a40750765b83b53e6b12c24d580dc6894) | 
`public const SSL_CIPHER * `[`ciphersuite`](#structssl__esni__st_1a70181a0186aecc742d224c04c3070f39) | 
`public uint16_t `[`group_id`](#structssl__esni__st_1ac47e519775c29bd9129eba95cbed25f9) | 
`public size_t `[`esni_server_keyshare_len`](#structssl__esni__st_1acaf7fdcb02985218a99cfe942b429f93) | 
`public unsigned char * `[`esni_server_keyshare`](#structssl__esni__st_1a01d28bcfc48b5652fc6ccc31f5cf2981) | 
`public EVP_PKEY * `[`esni_server_pkey`](#structssl__esni__st_1a10402a2307b7dd624e7b2984c78ad8d3) | 
`public size_t `[`padded_length`](#structssl__esni__st_1adf84b36cfa57d84629cac876c5330ba8) | 
`public uint64_t `[`not_before`](#structssl__esni__st_1a4cb0d34f50b80a38964af87c544f7ce9) | 
`public uint64_t `[`not_after`](#structssl__esni__st_1ac6d2a892f59c287cc6ee7aa35f23c593) | 
`public int `[`nexts`](#structssl__esni__st_1ad378e22df57746ad53996b3557ad8b84) | 
`public void ** `[`exts`](#structssl__esni__st_1a6a0a42a24377c80cb1d1d614e770df18) | 
`public size_t `[`nonce_len`](#structssl__esni__st_1aa3e7c7adffc576490b12cb397398e9e4) | 
`public unsigned char * `[`nonce`](#structssl__esni__st_1a1b1a621faf0c5661d399f74a15f53ff4) | 
`public size_t `[`hs_cr_len`](#structssl__esni__st_1a60c77ce40536a46dd82d534e305c841d) | 
`public unsigned char * `[`hs_cr`](#structssl__esni__st_1a41cc4a76f8c5791c2d56cda576f99b2e) | 
`public size_t `[`hs_kse_len`](#structssl__esni__st_1aaa28d8aae330ffb7d54690362dbbd099) | 
`public unsigned char * `[`hs_kse`](#structssl__esni__st_1ace5b1a36ef299d60894e6c12fb87efa8) | 
`public EVP_PKEY * `[`keyshare`](#structssl__esni__st_1a26fe847e4d6ef31e052388db50ea6dfe) | 
`public size_t `[`encoded_keyshare_len`](#structssl__esni__st_1a996ba562dc4023f24f5f7b9e06cf7ea9) | 
`public unsigned char * `[`encoded_keyshare`](#structssl__esni__st_1a4d01bbfec69faa47688893bf97c3d517) | 
`public size_t `[`hi_len`](#structssl__esni__st_1a736fa2d396148e03dda2b6f16bf2f2b3) | 
`public unsigned char * `[`hi`](#structssl__esni__st_1a4a90ef99a66189196461a24be3228e88) | 
`public size_t `[`hash_len`](#structssl__esni__st_1adc8cd5f2e038050f8f8c943ce83a69e7) | 
`public unsigned char * `[`hash`](#structssl__esni__st_1a13aa60c6ec57e21c72f3ad9a08501de0) | 
`public size_t `[`Z_len`](#structssl__esni__st_1a7481a2e9fa19146dc73daa985ab48299) | 
`public unsigned char * `[`Z`](#structssl__esni__st_1a34834976fb049c9648199f4d5d30ce5a) | 
`public size_t `[`Zx_len`](#structssl__esni__st_1a32851db584691fef7515514c3633cd10) | 
`public unsigned char * `[`Zx`](#structssl__esni__st_1a0e7f1692a4a10d5f4379ba416dfc8f9b) | 
`public size_t `[`key_len`](#structssl__esni__st_1a2ba57f56ad092ad7aa99d1bf13c7ba4f) | 
`public unsigned char * `[`key`](#structssl__esni__st_1a82a0329090f1e41c1f194b965649c578) | 
`public size_t `[`iv_len`](#structssl__esni__st_1a860a6a8162ff52d946e501f70cb8cab3) | 
`public unsigned char * `[`iv`](#structssl__esni__st_1a68620bc395b1faeefd4ff616c987a762) | 
`public size_t `[`aad_len`](#structssl__esni__st_1a3293081d097ffe98ee954fad33da1527) | 
`public unsigned char * `[`aad`](#structssl__esni__st_1a047ff937dc8738a348c38a1430d2a748) | 
`public size_t `[`plain_len`](#structssl__esni__st_1a16cf3490d5e685f020d4b0dfebae20b4) | 
`public unsigned char * `[`plain`](#structssl__esni__st_1a8138dff60c8e4b4aefa3fca687071c72) | 
`public size_t `[`cipher_len`](#structssl__esni__st_1ad8cff17bc628d23a8f07f222faea037b) | 
`public unsigned char * `[`cipher`](#structssl__esni__st_1a19d1bfe34738bd14d62c5f98d25ed9d8) | 
`public size_t `[`tag_len`](#structssl__esni__st_1a422257e7b151614e7873443572e380af) | 
`public unsigned char * `[`tag`](#structssl__esni__st_1ae12ddfc5fb31d43b68c9febca9730e94) | 
`public size_t `[`realSNI_len`](#structssl__esni__st_1a6908a094db5191657c7215fc53c07cac) | 
`public unsigned char * `[`realSNI`](#structssl__esni__st_1a13b4a4088c85d54354a4d0b762b6ecf1) | 
`public `[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` * `[`the_esni`](#structssl__esni__st_1acc1e4d390a3f6fc96c52a10cac4fd6c1) | 
`public  `[`STACK_OF`](#structssl__esni__st_1a50e1e3bc7a1318ab8624021ea50374cb)`(SSL_CIPHER)` | 

## Members

#### `public char * `[`encservername`](#structssl__esni__st_1a2468815c9c565e18fd3c3bbe8deb5ac9) {#structssl__esni__st_1a2468815c9c565e18fd3c3bbe8deb5ac9}

#### `public char * `[`covername`](#structssl__esni__st_1a97b71311959fbdb7cd424106c9e2afab) {#structssl__esni__st_1a97b71311959fbdb7cd424106c9e2afab}

#### `public int `[`require_hidden_match`](#structssl__esni__st_1a37524b2d52a46fa9df7193a2efcae39c) {#structssl__esni__st_1a37524b2d52a46fa9df7193a2efcae39c}

#### `public size_t `[`encoded_rr_len`](#structssl__esni__st_1a27ada5b21000aeb74ca5ed8e76bca329) {#structssl__esni__st_1a27ada5b21000aeb74ca5ed8e76bca329}

#### `public unsigned char * `[`encoded_rr`](#structssl__esni__st_1a71c8c509c7d198e8a719c65f99137f42) {#structssl__esni__st_1a71c8c509c7d198e8a719c65f99137f42}

#### `public size_t `[`rd_len`](#structssl__esni__st_1a14dda82e4a3ff57fe2dc856e67a2c971) {#structssl__esni__st_1a14dda82e4a3ff57fe2dc856e67a2c971}

#### `public unsigned char * `[`rd`](#structssl__esni__st_1a40750765b83b53e6b12c24d580dc6894) {#structssl__esni__st_1a40750765b83b53e6b12c24d580dc6894}

#### `public const SSL_CIPHER * `[`ciphersuite`](#structssl__esni__st_1a70181a0186aecc742d224c04c3070f39) {#structssl__esni__st_1a70181a0186aecc742d224c04c3070f39}

#### `public uint16_t `[`group_id`](#structssl__esni__st_1ac47e519775c29bd9129eba95cbed25f9) {#structssl__esni__st_1ac47e519775c29bd9129eba95cbed25f9}

#### `public size_t `[`esni_server_keyshare_len`](#structssl__esni__st_1acaf7fdcb02985218a99cfe942b429f93) {#structssl__esni__st_1acaf7fdcb02985218a99cfe942b429f93}

#### `public unsigned char * `[`esni_server_keyshare`](#structssl__esni__st_1a01d28bcfc48b5652fc6ccc31f5cf2981) {#structssl__esni__st_1a01d28bcfc48b5652fc6ccc31f5cf2981}

#### `public EVP_PKEY * `[`esni_server_pkey`](#structssl__esni__st_1a10402a2307b7dd624e7b2984c78ad8d3) {#structssl__esni__st_1a10402a2307b7dd624e7b2984c78ad8d3}

#### `public size_t `[`padded_length`](#structssl__esni__st_1adf84b36cfa57d84629cac876c5330ba8) {#structssl__esni__st_1adf84b36cfa57d84629cac876c5330ba8}

#### `public uint64_t `[`not_before`](#structssl__esni__st_1a4cb0d34f50b80a38964af87c544f7ce9) {#structssl__esni__st_1a4cb0d34f50b80a38964af87c544f7ce9}

#### `public uint64_t `[`not_after`](#structssl__esni__st_1ac6d2a892f59c287cc6ee7aa35f23c593) {#structssl__esni__st_1ac6d2a892f59c287cc6ee7aa35f23c593}

#### `public int `[`nexts`](#structssl__esni__st_1ad378e22df57746ad53996b3557ad8b84) {#structssl__esni__st_1ad378e22df57746ad53996b3557ad8b84}

#### `public void ** `[`exts`](#structssl__esni__st_1a6a0a42a24377c80cb1d1d614e770df18) {#structssl__esni__st_1a6a0a42a24377c80cb1d1d614e770df18}

#### `public size_t `[`nonce_len`](#structssl__esni__st_1aa3e7c7adffc576490b12cb397398e9e4) {#structssl__esni__st_1aa3e7c7adffc576490b12cb397398e9e4}

#### `public unsigned char * `[`nonce`](#structssl__esni__st_1a1b1a621faf0c5661d399f74a15f53ff4) {#structssl__esni__st_1a1b1a621faf0c5661d399f74a15f53ff4}

#### `public size_t `[`hs_cr_len`](#structssl__esni__st_1a60c77ce40536a46dd82d534e305c841d) {#structssl__esni__st_1a60c77ce40536a46dd82d534e305c841d}

#### `public unsigned char * `[`hs_cr`](#structssl__esni__st_1a41cc4a76f8c5791c2d56cda576f99b2e) {#structssl__esni__st_1a41cc4a76f8c5791c2d56cda576f99b2e}

#### `public size_t `[`hs_kse_len`](#structssl__esni__st_1aaa28d8aae330ffb7d54690362dbbd099) {#structssl__esni__st_1aaa28d8aae330ffb7d54690362dbbd099}

#### `public unsigned char * `[`hs_kse`](#structssl__esni__st_1ace5b1a36ef299d60894e6c12fb87efa8) {#structssl__esni__st_1ace5b1a36ef299d60894e6c12fb87efa8}

#### `public EVP_PKEY * `[`keyshare`](#structssl__esni__st_1a26fe847e4d6ef31e052388db50ea6dfe) {#structssl__esni__st_1a26fe847e4d6ef31e052388db50ea6dfe}

#### `public size_t `[`encoded_keyshare_len`](#structssl__esni__st_1a996ba562dc4023f24f5f7b9e06cf7ea9) {#structssl__esni__st_1a996ba562dc4023f24f5f7b9e06cf7ea9}

#### `public unsigned char * `[`encoded_keyshare`](#structssl__esni__st_1a4d01bbfec69faa47688893bf97c3d517) {#structssl__esni__st_1a4d01bbfec69faa47688893bf97c3d517}

#### `public size_t `[`hi_len`](#structssl__esni__st_1a736fa2d396148e03dda2b6f16bf2f2b3) {#structssl__esni__st_1a736fa2d396148e03dda2b6f16bf2f2b3}

#### `public unsigned char * `[`hi`](#structssl__esni__st_1a4a90ef99a66189196461a24be3228e88) {#structssl__esni__st_1a4a90ef99a66189196461a24be3228e88}

#### `public size_t `[`hash_len`](#structssl__esni__st_1adc8cd5f2e038050f8f8c943ce83a69e7) {#structssl__esni__st_1adc8cd5f2e038050f8f8c943ce83a69e7}

#### `public unsigned char * `[`hash`](#structssl__esni__st_1a13aa60c6ec57e21c72f3ad9a08501de0) {#structssl__esni__st_1a13aa60c6ec57e21c72f3ad9a08501de0}

#### `public size_t `[`Z_len`](#structssl__esni__st_1a7481a2e9fa19146dc73daa985ab48299) {#structssl__esni__st_1a7481a2e9fa19146dc73daa985ab48299}

#### `public unsigned char * `[`Z`](#structssl__esni__st_1a34834976fb049c9648199f4d5d30ce5a) {#structssl__esni__st_1a34834976fb049c9648199f4d5d30ce5a}

#### `public size_t `[`Zx_len`](#structssl__esni__st_1a32851db584691fef7515514c3633cd10) {#structssl__esni__st_1a32851db584691fef7515514c3633cd10}

#### `public unsigned char * `[`Zx`](#structssl__esni__st_1a0e7f1692a4a10d5f4379ba416dfc8f9b) {#structssl__esni__st_1a0e7f1692a4a10d5f4379ba416dfc8f9b}

#### `public size_t `[`key_len`](#structssl__esni__st_1a2ba57f56ad092ad7aa99d1bf13c7ba4f) {#structssl__esni__st_1a2ba57f56ad092ad7aa99d1bf13c7ba4f}

#### `public unsigned char * `[`key`](#structssl__esni__st_1a82a0329090f1e41c1f194b965649c578) {#structssl__esni__st_1a82a0329090f1e41c1f194b965649c578}

#### `public size_t `[`iv_len`](#structssl__esni__st_1a860a6a8162ff52d946e501f70cb8cab3) {#structssl__esni__st_1a860a6a8162ff52d946e501f70cb8cab3}

#### `public unsigned char * `[`iv`](#structssl__esni__st_1a68620bc395b1faeefd4ff616c987a762) {#structssl__esni__st_1a68620bc395b1faeefd4ff616c987a762}

#### `public size_t `[`aad_len`](#structssl__esni__st_1a3293081d097ffe98ee954fad33da1527) {#structssl__esni__st_1a3293081d097ffe98ee954fad33da1527}

#### `public unsigned char * `[`aad`](#structssl__esni__st_1a047ff937dc8738a348c38a1430d2a748) {#structssl__esni__st_1a047ff937dc8738a348c38a1430d2a748}

#### `public size_t `[`plain_len`](#structssl__esni__st_1a16cf3490d5e685f020d4b0dfebae20b4) {#structssl__esni__st_1a16cf3490d5e685f020d4b0dfebae20b4}

#### `public unsigned char * `[`plain`](#structssl__esni__st_1a8138dff60c8e4b4aefa3fca687071c72) {#structssl__esni__st_1a8138dff60c8e4b4aefa3fca687071c72}

#### `public size_t `[`cipher_len`](#structssl__esni__st_1ad8cff17bc628d23a8f07f222faea037b) {#structssl__esni__st_1ad8cff17bc628d23a8f07f222faea037b}

#### `public unsigned char * `[`cipher`](#structssl__esni__st_1a19d1bfe34738bd14d62c5f98d25ed9d8) {#structssl__esni__st_1a19d1bfe34738bd14d62c5f98d25ed9d8}

#### `public size_t `[`tag_len`](#structssl__esni__st_1a422257e7b151614e7873443572e380af) {#structssl__esni__st_1a422257e7b151614e7873443572e380af}

#### `public unsigned char * `[`tag`](#structssl__esni__st_1ae12ddfc5fb31d43b68c9febca9730e94) {#structssl__esni__st_1ae12ddfc5fb31d43b68c9febca9730e94}

#### `public size_t `[`realSNI_len`](#structssl__esni__st_1a6908a094db5191657c7215fc53c07cac) {#structssl__esni__st_1a6908a094db5191657c7215fc53c07cac}

#### `public unsigned char * `[`realSNI`](#structssl__esni__st_1a13b4a4088c85d54354a4d0b762b6ecf1) {#structssl__esni__st_1a13b4a4088c85d54354a4d0b762b6ecf1}

#### `public `[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` * `[`the_esni`](#structssl__esni__st_1acc1e4d390a3f6fc96c52a10cac4fd6c1) {#structssl__esni__st_1acc1e4d390a3f6fc96c52a10cac4fd6c1}

#### `public  `[`STACK_OF`](#structssl__esni__st_1a50e1e3bc7a1318ab8624021ea50374cb)`(SSL_CIPHER)` {#structssl__esni__st_1a50e1e3bc7a1318ab8624021ea50374cb}

Generated by [Moxygen](https://sourcey.com/moxygen)