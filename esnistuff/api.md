# Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`define `[`MAX_ESNIKEYS_BUFLEN`](#mk__esnikeys_8c_1a33d1c4849da0ae9cc7cf6056b60520d3)            | just for laughs, won't be that long
`define `[`MAX_ESNI_COVER_NAME`](#mk__esnikeys_8c_1a02e3ec393689520344dbb1e270063a34)            | longer than this won't fit in SNI
`define `[`MAX_ESNI_ADDRS`](#mk__esnikeys_8c_1ae83c43362ce44c63f260db024f34e8a9)            | max addresses to include in AddressSet
`define `[`MAX_PADDING`](#mk__esnikeys_8c_1a2af3e0d0d59490c2c9d9392e1ea613b7)            | max padding to use when folding DNS records
`define `[`MAX_FMT_LEN`](#mk__esnikeys_8c_1a74dc89faf01842de8d5cbae2ac456e95)            | max length to allow for generated format strings
`define `[`MAX_ZONEDATA_BUFLEN`](#mk__esnikeys_8c_1a340659980efeb5f7dddff621c9378174)            | 
`define `[`ESNI_MAX_RRVALUE_LEN`](#esni_8h_1a1a51d2e5c90478d2ca90cbf1bd2d2c29)            | Max size of a collection of ESNI RR values.
`define `[`ESNI_SELECT_ALL`](#esni_8h_1a6775465f75ad8bf586bc5468ab3d8f5e)            | used to duplicate all RRs in SSL_ESNI_dup
`define `[`ESNI_PBUF_SIZE`](#esni_8h_1ae0df91ca64c9f2d82de06f1ee80d4ea3)            | 8K buffer used for print string sent to application via esni_print_cb
`define `[`ESNI_ADDRESS_SET_EXT`](#esni_8h_1ad732752bab7540fb16bf7f27ac242337)            | AddressSet as per draft-03.
`define `[`A2B`](#esni_8h_1a5b8b06ed943bce760b10302ff7bb519f)            | 
`define `[`ESNI_RRFMT_GUESS`](#esni_8h_1a1c2606670454ecb64a7e07f6106b34d2)            | try guess which it is
`define `[`ESNI_RRFMT_BIN`](#esni_8h_1ab25780b5d7b726ca3e54f884212e55a4)            | binary encoded
`define `[`ESNI_RRFMT_ASCIIHEX`](#esni_8h_1adefe6934d973ab450e15d760bf9bd5df)            | draft-03 ascii hex value(s catenated)
`define `[`ESNI_RRFMT_B64TXT`](#esni_8h_1a923e0ee958634a65f7a9e0cd7285e830)            | draft-02 (legacy) base64 encoded TXT
`define `[`ESNI_CRYPT_INTEROP`](#esni_8h_1ac1aec0191ca183eb5a034a8b892203ba)            | If defined, this provides enough API, internals and tracing so we can ensure/check we're generating keys the same way as other code, in partocular the existing NSS code.
`define `[`ESNI_DRAFT_02_VERSION`](#esni_8h_1aab16ad9837022e87bad6a800c659faa8)            | ESNIKeys version from draft-02.
`define `[`ESNI_DRAFT_03_VERSION`](#esni_8h_1a201ec5108d07793dc3a57dc85dfbcf60)            | ESNIKeys version from draft-03.
`define `[`ESNI_RRTYPE`](#esni_8h_1aae21f7e7c2f68a344a0ea3de430cb7b6)            | experimental (as per draft-03) ESNI RRTYPE
`define `[`SSL_ESNI_STATUS_SUCCESS`](#esni_8h_1a6a4d94b18577a453e7ca65273c75b110)            | Success.
`define `[`SSL_ESNI_STATUS_FAILED`](#esni_8h_1aff48e6059acca5bd4a3f9f2a926e9ffd)            | Some internal error.
`define `[`SSL_ESNI_STATUS_BAD_CALL`](#esni_8h_1a182a797bad43060760194c701c882fd0)            | Required in/out arguments were NULL.
`define `[`SSL_ESNI_STATUS_NOT_TRIED`](#esni_8h_1ac754df41295244baf3b951e9cec0a1db)            | ESNI wasn't attempted.
`define `[`SSL_ESNI_STATUS_BAD_NAME`](#esni_8h_1a4019c4a8f415a42a213cc0c657d9986b)            | ESNI succeeded but the TLS server cert used didn't match the hidden service name.
`define `[`SSL_ESNI_STATUS_TOOMANY`](#esni_8h_1ac5475161def14c76f3839bc4c64aaff3)            | ESNI succeeded can't figure out which one!
`define `[`ESNI_F_BASE64_DECODE`](#esnierr_8h_1a9c57a1b191c8fc44f0c9d33e1fa63096)            | 
`define `[`ESNI_F_CHECKSUM_CHECK`](#esnierr_8h_1ac8cec6cf839fa6b361bc6f9abc001201)            | 
`define `[`ESNI_F_DEC`](#esnierr_8h_1abfce120a6f075e1028bed584590a1c5d)            | 
`define `[`ESNI_F_ENC`](#esnierr_8h_1a5e1e464c2d05b71de95e455a341f477f)            | 
`define `[`ESNI_F_ESNI_AEAD_DEC`](#esnierr_8h_1a571ccdae3631195b42c5ecdfe3212c62)            | 
`define `[`ESNI_F_ESNI_AEAD_ENC`](#esnierr_8h_1a1859b752b238b95674cc017446061974)            | 
`define `[`ESNI_F_ESNI_BASE64_DECODE`](#esnierr_8h_1a2543cd28665c7263ffe4615b6660ba10)            | 
`define `[`ESNI_F_ESNI_CHECKSUM_CHECK`](#esnierr_8h_1a9f478c0f902d24881b962cfec67a0ac1)            | 
`define `[`ESNI_F_ESNI_MAKE_RD`](#esnierr_8h_1a60229aec0de39210acad040463eecfdb)            | 
`define `[`ESNI_F_ESNI_MAKE_SE_FROM_ER`](#esnierr_8h_1afe278864812870bca9fc98a4f261affc)            | 
`define `[`ESNI_F_KEY_DERIVATION`](#esnierr_8h_1a59d22dd182fd9430a2207635df598f9b)            | 
`define `[`ESNI_F_MAKEESNICONTENTHASH`](#esnierr_8h_1aa27cf276204a3be511e6ab7e865faa0b)            | 
`define `[`ESNI_F_NEW_FROM_BASE64`](#esnierr_8h_1a2292c05f5c24b23849789eb87f20bb0c)            | 
`define `[`ESNI_F_SERVER_ENABLE`](#esnierr_8h_1acad1a58b5647c362ed60ff908c36d5f6)            | 
`define `[`ESNI_F_SSL_ESNI_DEC`](#esnierr_8h_1ac9a4f6e0b201b714d7fc826fb72cc0b9)            | 
`define `[`ESNI_F_SSL_ESNI_DUP`](#esnierr_8h_1aec816c5e3c505967eed955abc47bd183)            | 
`define `[`ESNI_F_SSL_ESNI_ENC`](#esnierr_8h_1a700d74c26efd12bff3173ee199564ad8)            | 
`define `[`ESNI_F_SSL_ESNI_NEW_FROM_BASE64`](#esnierr_8h_1a8e769255bdcaf3fd6f82697804d1d862)            | 
`define `[`ESNI_F_SSL_ESNI_NEW_FROM_BUFFER`](#esnierr_8h_1afafb2aa4c81ba899e650e855b3cf6e85)            | 
`define `[`ESNI_F_SSL_ESNI_QUERY`](#esnierr_8h_1a24341c52c1aadd66aeec2e0451a88a0f)            | 
`define `[`ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY`](#esnierr_8h_1a5d28993dbae8bdf5b5126b0c853eaf3d)            | 
`define `[`ESNI_F_SSL_ESNI_REDUCE`](#esnierr_8h_1aa5513cc756c763f5bd555fe2640b6dae)            | 
`define `[`ESNI_F_SSL_ESNI_SERVER_ENABLE`](#esnierr_8h_1a41fef6b5fc372dad4fcc7008563eb32c)            | 
`define `[`ESNI_F_SSL_ESNI_WRAP_KEYSHARE`](#esnierr_8h_1adbb1d0dcbf5f441fed68948b660840b7)            | 
`define `[`ESNI_R_ASCIIHEX_DECODE_ERROR`](#esnierr_8h_1ab453885d2af021244097e10bd9da9a52)            | 
`define `[`ESNI_R_BASE64_DECODE_ERROR`](#esnierr_8h_1a1c13aa91c93bd84f1f92101ddb9bc9eb)            | 
`define `[`ESNI_R_NOT_IMPL`](#esnierr_8h_1aeb72e4451595e51885c8192c3c06e870)            | 
`define `[`ESNI_R_RR_DECODE_ERROR`](#esnierr_8h_1acc748e3e2af6dc12fead035b479c221f)            | 
`define `[`ESNI_DEFAULT_PADDED`](#esni_8c_1a706a8b9ec3b00f59d60711d623c90d74)            | File: esni.c - the core implementation of drat-ietf-tls-esni-02 Author: [stephen.farrell@cs.tcd.ie](mailto:stephen.farrell@cs.tcd.ie) Date: 2018 December-ish.
`define `[`SSL_ESNI_dup_one`](#esni_8c_1a264331e3021c14c1d3e1403c5923fd93)            | 
`public static unsigned int `[`esni_print_cb`](#s__client_8c_1ad7caf3d16900b8c136462917f264cf13)`(SSL * s,char * str)`            | print an ESNI structure, this time thread safely;-)
`public static unsigned int `[`esni_print_cb`](#s__server_8c_1ad7caf3d16900b8c136462917f264cf13)`(SSL * s,char * str)`            | print an ESNI structure, this time thread safely;-)
`public static size_t `[`esni_padding_cb`](#s__server_8c_1a2deb1d25456628e166cb5fbaa8f11bbf)`(SSL * s,int type,size_t len,void * arg)`            | @ brief pad Certificate and CertificateVerify messages
`public static int `[`ssl_esni_servername_cb`](#s__server_8c_1a454eca00c708c0f47fccc73616408b67)`(SSL * s,int * ad,void * arg)`            | a servername_cb that is ESNI aware
`public int `[`ERR_load_ESNI_strings`](#esnierr_8c_1ab6db8c60b35aacaa03550e6d9d9c2099)`(void)`            | 
`public static void `[`so_esni_pbuf`](#mk__esnikeys_8c_1ae1bab08e2b36301f0c81f27d7ffb006b)`(char * msg,unsigned char * buf,size_t blen,int indent)`            | 
`public static void `[`sp_esni_prr`](#mk__esnikeys_8c_1ac9aa090d4d174faf6bfc215e81fea637)`(unsigned char * sbuf,size_t slen,unsigned char * buf,size_t blen,unsigned short typecode,int ttl,char * owner_name)`            | write zone fragment to buffer for display or writing to file
`public static int `[`esni_checksum_gen`](#mk__esnikeys_8c_1a32ec581cbe2fef728eca2951e596d25f)`(unsigned char * buf,size_t buf_len,unsigned char cksum)`            | generate the SHA256 checksum that should be in the DNS record
`public void `[`usage`](#mk__esnikeys_8c_1aa4817482b1728bf62acf8030cab9842c)`(char * prog)`            | 
`public static unsigned short `[`verstr2us`](#mk__esnikeys_8c_1a72a0b47dc43ca86d6b01cc02529e5e59)`(char * arg)`            | map version string like 0xff01 to unsigned short
`public static int `[`add2alist`](#mk__esnikeys_8c_1ab7c3a487787a14d9d4ed14cbfcfd1ae6)`(char * ips,int * nips_p,char * line)`            | Add an adderess to the list if it's not there already.
`public static int `[`mk_aset`](#mk__esnikeys_8c_1a3aa9ea3f0f5ded3a054da299975fc977)`(char * asetfname,char * cover_name,size_t * elen,unsigned char ** eval)`            | make up AddressSet extension
`public static int `[`mk_grease_ext`](#mk__esnikeys_8c_1afd211911d9d53ff8cd4e5832fdf38c4f)`(int type,size_t * elen,unsigned char ** eval)`            | return a greasy extension value
`public static int `[`mk_esnikeys`](#mk__esnikeys_8c_1a9d11ac25babd35d36598edd0beab07c9)`(int argc,char ** argv)`            | Make an X25519 key pair and ESNIKeys structure for the public.
`public int `[`main`](#mk__esnikeys_8c_1a3c04138a5bfe5d72780bb7e82a18e627)`(int argc,char ** argv)`            | 
`public unsigned char * `[`SSL_ESNI_wrap_keyshare`](#esni_8h_1adcc8e3823bf93d20d67977dfeb29fa5d)`(const unsigned char * keyshare,const size_t keyshare_len,const uint16_t curve_id,size_t * outlen)`            | wrap a "raw" key share in the relevant TLS presentation layer encoding
`public int `[`SSL_ESNI_enc`](#esni_8h_1a1059808bc7c121128c470de41e2dc304)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` ** the_esni)`            | Do the client-side SNI encryption during a TLS handshake.
`public unsigned char * `[`SSL_ESNI_dec`](#esni_8h_1ae4af2d2173a5c3b1513a1dcd04e2e940)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,size_t * encservername_len)`            | Server-side decryption during a TLS handshake.
`public void `[`SSL_ESNI_free`](#esni_8h_1a6d6ea1b22339efdc370e6cbf251b277d)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys)`            | Memory management - free an SSL_ESNI.
`public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_dup`](#esni_8h_1a07a28c6e3bb17d0f37f039c25bd7cdfb)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * orig,size_t nesni,int selector)`            | Duplicate the configuration related fields of an SSL_ESNI.
`public int `[`SSL_esni_checknames`](#esni_8h_1a55aedc0e921fd36dcc3327124f07da10)`(const char * encservername,const char * covername)`            | Make a basic check of names from CLI or API.
`public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_new_from_buffer`](#esni_8h_1a4c6db15a4771bde53711578b90279518)`(const short ekfmt,const size_t eklen,const char * esnikeys,int * num_esnis)`            | Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
`public int `[`SSL_esni_enable`](#esni_8h_1ab8f184bbd11ca9a01018b3ec381cf377)`(SSL * s,const char * hidden,const char * cover,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int nesnis,int require_hidden_match)`            | Turn on SNI encryption for an (upcoming) TLS session.
`public int `[`SSL_esni_query`](#esni_8h_1a90dc2776e24df4afed11ed5f87f9775c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * in,`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` ** out,int * nindices)`            | query the content of an SSL_ESNI structure
`public void `[`SSL_ESNI_ext_free`](#esni_8h_1ad0558a0a329a96dcd5df41120692e08e)`(`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` * in,int size)`            | free up memory for an SSL_ESNI_ext
`public int `[`SSL_ESNI_ext_print`](#esni_8h_1ae9c0193105f5bffc743bfd8b9c29b561)`(BIO * out,`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` * se,int count)`            | utility fnc for application that wants to print an SSL_ESNI_ext
`public int `[`SSL_esni_reduce`](#esni_8h_1a5d34c8e2d50475b71c6b386ae27dab61)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * in,int index,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** out)`            | down-select to use of one option with an SSL_ESNI
`public int `[`SSL_esni_server_enable`](#esni_8h_1a0589fa7d65bf2263c361258876e0e67a)`(SSL_CTX * s,const char * esnikeyfile,const char * esnipubfile)`            | Turn on SNI Encryption, server-side.
`public int `[`SSL_ESNI_get_esni`](#esni_8h_1ac214a7933d6e5fa9e2be5218b9537a63)`(SSL * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)`            | Access an SSL_ESNI structure note - can include sensitive values!
`public int `[`SSL_ESNI_get_esni_ctx`](#esni_8h_1acd373a6c0dddd76f399e103e80f538cc)`(SSL_CTX * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)`            | Access an SSL_ESNI structure note - can include sensitive values!
`public int `[`SSL_ESNI_print`](#esni_8h_1ac953373e8ce69f0ee18f451d1f17df48)`(BIO * out,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int selector)`            | Print the content of an SSL_ESNI.
`public int `[`SSL_get_esni_status`](#esni_8h_1abc2468ba57b69ddaca0344481027d7a1)`(SSL * s,char ** hidden,char ** cover)`            | API to allow calling code know ESNI outcome, post-handshake.
`public int `[`SSL_ESNI_set_private`](#esni_8h_1a8df1af022d25fc0f7e72683b0bd4667f)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,char * private_str)`            | Allows caller to set the ECDH private value for ESNI.
`public int `[`SSL_ESNI_set_nonce`](#esni_8h_1a0f48da79909334acee7b24dec440eb4c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,unsigned char * nonce,size_t nlen)`            | Allows caller to set the nonce value for ESNI.
`public int `[`ERR_load_ESNI_strings`](#esnierr_8h_1ab6db8c60b35aacaa03550e6d9d9c2099)`(void)`            | 
`public static uint64_t `[`uint64_from_bytes`](#esni_8c_1a83d195ea944e970d225ac1554c88c3d4)`(unsigned char * buf)`            | map 8 bytes in n/w byte order from PACKET to a 64-bit time value
`public static int `[`ah_decode`](#esni_8c_1aa69325c71b10890e08f4a74cbb6f282e)`(size_t ahlen,const char * ah,size_t * blen,unsigned char ** buf)`            | decode ascii hex to a binary buffer
`public static int `[`esni_base64_decode`](#esni_8c_1a2ed0892e8d90c540129b2bbbe622491f)`(char * in,unsigned char ** out)`            | Decode from TXT RR to binary buffer.
`public static const SSL_CIPHER * `[`cs2sc`](#esni_8c_1a45c16ecbc68d6567bf9d4ef58bfdb46f)`(uint16_t ciphersuite)`            | 
`public void `[`ESNI_RECORD_free`](#esni_8c_1a2af97ba7f8ebc58e04391bc845f21811)`(`[`ESNI_RECORD`](#esni_8h_1ab29e08d24d0eac604e0d6783dfbf1758)` * er)`            | Free up an ENSI_RECORD.
`public void `[`SSL_ESNI_free`](#esni_8c_1ac5e6bdbd9c660b5018b6fbcb709acfa0)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * deadesni)`            | Free up an SSL_ESNI structure.
`public static int `[`esni_checksum_check`](#esni_8c_1a4c8d42c0081cae34740804bb9c4fc88b)`(unsigned char * buf,size_t buf_len)`            | Verify the SHA256 checksum that should be in the DNS record.
`public static unsigned char * `[`esni_make_rd`](#esni_8c_1a1a6df9cdee70887ac4c2492164155e83)`(const unsigned char * buf,const size_t blen,const EVP_MD * md,size_t * rd_len)`            | Hash the buffer as per the ciphersuite specified therein.
`public unsigned char * `[`SSL_ESNI_wrap_keyshare`](#esni_8c_1adcc8e3823bf93d20d67977dfeb29fa5d)`(const unsigned char * keyshare,const size_t keyshare_len,const uint16_t curve_id,size_t * outlen)`            | wrap a "raw" key share in the relevant TLS presentation layer encoding
`public static `[`ESNI_RECORD`](#esni_8h_1ab29e08d24d0eac604e0d6783dfbf1758)` * `[`SSL_ESNI_RECORD_new_from_binary`](#esni_8c_1af9f431ee1fc925fd0ff18da59e75c1e9)`(unsigned char * binbuf,size_t binblen,int * leftover)`            | Decode from binary to ESNI_RECORD.
`public static int `[`esni_parse_address_set`](#esni_8c_1a0e394e29dfeb6fc5137bbf29c396c7c5)`(size_t evl,unsigned char * ev,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * se)`            | parse an AddressSet extension value into an SSL_ESNI structure
`public static int `[`esni_make_se_from_er`](#esni_8c_1a1332a08e3b77da97cc9aef2efd50f904)`(`[`ESNI_RECORD`](#esni_8h_1ab29e08d24d0eac604e0d6783dfbf1758)` * er,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * se,int server)`            | populate an SSL_ESNI from an ESNI_RECORD
`public static int `[`esni_guess_fmt`](#esni_8c_1ab62256e9f33fa91eaf5b6c76bedd0a96)`(const size_t eklen,const char * esnikeys,short * guessedfmt)`            | Try figure out ESNIKeys encodng.
`public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_new_from_buffer`](#esni_8c_1a4c6db15a4771bde53711578b90279518)`(const short ekfmt,const size_t eklen,const char * esnikeys,int * num_esnis)`            | Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
`public static void `[`esni_pbuf`](#esni_8c_1ad619d10af828adf65d47682bdab514d1)`(BIO * out,char * msg,unsigned char * buf,size_t blen,int indent)`            | print a buffer nicely
`public int `[`SSL_ESNI_print`](#esni_8c_1afebef7970cbb431fbac3df60397fabf9)`(BIO * out,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esniarr,int selector)`            | Print out an array of SSL_ESNI structures.
`public static unsigned char * `[`esni_nonce`](#esni_8c_1a50f8ca970c2ceb308dbf23fd0410ee3b)`(size_t nl)`            | Make a 16 octet nonce for ESNI.
`public static unsigned char * `[`esni_pad`](#esni_8c_1a3e85b60a8ef53ff8670c54af6e376c40)`(char * name,unsigned int padded_len)`            | Pad an SNI before encryption with zeros on the right to the required length.
`public static unsigned char * `[`esni_hkdf_extract`](#esni_8c_1a9f76caa6f579de747d413ee3e809650d)`(unsigned char * secret,size_t slen,size_t * olen,const EVP_MD * md)`            | Local wrapper for HKDF-Extract(salt,IVM)=HMAC-Hash(salt,IKM) according to RFC5689.
`public static unsigned char * `[`esni_hkdf_expand_label`](#esni_8c_1a7dd32376e27d6c6aed533917093639e8)`(unsigned char * Zx,size_t Zx_len,const char * label,unsigned char * hash,size_t hash_len,size_t * expanded_len,const EVP_MD * md)`            | expand a label as per the I-D
`public static unsigned char * `[`esni_aead_enc`](#esni_8c_1a7a9797b7a757306ed1035009fa7d0694)`(unsigned char * key,size_t key_len,unsigned char * iv,size_t iv_len,unsigned char * aad,size_t aad_len,unsigned char * plain,size_t plain_len,unsigned char * tag,size_t tag_len,size_t * cipher_len,uint16_t ciph)`            | do the AEAD encryption as per the I-D
`public static unsigned char * `[`esni_aead_dec`](#esni_8c_1a870cb4460d44f015048426db48ad9446)`(unsigned char * key,size_t key_len,unsigned char * iv,size_t iv_len,unsigned char * aad,size_t aad_len,unsigned char * cipher,size_t cipher_len,size_t * plain_len,uint16_t ciph)`            | do the AEAD decryption as per the I-D
`public static int `[`makeesnicontenthash`](#esni_8c_1a52493599c778fa63f5254cd84e8ae464)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys,int server)`            | given an SSL_ESNI create ESNIContent and hash that
`public static int `[`key_derivation`](#esni_8c_1a42f693ae84206906ae6ff8cd553434ac)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys)`            | from Zx and ESNIContent, derive key, iv and aad
`public int `[`SSL_ESNI_enc`](#esni_8c_1ac4b4c67757dece6ab4a26078f749c698)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys_in,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` ** the_esni)`            | Do the client-side SNI encryption during a TLS handshake.
`public unsigned char * `[`SSL_ESNI_dec`](#esni_8c_1ae4af2d2173a5c3b1513a1dcd04e2e940)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,size_t * encservername_len)`            | Attempt/do the serveri-side decryption during a TLS handshake.
`public int `[`SSL_esni_checknames`](#esni_8c_1a55aedc0e921fd36dcc3327124f07da10)`(const char * encservername,const char * covername)`            | Make a basic check of names from CLI or API.
`public int `[`SSL_esni_enable`](#esni_8c_1ab8f184bbd11ca9a01018b3ec381cf377)`(SSL * s,const char * hidden,const char * cover,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int nesnis,int require_hidden_match)`            | : Turn on SNI encryption for an (upcoming) TLS session
`public int `[`SSL_esni_server_enable`](#esni_8c_1aeef3e81451e59142e5cdec4f26c09fff)`(SSL_CTX * s,const char * esnikeyfile,const char * esnipubfile)`            | Turn on SNI Encryption, server-side.
`public int `[`SSL_get_esni_status`](#esni_8c_1abc2468ba57b69ddaca0344481027d7a1)`(SSL * s,char ** hidden,char ** cover)`            | API to allow calling code know ESNI outcome, post-handshake.
`public void `[`SSL_set_esni_callback`](#esni_8c_1ac4fbad870f00b5b6cb84629c4995be02)`(SSL * s,SSL_esni_client_cb_func f)`            | 
`public void `[`SSL_set_esni_callback_ctx`](#esni_8c_1a67ce35919f89b9259bb873b7702227ac)`(SSL_CTX * s,SSL_esni_client_cb_func f)`            | 
`public int `[`SSL_ESNI_get_esni`](#esni_8c_1ac214a7933d6e5fa9e2be5218b9537a63)`(SSL * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)`            | Access an SSL_ESNI structure note - can include sensitive values!
`public int `[`SSL_ESNI_get_esni_ctx`](#esni_8c_1acd373a6c0dddd76f399e103e80f538cc)`(SSL_CTX * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)`            | Access an SSL_ESNI structure note - can include sensitive values!
`public int `[`SSL_ESNI_set_private`](#esni_8c_1a8df1af022d25fc0f7e72683b0bd4667f)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,char * private_str)`            | Allows caller to set the ECDH private value for ESNI.
`public int `[`SSL_ESNI_set_nonce`](#esni_8c_1a0f48da79909334acee7b24dec440eb4c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,unsigned char * nonce,size_t nlen)`            | Allows caller to set the nonce value for ESNI.
`public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_dup`](#esni_8c_1a07a28c6e3bb17d0f37f039c25bd7cdfb)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * orig,size_t nesni,int selector)`            | Duplicate the configuration related fields of an SSL_ESNI.
`public int `[`SSL_esni_query`](#esni_8c_1a90dc2776e24df4afed11ed5f87f9775c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * in,`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` ** out,int * nindices)`            | query the content of an SSL_ESNI structure
`public void `[`SSL_ESNI_ext_free`](#esni_8c_1ad0558a0a329a96dcd5df41120692e08e)`(`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` * in,int size)`            | free up memory for an SSL_ESNI_ext
`public int `[`SSL_esni_reduce`](#esni_8c_1a5d34c8e2d50475b71c6b386ae27dab61)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * in,int index,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** out)`            | down-select to use of one option with an SSL_ESNI
`public int `[`SSL_ESNI_ext_print`](#esni_8c_1ae9c0193105f5bffc743bfd8b9c29b561)`(BIO * out,`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` * se,int count)`            | utility fnc for application that wants to print an SSL_ESNI_ext
`public static int `[`init_esni`](#extensions_8c_1a07941fe88fcdb65271ad678cd41e7d57)`(SSL * s,unsigned int context)`            | Just note that esni is not yet done.
`public static int `[`final_esni`](#extensions_8c_1a4027805482e89339fd2870f852db4b4e)`(SSL * s,unsigned int context,int sent)`            | check result of esni and return error or ok
`public static EXT_RETURN `[`esni_server_name_fixup`](#extensions__clnt_8c_1a2454a14e823689509154ca3bfb4cdaea)`(SSL * s,WPACKET * pkt,unsigned int context,X509 * x,size_t chainidx)`            | Possibly do/don't send SNI if doing ESNI.
`public EXT_RETURN `[`tls_construct_ctos_esni`](#extensions__clnt_8c_1afca936de2d3ae315b5e8b8b200d17462)`(SSL * s,WPACKET * pkt,unsigned int context,X509 * x,size_t chainidx)`            | Create the ESNI extension for the ClientHello.
`public int `[`tls_parse_stoc_esni`](#extensions__clnt_8c_1ac388d56d20b4d3b507e56203f1c08303)`(SSL * s,PACKET * pkt,unsigned int context,X509 * x,size_t chainidx)`            | Parse and check the ESNI value returned in the EncryptedExtensions to make sure it has the nonce we sent in the ClientHello.
`public int `[`tls_parse_ctos_esni`](#extensions__srvr_8c_1a4a75b5940e39e1b5da10aefc8ed0ac69)`(SSL * s,PACKET * pkt,unsigned int context,X509 * x,size_t chainidx)`            | Decodes inbound ESNI extension into SSL_ESNI structure.
`public EXT_RETURN `[`tls_construct_stoc_esni`](#extensions__srvr_8c_1ae56ce4660abc014b273c5f743bc3eb63)`(SSL * s,WPACKET * pkt,unsigned int context,X509 * x,size_t chainidx)`            | If ESNI all went well, and we have a nonce then send that back.
`struct `[`client_esni_st`](#structclient__esni__st) | What we send in the esni CH extension:
`struct `[`esni_padding_sizes`](#structesni__padding__sizes) | Padding size info.
`struct `[`esni_record_st`](#structesni__record__st) | Representation of what goes in DNS.
`struct `[`ssl_esni_ext_st`](#structssl__esni__ext__st) | Exterally visible form of an ESNIKeys RR value.
`struct `[`ssl_esni_st`](#structssl__esni__st) | The ESNI data structure that's part of the SSL structure.

## Members

<p id="mk__esnikeys_8c_1a33d1c4849da0ae9cc7cf6056b60520d3"><hr></p>

#### `define `[`MAX_ESNIKEYS_BUFLEN`](#mk__esnikeys_8c_1a33d1c4849da0ae9cc7cf6056b60520d3) 

just for laughs, won't be that long

<p id="mk__esnikeys_8c_1a02e3ec393689520344dbb1e270063a34"><hr></p>

#### `define `[`MAX_ESNI_COVER_NAME`](#mk__esnikeys_8c_1a02e3ec393689520344dbb1e270063a34) 

longer than this won't fit in SNI

<p id="mk__esnikeys_8c_1ae83c43362ce44c63f260db024f34e8a9"><hr></p>

#### `define `[`MAX_ESNI_ADDRS`](#mk__esnikeys_8c_1ae83c43362ce44c63f260db024f34e8a9) 

max addresses to include in AddressSet

<p id="mk__esnikeys_8c_1a2af3e0d0d59490c2c9d9392e1ea613b7"><hr></p>

#### `define `[`MAX_PADDING`](#mk__esnikeys_8c_1a2af3e0d0d59490c2c9d9392e1ea613b7) 

max padding to use when folding DNS records

<p id="mk__esnikeys_8c_1a74dc89faf01842de8d5cbae2ac456e95"><hr></p>

#### `define `[`MAX_FMT_LEN`](#mk__esnikeys_8c_1a74dc89faf01842de8d5cbae2ac456e95) 

max length to allow for generated format strings

<p id="mk__esnikeys_8c_1a340659980efeb5f7dddff621c9378174"><hr></p>

#### `define `[`MAX_ZONEDATA_BUFLEN`](#mk__esnikeys_8c_1a340659980efeb5f7dddff621c9378174) 

<p id="esni_8h_1a1a51d2e5c90478d2ca90cbf1bd2d2c29"><hr></p>

#### `define `[`ESNI_MAX_RRVALUE_LEN`](#esni_8h_1a1a51d2e5c90478d2ca90cbf1bd2d2c29) 

Max size of a collection of ESNI RR values.

<p id="esni_8h_1a6775465f75ad8bf586bc5468ab3d8f5e"><hr></p>

#### `define `[`ESNI_SELECT_ALL`](#esni_8h_1a6775465f75ad8bf586bc5468ab3d8f5e) 

used to duplicate all RRs in SSL_ESNI_dup

<p id="esni_8h_1ae0df91ca64c9f2d82de06f1ee80d4ea3"><hr></p>

#### `define `[`ESNI_PBUF_SIZE`](#esni_8h_1ae0df91ca64c9f2d82de06f1ee80d4ea3) 

8K buffer used for print string sent to application via esni_print_cb

<p id="esni_8h_1ad732752bab7540fb16bf7f27ac242337"><hr></p>

#### `define `[`ESNI_ADDRESS_SET_EXT`](#esni_8h_1ad732752bab7540fb16bf7f27ac242337) 

AddressSet as per draft-03.

<p id="esni_8h_1a5b8b06ed943bce760b10302ff7bb519f"><hr></p>

#### `define `[`A2B`](#esni_8h_1a5b8b06ed943bce760b10302ff7bb519f) 

<p id="esni_8h_1a1c2606670454ecb64a7e07f6106b34d2"><hr></p>

#### `define `[`ESNI_RRFMT_GUESS`](#esni_8h_1a1c2606670454ecb64a7e07f6106b34d2) 

try guess which it is

<p id="esni_8h_1ab25780b5d7b726ca3e54f884212e55a4"><hr></p>

#### `define `[`ESNI_RRFMT_BIN`](#esni_8h_1ab25780b5d7b726ca3e54f884212e55a4) 

binary encoded

<p id="esni_8h_1adefe6934d973ab450e15d760bf9bd5df"><hr></p>

#### `define `[`ESNI_RRFMT_ASCIIHEX`](#esni_8h_1adefe6934d973ab450e15d760bf9bd5df) 

draft-03 ascii hex value(s catenated)

<p id="esni_8h_1a923e0ee958634a65f7a9e0cd7285e830"><hr></p>

#### `define `[`ESNI_RRFMT_B64TXT`](#esni_8h_1a923e0ee958634a65f7a9e0cd7285e830) 

draft-02 (legacy) base64 encoded TXT

<p id="esni_8h_1ac1aec0191ca183eb5a034a8b892203ba"><hr></p>

#### `define `[`ESNI_CRYPT_INTEROP`](#esni_8h_1ac1aec0191ca183eb5a034a8b892203ba) 

If defined, this provides enough API, internals and tracing so we can ensure/check we're generating keys the same way as other code, in partocular the existing NSS code.

<p id="esni_8h_1aab16ad9837022e87bad6a800c659faa8"><hr></p>

#### `define `[`ESNI_DRAFT_02_VERSION`](#esni_8h_1aab16ad9837022e87bad6a800c659faa8) 

ESNIKeys version from draft-02.

<p id="esni_8h_1a201ec5108d07793dc3a57dc85dfbcf60"><hr></p>

#### `define `[`ESNI_DRAFT_03_VERSION`](#esni_8h_1a201ec5108d07793dc3a57dc85dfbcf60) 

ESNIKeys version from draft-03.

<p id="esni_8h_1aae21f7e7c2f68a344a0ea3de430cb7b6"><hr></p>

#### `define `[`ESNI_RRTYPE`](#esni_8h_1aae21f7e7c2f68a344a0ea3de430cb7b6) 

experimental (as per draft-03) ESNI RRTYPE

<p id="esni_8h_1a6a4d94b18577a453e7ca65273c75b110"><hr></p>

#### `define `[`SSL_ESNI_STATUS_SUCCESS`](#esni_8h_1a6a4d94b18577a453e7ca65273c75b110) 

Success.

<p id="esni_8h_1aff48e6059acca5bd4a3f9f2a926e9ffd"><hr></p>

#### `define `[`SSL_ESNI_STATUS_FAILED`](#esni_8h_1aff48e6059acca5bd4a3f9f2a926e9ffd) 

Some internal error.

<p id="esni_8h_1a182a797bad43060760194c701c882fd0"><hr></p>

#### `define `[`SSL_ESNI_STATUS_BAD_CALL`](#esni_8h_1a182a797bad43060760194c701c882fd0) 

Required in/out arguments were NULL.

<p id="esni_8h_1ac754df41295244baf3b951e9cec0a1db"><hr></p>

#### `define `[`SSL_ESNI_STATUS_NOT_TRIED`](#esni_8h_1ac754df41295244baf3b951e9cec0a1db) 

ESNI wasn't attempted.

<p id="esni_8h_1a4019c4a8f415a42a213cc0c657d9986b"><hr></p>

#### `define `[`SSL_ESNI_STATUS_BAD_NAME`](#esni_8h_1a4019c4a8f415a42a213cc0c657d9986b) 

ESNI succeeded but the TLS server cert used didn't match the hidden service name.

<p id="esni_8h_1ac5475161def14c76f3839bc4c64aaff3"><hr></p>

#### `define `[`SSL_ESNI_STATUS_TOOMANY`](#esni_8h_1ac5475161def14c76f3839bc4c64aaff3) 

ESNI succeeded can't figure out which one!

<p id="esnierr_8h_1a9c57a1b191c8fc44f0c9d33e1fa63096"><hr></p>

#### `define `[`ESNI_F_BASE64_DECODE`](#esnierr_8h_1a9c57a1b191c8fc44f0c9d33e1fa63096) 

<p id="esnierr_8h_1ac8cec6cf839fa6b361bc6f9abc001201"><hr></p>

#### `define `[`ESNI_F_CHECKSUM_CHECK`](#esnierr_8h_1ac8cec6cf839fa6b361bc6f9abc001201) 

<p id="esnierr_8h_1abfce120a6f075e1028bed584590a1c5d"><hr></p>

#### `define `[`ESNI_F_DEC`](#esnierr_8h_1abfce120a6f075e1028bed584590a1c5d) 

<p id="esnierr_8h_1a5e1e464c2d05b71de95e455a341f477f"><hr></p>

#### `define `[`ESNI_F_ENC`](#esnierr_8h_1a5e1e464c2d05b71de95e455a341f477f) 

<p id="esnierr_8h_1a571ccdae3631195b42c5ecdfe3212c62"><hr></p>

#### `define `[`ESNI_F_ESNI_AEAD_DEC`](#esnierr_8h_1a571ccdae3631195b42c5ecdfe3212c62) 

<p id="esnierr_8h_1a1859b752b238b95674cc017446061974"><hr></p>

#### `define `[`ESNI_F_ESNI_AEAD_ENC`](#esnierr_8h_1a1859b752b238b95674cc017446061974) 

<p id="esnierr_8h_1a2543cd28665c7263ffe4615b6660ba10"><hr></p>

#### `define `[`ESNI_F_ESNI_BASE64_DECODE`](#esnierr_8h_1a2543cd28665c7263ffe4615b6660ba10) 

<p id="esnierr_8h_1a9f478c0f902d24881b962cfec67a0ac1"><hr></p>

#### `define `[`ESNI_F_ESNI_CHECKSUM_CHECK`](#esnierr_8h_1a9f478c0f902d24881b962cfec67a0ac1) 

<p id="esnierr_8h_1a60229aec0de39210acad040463eecfdb"><hr></p>

#### `define `[`ESNI_F_ESNI_MAKE_RD`](#esnierr_8h_1a60229aec0de39210acad040463eecfdb) 

<p id="esnierr_8h_1afe278864812870bca9fc98a4f261affc"><hr></p>

#### `define `[`ESNI_F_ESNI_MAKE_SE_FROM_ER`](#esnierr_8h_1afe278864812870bca9fc98a4f261affc) 

<p id="esnierr_8h_1a59d22dd182fd9430a2207635df598f9b"><hr></p>

#### `define `[`ESNI_F_KEY_DERIVATION`](#esnierr_8h_1a59d22dd182fd9430a2207635df598f9b) 

<p id="esnierr_8h_1aa27cf276204a3be511e6ab7e865faa0b"><hr></p>

#### `define `[`ESNI_F_MAKEESNICONTENTHASH`](#esnierr_8h_1aa27cf276204a3be511e6ab7e865faa0b) 

<p id="esnierr_8h_1a2292c05f5c24b23849789eb87f20bb0c"><hr></p>

#### `define `[`ESNI_F_NEW_FROM_BASE64`](#esnierr_8h_1a2292c05f5c24b23849789eb87f20bb0c) 

<p id="esnierr_8h_1acad1a58b5647c362ed60ff908c36d5f6"><hr></p>

#### `define `[`ESNI_F_SERVER_ENABLE`](#esnierr_8h_1acad1a58b5647c362ed60ff908c36d5f6) 

<p id="esnierr_8h_1ac9a4f6e0b201b714d7fc826fb72cc0b9"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_DEC`](#esnierr_8h_1ac9a4f6e0b201b714d7fc826fb72cc0b9) 

<p id="esnierr_8h_1aec816c5e3c505967eed955abc47bd183"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_DUP`](#esnierr_8h_1aec816c5e3c505967eed955abc47bd183) 

<p id="esnierr_8h_1a700d74c26efd12bff3173ee199564ad8"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_ENC`](#esnierr_8h_1a700d74c26efd12bff3173ee199564ad8) 

<p id="esnierr_8h_1a8e769255bdcaf3fd6f82697804d1d862"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_NEW_FROM_BASE64`](#esnierr_8h_1a8e769255bdcaf3fd6f82697804d1d862) 

<p id="esnierr_8h_1afafb2aa4c81ba899e650e855b3cf6e85"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_NEW_FROM_BUFFER`](#esnierr_8h_1afafb2aa4c81ba899e650e855b3cf6e85) 

<p id="esnierr_8h_1a24341c52c1aadd66aeec2e0451a88a0f"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_QUERY`](#esnierr_8h_1a24341c52c1aadd66aeec2e0451a88a0f) 

<p id="esnierr_8h_1a5d28993dbae8bdf5b5126b0c853eaf3d"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY`](#esnierr_8h_1a5d28993dbae8bdf5b5126b0c853eaf3d) 

<p id="esnierr_8h_1aa5513cc756c763f5bd555fe2640b6dae"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_REDUCE`](#esnierr_8h_1aa5513cc756c763f5bd555fe2640b6dae) 

<p id="esnierr_8h_1a41fef6b5fc372dad4fcc7008563eb32c"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_SERVER_ENABLE`](#esnierr_8h_1a41fef6b5fc372dad4fcc7008563eb32c) 

<p id="esnierr_8h_1adbb1d0dcbf5f441fed68948b660840b7"><hr></p>

#### `define `[`ESNI_F_SSL_ESNI_WRAP_KEYSHARE`](#esnierr_8h_1adbb1d0dcbf5f441fed68948b660840b7) 

<p id="esnierr_8h_1ab453885d2af021244097e10bd9da9a52"><hr></p>

#### `define `[`ESNI_R_ASCIIHEX_DECODE_ERROR`](#esnierr_8h_1ab453885d2af021244097e10bd9da9a52) 

<p id="esnierr_8h_1a1c13aa91c93bd84f1f92101ddb9bc9eb"><hr></p>

#### `define `[`ESNI_R_BASE64_DECODE_ERROR`](#esnierr_8h_1a1c13aa91c93bd84f1f92101ddb9bc9eb) 

<p id="esnierr_8h_1aeb72e4451595e51885c8192c3c06e870"><hr></p>

#### `define `[`ESNI_R_NOT_IMPL`](#esnierr_8h_1aeb72e4451595e51885c8192c3c06e870) 

<p id="esnierr_8h_1acc748e3e2af6dc12fead035b479c221f"><hr></p>

#### `define `[`ESNI_R_RR_DECODE_ERROR`](#esnierr_8h_1acc748e3e2af6dc12fead035b479c221f) 

<p id="esni_8c_1a706a8b9ec3b00f59d60711d623c90d74"><hr></p>

#### `define `[`ESNI_DEFAULT_PADDED`](#esni_8c_1a706a8b9ec3b00f59d60711d623c90d74) 

File: esni.c - the core implementation of drat-ietf-tls-esni-02 Author: [stephen.farrell@cs.tcd.ie](mailto:stephen.farrell@cs.tcd.ie) Date: 2018 December-ish.

Handle padding - the server needs to do padding in case the certificate/key-size exposes the ESNI. But so can lots of the other application interactions, so to be at least a bit cautious, we'll also pad the crap out of everything on the client side (at least to see what happens:-) This could be over-ridden by the client appication if it wants by setting a callback via SSL_set_record_padding_callback We'll try set to 486 bytes, so that 3 plaintexts are likely to fit in a 1500 byte MTU. (That's a pretty arbitrary decision:-) TODO: test and see how this padding affects a real application as soon as we've integrated with oneWe'll pad all TLS plaintext to this size

<p id="esni_8c_1a264331e3021c14c1d3e1403c5923fd93"><hr></p>

#### `define `[`SSL_ESNI_dup_one`](#esni_8c_1a264331e3021c14c1d3e1403c5923fd93) 

<p id="s__client_8c_1ad7caf3d16900b8c136462917f264cf13"><hr></p>

#### `public static unsigned int `[`esni_print_cb`](#s__client_8c_1ad7caf3d16900b8c136462917f264cf13)`(SSL * s,char * str)` 

print an ESNI structure, this time thread safely;-)

<p id="s__server_8c_1ad7caf3d16900b8c136462917f264cf13"><hr></p>

#### `public static unsigned int `[`esni_print_cb`](#s__server_8c_1ad7caf3d16900b8c136462917f264cf13)`(SSL * s,char * str)` 

print an ESNI structure, this time thread safely;-)

<p id="s__server_8c_1a2deb1d25456628e166cb5fbaa8f11bbf"><hr></p>

#### `public static size_t `[`esni_padding_cb`](#s__server_8c_1a2deb1d25456628e166cb5fbaa8f11bbf)`(SSL * s,int type,size_t len,void * arg)` 

@ brief pad Certificate and CertificateVerify messages

This is passed to SSL_CTX_set_record_padding_callback and pads the Certificate and CertificateVerify handshake messages to a size derived from the argument arg

#### Parameters
* `s` is the SSL connection 

* `len` is the plaintext length before padding 

* `arg` is a pointer to an [esni_padding_sizes](#structesni__padding__sizes) struct 

#### Returns
is the number of bytes of padding to add to the plaintext

<p id="s__server_8c_1a454eca00c708c0f47fccc73616408b67"><hr></p>

#### `public static int `[`ssl_esni_servername_cb`](#s__server_8c_1a454eca00c708c0f47fccc73616408b67)`(SSL * s,int * ad,void * arg)` 

a servername_cb that is ESNI aware

The server has possibly two names (from command line and config) basically in ctx and ctx2. So we need to check if the client-supplied (E)SNI matches either and serve whichever is appropriate. X509_check_host is the way to do that, given an X509* pointer. We default to the "main" ctx is the client-supplied (E)SNI does not match the ctx2 certificate. We don't fail if the client-supplied (E)SNI matches neither, but just continue with the "main" ctx. If the client-supplied (E)SNI matches both ctx and ctx2, then we'll switch to ctx2 anyway - we don't try for a "best" match in that case.

#### Parameters
* `s` is the SSL connection 

* `ad` is dunno 

* `arg` is a pointer to a tlsext 

#### Returns
1 or error

<p id="esnierr_8c_1ab6db8c60b35aacaa03550e6d9d9c2099"><hr></p>

#### `public int `[`ERR_load_ESNI_strings`](#esnierr_8c_1ab6db8c60b35aacaa03550e6d9d9c2099)`(void)` 

<p id="mk__esnikeys_8c_1ae1bab08e2b36301f0c81f27d7ffb006b"><hr></p>

#### `public static void `[`so_esni_pbuf`](#mk__esnikeys_8c_1ae1bab08e2b36301f0c81f27d7ffb006b)`(char * msg,unsigned char * buf,size_t blen,int indent)` 

<p id="mk__esnikeys_8c_1ac9aa090d4d174faf6bfc215e81fea637"><hr></p>

#### `public static void `[`sp_esni_prr`](#mk__esnikeys_8c_1ac9aa090d4d174faf6bfc215e81fea637)`(unsigned char * sbuf,size_t slen,unsigned char * buf,size_t blen,unsigned short typecode,int ttl,char * owner_name)` 

write zone fragment to buffer for display or writing to file

#### Parameters
* `sbuf` where zone fragment will be written 

* `slen` length of sbuf 

* `buf` binary public key data 

* `blen` length of buf 

* `typecode` DNS TYPE code to use 

* `ttl` is the TTL to use 

* `owner_name` fully-qualified DNS owner, without trailing dot

<p id="mk__esnikeys_8c_1a32ec581cbe2fef728eca2951e596d25f"><hr></p>

#### `public static int `[`esni_checksum_gen`](#mk__esnikeys_8c_1a32ec581cbe2fef728eca2951e596d25f)`(unsigned char * buf,size_t buf_len,unsigned char cksum)` 

generate the SHA256 checksum that should be in the DNS record

Fixed SHA256 hash in this case, we work on the offset here, (bytes 2 bytes then 4 checksum bytes then rest) with no other knowledge of the encoding.

#### Parameters
* `buf` is the buffer 

* `buf_len` is obvous 

#### Returns
1 for success, not 1 otherwise

<p id="mk__esnikeys_8c_1aa4817482b1728bf62acf8030cab9842c"><hr></p>

#### `public void `[`usage`](#mk__esnikeys_8c_1aa4817482b1728bf62acf8030cab9842c)`(char * prog)` 

<p id="mk__esnikeys_8c_1a72a0b47dc43ca86d6b01cc02529e5e59"><hr></p>

#### `public static unsigned short `[`verstr2us`](#mk__esnikeys_8c_1a72a0b47dc43ca86d6b01cc02529e5e59)`(char * arg)` 

map version string like 0xff01 to unsigned short

#### Parameters
* `arg` is the version string, from command line 

#### Returns
is the unsigned short value (with zero for error cases)

<p id="mk__esnikeys_8c_1ab7c3a487787a14d9d4ed14cbfcfd1ae6"><hr></p>

#### `public static int `[`add2alist`](#mk__esnikeys_8c_1ab7c3a487787a14d9d4ed14cbfcfd1ae6)`(char * ips,int * nips_p,char * line)` 

Add an adderess to the list if it's not there already.

#### Parameters
*

<p id="mk__esnikeys_8c_1a3aa9ea3f0f5ded3a054da299975fc977"><hr></p>

#### `public static int `[`mk_aset`](#mk__esnikeys_8c_1a3aa9ea3f0f5ded3a054da299975fc977)`(char * asetfname,char * cover_name,size_t * elen,unsigned char ** eval)` 

make up AddressSet extension

#### Parameters
* `asetfname` names a file with one IPv4 or IPv6 address per line 

* `cover_name` names the cover site 

* `elen` returns the length of the AddressSet extension encoding 

* `eval` returns the AddressSet extension encoding (including the type) 

#### Returns
1 for success, 0 for error

<p id="mk__esnikeys_8c_1afd211911d9d53ff8cd4e5832fdf38c4f"><hr></p>

#### `public static int `[`mk_grease_ext`](#mk__esnikeys_8c_1afd211911d9d53ff8cd4e5832fdf38c4f)`(int type,size_t * elen,unsigned char ** eval)` 

return a greasy extension value

#### Parameters
* `type` - the extension type to use 

* `elen` - returns the extension length 

* `eval` - the octets of the extension encoding 

#### Returns
1 for good, 0 for error

<p id="mk__esnikeys_8c_1a9d11ac25babd35d36598edd0beab07c9"><hr></p>

#### `public static int `[`mk_esnikeys`](#mk__esnikeys_8c_1a9d11ac25babd35d36598edd0beab07c9)`(int argc,char ** argv)` 

Make an X25519 key pair and ESNIKeys structure for the public.

> Todo: TODO: check out NSS code to see if I can make same format private 

TODO: Decide if supporting private key re-use is even needed.

<p id="mk__esnikeys_8c_1a3c04138a5bfe5d72780bb7e82a18e627"><hr></p>

#### `public int `[`main`](#mk__esnikeys_8c_1a3c04138a5bfe5d72780bb7e82a18e627)`(int argc,char ** argv)` 

<p id="esni_8h_1adcc8e3823bf93d20d67977dfeb29fa5d"><hr></p>

#### `public unsigned char * `[`SSL_ESNI_wrap_keyshare`](#esni_8h_1adcc8e3823bf93d20d67977dfeb29fa5d)`(const unsigned char * keyshare,const size_t keyshare_len,const uint16_t curve_id,size_t * outlen)` 

wrap a "raw" key share in the relevant TLS presentation layer encoding

Put the outer length and curve ID around a key share. This just exists because we do it a few times: for the ESNI client keyshare and for handshake client keyshare. The input keyshare is the e.g. 32 octets of a point on curve 25519 as used in X25519.

#### Parameters
* `keyshare` is the input keyshare which'd be 32 octets for x25519 

* `keyshare_len` is the length of the above (0x20 for x25519) 

* `curve_id` is the IANA registered value for the curve e.g. 0x1d for X25519 

* `outlen` is the length of the encoded version of the above 

#### Returns
is NULL (on error) or a pointer to the encoded version buffer

Put the outer length and curve ID around a key share. This just exists because we do it twice: for the ESNI client keyshare and for handshake client keyshare. The input keyshare is the e.g. 32 octets of a point on curve 25519 as used in X25519. There's no magic here, it's just that this code recurs in handling ESNI. Theere might be some existing API to use that'd be better.

#### Parameters
* `keyshare` is the input keyshare which'd be 32 octets for x25519 

* `keyshare_len` is the length of the above (0x20 for x25519) 

* `curve_id` is the IANA registered value for the curve e.g. 0x1d for X25519 

* `outlen` is the length of the encoded version of the above 

#### Returns
is NULL (on error) or a pointer to the encoded version buffer

<p id="esni_8h_1a1059808bc7c121128c470de41e2dc304"><hr></p>

#### `public int `[`SSL_ESNI_enc`](#esni_8h_1a1059808bc7c121128c470de41e2dc304)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` ** the_esni)` 

Do the client-side SNI encryption during a TLS handshake.

This is an internal API called as part of the state machine dealing with this extension.

#### Parameters
* `esnikeys` is the SSL_ESNI structure 

* `client_random_len` is the number of bytes of 

* `client_random` being the TLS h/s client random 

* `curve_id` is the curve_id of the client keyshare 

* `client_keyshare_len` is the number of bytes of 

* `client_keyshare` is the h/s client keyshare 

#### Returns
1 for success, other otherwise

This is an internal API called as part of the state machine dealing with this extension.

#### Parameters
* `esnikeys_in` is an array of SSL_ESNI structures:w 

* `client_random_len` is the number of bytes of 

* `client_random` being the TLS h/s client random 

* `curve_id` is the curve_id of the client keyshare 

* `client_keyshare_len` is the number of bytes of 

* `client_keyshare` is the h/s client keyshare 

#### Returns
1 for success, other otherwise

<p id="esni_8h_1ae4af2d2173a5c3b1513a1dcd04e2e940"><hr></p>

#### `public unsigned char * `[`SSL_ESNI_dec`](#esni_8h_1ae4af2d2173a5c3b1513a1dcd04e2e940)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,size_t * encservername_len)` 

Server-side decryption during a TLS handshake.

This is the internal API called as part of the state machine dealing with this extension. Note that the decrypted server name is just a set of octets - there is no guarantee it's a DNS name or printable etc. (Same as with SNI generally.)

#### Parameters
* `esni` is the SSL_ESNI structure 

* `client_random_len` is the number of bytes of 

* `client_random` being the TLS h/s client random 

* `curve_id` is the curve_id of the client keyshare 

* `client_keyshare_len` is the number of bytes of 

* `client_keyshare` is the h/s client keyshare 

#### Returns
NULL for error, or the decrypted servername when it works

Server-side decryption during a TLS handshake.

This is the internal API called as part of the state machine dealing with this extension.

Note that the decrypted server name is just a set of octets - there is no guarantee it's a DNS name or printable etc. (Same as with SNI generally.)

#### Parameters
* `esni` is the SSL_ESNI structure 

* `client_random_len` is the number of bytes of 

* `client_random` being the TLS h/s client random 

* `curve_id` is the curve_id of the client keyshare 

* `client_keyshare_len` is the number of bytes of 

* `client_keyshare` is the h/s client keyshare 

#### Returns
NULL for error, or the decrypted servername when it works

<p id="esni_8h_1a6d6ea1b22339efdc370e6cbf251b277d"><hr></p>

#### `public void `[`SSL_ESNI_free`](#esni_8h_1a6d6ea1b22339efdc370e6cbf251b277d)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys)` 

Memory management - free an SSL_ESNI.

Free everything within an SSL_ESNI. Note that the caller has to free the top level SSL_ESNI, IOW the pattern here is: SSL_ESNI_free(esnikeys); OPENSSL_free(esnikeys);

#### Parameters
* `esnikeys` is an SSL_ESNI structure

Memory management - free an SSL_ESNI.

Note that we don't free the top level, caller should do that This will free the CLIENT_ESNI structure contained in here.

#### Parameters
* `esni` a ptr to an SSL_ESNI str

<p id="esni_8h_1a07a28c6e3bb17d0f37f039c25bd7cdfb"><hr></p>

#### `public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_dup`](#esni_8h_1a07a28c6e3bb17d0f37f039c25bd7cdfb)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * orig,size_t nesni,int selector)` 

Duplicate the configuration related fields of an SSL_ESNI.

This is needed to handle the SSL_CTX->SSL factory model in the server. Clients don't need this. There aren't too many fields populated when this is called - essentially just the ESNIKeys and the server private value. For the moment, we actually only deep-copy those.

#### Parameters
* `orig` is the input array of SSL_ESNI to be partly deep-copied 

* `nesni` is the number of elements in the array 

* `selector` allows for picking all (ESNI_SELECT_ALL==-1) or just one of the RR values in orig 

#### Returns
a partial deep-copy array or NULL if errors occur

<p id="esni_8h_1a55aedc0e921fd36dcc3327124f07da10"><hr></p>

#### `public int `[`SSL_esni_checknames`](#esni_8h_1a55aedc0e921fd36dcc3327124f07da10)`(const char * encservername,const char * covername)` 

Make a basic check of names from CLI or API.

Note: This may disappear as all the checks currently done would result in errors anyway. However, that could change, so we'll keep it for now.

#### Parameters
* `encservername` the hidden servie 

* `convername` the cleartext SNI to send (can be NULL if we don't want any) 

#### Returns
1 for success, other otherwise

<p id="esni_8h_1a4c6db15a4771bde53711578b90279518"><hr></p>

#### `public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_new_from_buffer`](#esni_8h_1a4c6db15a4771bde53711578b90279518)`(const short ekfmt,const size_t eklen,const char * esnikeys,int * num_esnis)` 

Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)

The esnnikeys value here may be the catenation of multiple encoded ESNIKeys RR values (or TXT values for draft-02), we'll internally try decode and handle those and (later) use whichever is relevant/best. The fmt parameter can be e.g. ESNI_RRFMT_ASCII_HEX

#### Parameters
* `ekfmt` specifies the format of the input text string 

* `eklen` is the length of the binary, base64 or ascii-hex encoded value from DNS 

* `esnikeys` is the binary, base64 or ascii-hex encoded value from DNS 

* `num_esnis` says how many SSL_ESNI structures are in the returned array 

#### Returns
is an SSL_ESNI structure

<p id="esni_8h_1ab8f184bbd11ca9a01018b3ec381cf377"><hr></p>

#### `public int `[`SSL_esni_enable`](#esni_8h_1ab8f184bbd11ca9a01018b3ec381cf377)`(SSL * s,const char * hidden,const char * cover,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int nesnis,int require_hidden_match)` 

Turn on SNI encryption for an (upcoming) TLS session.

#### Parameters
* `s` is the SSL context 

* `hidde` is the hidden service name 

* `cover` is the cleartext SNI name to use 

* `esni` is an array of SSL_ESNI structures 

* `nesnis` says how many structures are in the esni array 

* `require_hidden_match` say whether to require (==1) the TLS server cert matches the hidden name 

#### Returns
1 for success, error otherwise

Turn on SNI encryption for an (upcoming) TLS session.

FIXME: Rationalise the handling of arrays of SSL_ESNI structs. As of now, we sometimes set the number of those as a parameter (as in this case), whereas other bits of code use the num_esni_rrs field inside the first array element to know how many we're dealing with.

#### Parameters
* `s` is the SSL context 

* `hidde` is the hidden service name 

* `cover` is the cleartext SNI name to use 

* `esni` is an array of SSL_ESNI structures 

* `nesnis` says how many structures are in the esni array 

* `require_hidden_match` say whether to require (==1) the TLS server cert matches the hidden name 

#### Returns
1 for success, other otherwise

<p id="esni_8h_1a90dc2776e24df4afed11ed5f87f9775c"><hr></p>

#### `public int `[`SSL_esni_query`](#esni_8h_1a90dc2776e24df4afed11ed5f87f9775c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * in,`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` ** out,int * nindices)` 

query the content of an SSL_ESNI structure

This function allows the application to examine some internals of an SSL_ESNI structure so that it can then down-select some options. In particular, the caller can see the public_name and IP address related information associated with each ESNIKeys RR value (after decoding and initial checking within the library), and can then choose which of the RR value options the application would prefer to use.

#### Parameters
* `in` is the internal form of SSL_ESNI structure 

* `out` is the returned externally visible detailed form of the SSL_ESNI structure 

* `nindices` is an output saying how many indices are in the SSL_ESNI_ext structure 

#### Returns
1 for success, error otherwise

This function allows the application to examine some internals of an SSL_ESNI structure so that it can then down-select some options. In particular, the caller can see the public_name and IP address related information associated with each ESNIKeys RR value (after decoding and initial checking within the library), and can then choose which of the RR value options the application would prefer to use.

#### Parameters
* `in` is the internal form of SSL_ESNI structure 

* `out` is the returned externally array of visible detailed forms of the SSL_ESNI structure 

* `nindices` is an output saying how many indices are in the SSL_ESNI_ext structure 

#### Returns
1 for success, error otherwise

<p id="esni_8h_1ad0558a0a329a96dcd5df41120692e08e"><hr></p>

#### `public void `[`SSL_ESNI_ext_free`](#esni_8h_1ad0558a0a329a96dcd5df41120692e08e)`(`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` * in,int size)` 

free up memory for an SSL_ESNI_ext

#### Parameters
* `in` is the structure to free up 

* `size` says how many indices are in in

<p id="esni_8h_1ae9c0193105f5bffc743bfd8b9c29b561"><hr></p>

#### `public int `[`SSL_ESNI_ext_print`](#esni_8h_1ae9c0193105f5bffc743bfd8b9c29b561)`(BIO * out,`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` * se,int count)` 

utility fnc for application that wants to print an SSL_ESNI_ext

#### Parameters
* `out` is the BIO to use (e.g. stdout/whatever) 

* `se` is a pointer to an SSL_ESNI_ext struture 

* `count` is the number of elements in se 

#### Returns
1 for success, error othewise

<p id="esni_8h_1a5d34c8e2d50475b71c6b386ae27dab61"><hr></p>

#### `public int `[`SSL_esni_reduce`](#esni_8h_1a5d34c8e2d50475b71c6b386ae27dab61)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * in,int index,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** out)` 

down-select to use of one option with an SSL_ESNI

This allows the caller to select one of the RR values within an SSL_ESNI for later use.

#### Parameters
* `in` is an SSL_ESNI structure with possibly multiple RR values 

* `index` is the index value from an SSL_ESNI_ext produced from the 'in' 

* `out` is a returned SSL_ESNI containing only that indexed RR value 

#### Returns
1 for success, error otherwise

<p id="esni_8h_1a0589fa7d65bf2263c361258876e0e67a"><hr></p>

#### `public int `[`SSL_esni_server_enable`](#esni_8h_1a0589fa7d65bf2263c361258876e0e67a)`(SSL_CTX * s,const char * esnikeyfile,const char * esnipubfile)` 

Turn on SNI Encryption, server-side.

When this works, the server will decrypt any ESNI seen in ClientHellos and subsequently treat those as if they had been send in cleartext SNI.

#### Parameters
* `s` is the SSL server context 

* `esnikeyfile` has the relevant (X25519) private key in PEM format 

* `esnipubfile` has the relevant (binary encoded, not base64) ESNIKeys structure 

#### Returns
1 for success, other otherwise

<p id="esni_8h_1ac214a7933d6e5fa9e2be5218b9537a63"><hr></p>

#### `public int `[`SSL_ESNI_get_esni`](#esni_8h_1ac214a7933d6e5fa9e2be5218b9537a63)`(SSL * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)` 

Access an SSL_ESNI structure note - can include sensitive values!

#### Parameters
* `s` is a an SSL structure, as used on TLS client 

* `esni` is an SSL_ESNI structure 

#### Returns
1 for success, anything else for failure

<p id="esni_8h_1acd373a6c0dddd76f399e103e80f538cc"><hr></p>

#### `public int `[`SSL_ESNI_get_esni_ctx`](#esni_8h_1acd373a6c0dddd76f399e103e80f538cc)`(SSL_CTX * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)` 

Access an SSL_ESNI structure note - can include sensitive values!

#### Parameters
* `s` is a an SSL_CTX structure, as used on TLS server 

* `esni` is an SSL_ESNI structure 

#### Returns
0 for failure, non-zero is the number of SSL_ESNI in the array

<p id="esni_8h_1ac953373e8ce69f0ee18f451d1f17df48"><hr></p>

#### `public int `[`SSL_ESNI_print`](#esni_8h_1ac953373e8ce69f0ee18f451d1f17df48)`(BIO * out,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int selector)` 

Print the content of an SSL_ESNI.

#### Parameters
* `out` is the BIO to use (e.g. stdout/whatever) 

* `esni` is an SSL_ESNI strucutre 

* `selector` allows for picking all (ESNI_SELECT_ALL==-1) or just one of the RR values in orig 

#### Returns
1 for success, anything else for failure

The esni pointer must point at the full array, and not at the element you want to select using the selector. That is, the implementation here will try access esni[2] if you provide selector value 2.

Print the content of an SSL_ESNI.

This is called via callback

#### Parameters
* `out` is the BIO* 

* `esniarr` is an array of SSL_ESNI structures 

#### Returns
1 is good

<p id="esni_8h_1abc2468ba57b69ddaca0344481027d7a1"><hr></p>

#### `public int `[`SSL_get_esni_status`](#esni_8h_1abc2468ba57b69ddaca0344481027d7a1)`(SSL * s,char ** hidden,char ** cover)` 

API to allow calling code know ESNI outcome, post-handshake.

This is intended to be called by applications after the TLS handshake is complete. This works for both client and server. The caller does not have to (and shouldn't) free the hidden or cover strings. TODO: Those are pointers into the SSL struct though so maybe better to allocate fresh ones.

Note that the PR we sent to curl will include a check that this function exists (something like "AC_CHECK_FUNCS( SSL_get_esni_status )" so don't change this name without co-ordinating with that. The curl PR: [https://github.com/curl/curl/pull/4011](https://github.com/curl/curl/pull/4011)

#### Parameters
* `s` The SSL context (if that's the right term) 

* `hidden` will be set to the address of the hidden service 

* `cover` will be set to the address of the hidden service 

#### Returns
1 for success, other otherwise

<p id="esni_8h_1a8df1af022d25fc0f7e72683b0bd4667f"><hr></p>

#### `public int `[`SSL_ESNI_set_private`](#esni_8h_1a8df1af022d25fc0f7e72683b0bd4667f)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,char * private_str)` 

Allows caller to set the ECDH private value for ESNI.

This is intended to only be used for interop testing - what was useful was to grab the value from the NSS implemtation, force it into mine and see which of the derived values end up the same.

#### Parameters
* `esni` is the SSL_ESNI struture 

* `private_str` is an ASCII-hex encoded X25519 point (essentially a random 32 octet value:-) 

#### Returns
1 for success, other otherwise

<p id="esni_8h_1a0f48da79909334acee7b24dec440eb4c"><hr></p>

#### `public int `[`SSL_ESNI_set_nonce`](#esni_8h_1a0f48da79909334acee7b24dec440eb4c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,unsigned char * nonce,size_t nlen)` 

Allows caller to set the nonce value for ESNI.

This is intended to only be used for interop testing - what was useful was to grab the value from the NSS implemtation, force it into mine and see which of the derived values end up the same.

#### Parameters
* `esni` is the SSL_ESNI struture 

* `nonce` points to a buffer with the network byte order value  nlen is the size of the nonce buffer 

#### Returns
1 for success, other otherwise

<p id="esnierr_8h_1ab6db8c60b35aacaa03550e6d9d9c2099"><hr></p>

#### `public int `[`ERR_load_ESNI_strings`](#esnierr_8h_1ab6db8c60b35aacaa03550e6d9d9c2099)`(void)` 

<p id="esni_8c_1a83d195ea944e970d225ac1554c88c3d4"><hr></p>

#### `public static uint64_t `[`uint64_from_bytes`](#esni_8c_1a83d195ea944e970d225ac1554c88c3d4)`(unsigned char * buf)` 

map 8 bytes in n/w byte order from PACKET to a 64-bit time value

> Todo: TODO: there must be code for this somewhere - find it

#### Parameters
* `buf` is a bit of the PACKET with the 8 octets of interest 

#### Returns
is the 64 bit value from those 8 octets

<p id="esni_8c_1aa69325c71b10890e08f4a74cbb6f282e"><hr></p>

#### `public static int `[`ah_decode`](#esni_8c_1aa69325c71b10890e08f4a74cbb6f282e)`(size_t ahlen,const char * ah,size_t * blen,unsigned char ** buf)` 

decode ascii hex to a binary buffer

> Todo: TODO: there should be an OPENSSL_* function somewhere for this I guess - find it This assumes string is correctly ascii hex encoded

#### Parameters
* `ahlen` is the ascii hex string length 

* `ahstr` is the ascii hex string 

* `blen` is a pointer to the returned binary length 

* `buf` is a pointer to the internally allocated binary buffer 

#### Returns
zero for error, 1 for success

<p id="esni_8c_1a2ed0892e8d90c540129b2bbbe622491f"><hr></p>

#### `public static int `[`esni_base64_decode`](#esni_8c_1a2ed0892e8d90c540129b2bbbe622491f)`(char * in,unsigned char ** out)` 

Decode from TXT RR to binary buffer.

This was the same as ct_base64_decode from crypto/ct/ct_b64.c which function is declared static but could otherwise have been be re-used. Returns -1 for error or length of decoded buffer length otherwise (wasn't clear to me at first glance). Possible future change: re-use the ct code by exporting it. With draft-03, we're extending to allow a set of semi-colon separated strings as the input to handle multivalued RRs.

Decodes the base64 string |in| into |out|. A new string will be malloc'd and assigned to |out|. This will be owned by the caller. Do not provide a pre-allocated string in |out|. The input is modified if multivalued (NULL bytes are added in place of semi-colon separators.

#### Parameters
* `in` is the base64 encoded string 

* `out` is the binary equivalent 

#### Returns
is the number of octets in |out| if successful, <=0 for failure

<p id="esni_8c_1a45c16ecbc68d6567bf9d4ef58bfdb46f"><hr></p>

#### `public static const SSL_CIPHER * `[`cs2sc`](#esni_8c_1a45c16ecbc68d6567bf9d4ef58bfdb46f)`(uint16_t ciphersuite)` 

<p id="esni_8c_1a2af97ba7f8ebc58e04391bc845f21811"><hr></p>

#### `public void `[`ESNI_RECORD_free`](#esni_8c_1a2af97ba7f8ebc58e04391bc845f21811)`(`[`ESNI_RECORD`](#esni_8h_1ab29e08d24d0eac604e0d6783dfbf1758)` * er)` 

Free up an ENSI_RECORD.

ESNI_RECORD is our struct for what's in the DNS

er is a pointer to the record

<p id="esni_8c_1ac5e6bdbd9c660b5018b6fbcb709acfa0"><hr></p>

#### `public void `[`SSL_ESNI_free`](#esni_8c_1ac5e6bdbd9c660b5018b6fbcb709acfa0)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * deadesni)` 

Free up an SSL_ESNI structure.

Memory management - free an SSL_ESNI.

Note that we don't free the top level, caller should do that This will free the CLIENT_ESNI structure contained in here.

#### Parameters
* `esni` a ptr to an SSL_ESNI str

<p id="esni_8c_1a4c8d42c0081cae34740804bb9c4fc88b"><hr></p>

#### `public static int `[`esni_checksum_check`](#esni_8c_1a4c8d42c0081cae34740804bb9c4fc88b)`(unsigned char * buf,size_t buf_len)` 

Verify the SHA256 checksum that should be in the DNS record.

Fixed SHA256 hash in this case, we work on the offset here, (bytes 2 bytes then 4 checksum bytes then rest) with no other knowledge of the encoding.

#### Parameters
* `buf` is the buffer 

* `buf_len` is obvous 

#### Returns
1 for success, not 1 otherwise

<p id="esni_8c_1a1a6df9cdee70887ac4c2492164155e83"><hr></p>

#### `public static unsigned char * `[`esni_make_rd`](#esni_8c_1a1a6df9cdee70887ac4c2492164155e83)`(const unsigned char * buf,const size_t blen,const EVP_MD * md,size_t * rd_len)` 

Hash the buffer as per the ciphersuite specified therein.

Note that this isn't quite what the I-D says - It seems that NSS uses the entire buffer, incl. the version, so I've also done that as it works! Opened issue: [https://github.com/tlswg/draft-ietf-tls-esni/issues/119](https://github.com/tlswg/draft-ietf-tls-esni/issues/119)

#### Parameters
* `buf` is the input buffer 

* `blen` is the input buffer length 

* `md` is the hash function 

* `rd_len` is (a ptr to) the output hash length 

#### Returns
a pointer to the hash buffer allocated within the function or NULL on error

<p id="esni_8c_1adcc8e3823bf93d20d67977dfeb29fa5d"><hr></p>

#### `public unsigned char * `[`SSL_ESNI_wrap_keyshare`](#esni_8c_1adcc8e3823bf93d20d67977dfeb29fa5d)`(const unsigned char * keyshare,const size_t keyshare_len,const uint16_t curve_id,size_t * outlen)` 

wrap a "raw" key share in the relevant TLS presentation layer encoding

Put the outer length and curve ID around a key share. This just exists because we do it twice: for the ESNI client keyshare and for handshake client keyshare. The input keyshare is the e.g. 32 octets of a point on curve 25519 as used in X25519. There's no magic here, it's just that this code recurs in handling ESNI. Theere might be some existing API to use that'd be better.

#### Parameters
* `keyshare` is the input keyshare which'd be 32 octets for x25519 

* `keyshare_len` is the length of the above (0x20 for x25519) 

* `curve_id` is the IANA registered value for the curve e.g. 0x1d for X25519 

* `outlen` is the length of the encoded version of the above 

#### Returns
is NULL (on error) or a pointer to the encoded version buffer

<p id="esni_8c_1af9f431ee1fc925fd0ff18da59e75c1e9"><hr></p>

#### `public static `[`ESNI_RECORD`](#esni_8h_1ab29e08d24d0eac604e0d6783dfbf1758)` * `[`SSL_ESNI_RECORD_new_from_binary`](#esni_8c_1af9f431ee1fc925fd0ff18da59e75c1e9)`(unsigned char * binbuf,size_t binblen,int * leftover)` 

Decode from binary to ESNI_RECORD.

#### Parameters
* `binbuf` is the buffer with the encoding 

* `binblen` is the length of binbunf 

* `leftover` is the number of unused octets from the input 

#### Returns
NULL on error, or an ESNI_RECORD structure

<p id="esni_8c_1a0e394e29dfeb6fc5137bbf29c396c7c5"><hr></p>

#### `public static int `[`esni_parse_address_set`](#esni_8c_1a0e394e29dfeb6fc5137bbf29c396c7c5)`(size_t evl,unsigned char * ev,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * se)` 

parse an AddressSet extension value into an SSL_ESNI structure

#### Parameters
* `evl` is the length of the encoded extension 

* `ev` is the encoded extension value 

* `se` is the SSL_ESNI structure 

#### Returns
1 for ok, otherwise error

<p id="esni_8c_1a1332a08e3b77da97cc9aef2efd50f904"><hr></p>

#### `public static int `[`esni_make_se_from_er`](#esni_8c_1a1332a08e3b77da97cc9aef2efd50f904)`(`[`ESNI_RECORD`](#esni_8h_1ab29e08d24d0eac604e0d6783dfbf1758)` * er,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * se,int server)` 

populate an SSL_ESNI from an ESNI_RECORD

This is used by both client and server in (almost) identical ways. Note that se->encoded_rr and se->encodded_rr_len must be set before calling this, but that's usually fine.

> Todo: TODO: handle >1 of the many things that can have >1 instance (maybe at a higher layer)

#### Parameters
* `er` is the ESNI_RECORD 

* `se` is the SSL_ESNI 

* `server` is 1 if we're a TLS server, 0 otherwise, (just in case there's a difference) 

#### Returns
1 for success, not 1 otherwise

<p id="esni_8c_1ab62256e9f33fa91eaf5b6c76bedd0a96"><hr></p>

#### `public static int `[`esni_guess_fmt`](#esni_8c_1ab62256e9f33fa91eaf5b6c76bedd0a96)`(const size_t eklen,const char * esnikeys,short * guessedfmt)` 

Try figure out ESNIKeys encodng.

#### Parameters
* `eklen` is the length of esnikeys 

* `esnikeys` is encoded ESNIKeys structure 

* `guessedfmt` is our returned guess at the format 

#### Returns
1 for success, 0 for error

<p id="esni_8c_1a4c6db15a4771bde53711578b90279518"><hr></p>

#### `public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_new_from_buffer`](#esni_8c_1a4c6db15a4771bde53711578b90279518)`(const short ekfmt,const size_t eklen,const char * esnikeys,int * num_esnis)` 

Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)

The esnnikeys value here may be the catenation of multiple encoded ESNIKeys RR values (or TXT values for draft-02), we'll internally try decode and handle those and (later) use whichever is relevant/best. The fmt parameter can be e.g. ESNI_RRFMT_ASCII_HEX

#### Parameters
* `ekfmt` specifies the format of the input text string 

* `eklen` is the length of the binary, base64 or ascii-hex encoded value from DNS 

* `esnikeys` is the binary, base64 or ascii-hex encoded value from DNS 

* `num_esnis` says how many SSL_ESNI structures are in the returned array 

#### Returns
is an SSL_ESNI structure

<p id="esni_8c_1ad619d10af828adf65d47682bdab514d1"><hr></p>

#### `public static void `[`esni_pbuf`](#esni_8c_1ad619d10af828adf65d47682bdab514d1)`(BIO * out,char * msg,unsigned char * buf,size_t blen,int indent)` 

print a buffer nicely

This is used in SSL_ESNI_print

<p id="esni_8c_1afebef7970cbb431fbac3df60397fabf9"><hr></p>

#### `public int `[`SSL_ESNI_print`](#esni_8c_1afebef7970cbb431fbac3df60397fabf9)`(BIO * out,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esniarr,int selector)` 

Print out an array of SSL_ESNI structures.

Print the content of an SSL_ESNI.

This is called via callback

#### Parameters
* `out` is the BIO* 

* `esniarr` is an array of SSL_ESNI structures 

#### Returns
1 is good

<p id="esni_8c_1a50f8ca970c2ceb308dbf23fd0410ee3b"><hr></p>

#### `public static unsigned char * `[`esni_nonce`](#esni_8c_1a50f8ca970c2ceb308dbf23fd0410ee3b)`(size_t nl)` 

Make a 16 octet nonce for ESNI.

<p id="esni_8c_1a3e85b60a8ef53ff8670c54af6e376c40"><hr></p>

#### `public static unsigned char * `[`esni_pad`](#esni_8c_1a3e85b60a8ef53ff8670c54af6e376c40)`(char * name,unsigned int padded_len)` 

Pad an SNI before encryption with zeros on the right to the required length.

<p id="esni_8c_1a9f76caa6f579de747d413ee3e809650d"><hr></p>

#### `public static unsigned char * `[`esni_hkdf_extract`](#esni_8c_1a9f76caa6f579de747d413ee3e809650d)`(unsigned char * secret,size_t slen,size_t * olen,const EVP_MD * md)` 

Local wrapper for HKDF-Extract(salt,IVM)=HMAC-Hash(salt,IKM) according to RFC5689.

<p id="esni_8c_1a7dd32376e27d6c6aed533917093639e8"><hr></p>

#### `public static unsigned char * `[`esni_hkdf_expand_label`](#esni_8c_1a7dd32376e27d6c6aed533917093639e8)`(unsigned char * Zx,size_t Zx_len,const char * label,unsigned char * hash,size_t hash_len,size_t * expanded_len,const EVP_MD * md)` 

expand a label as per the I-D

> Todo: TODO: this and esni_hkdf_extract should be better integrated There are functions that can do this that require an `SSL *s` input and we should move to use those.

<p id="esni_8c_1a7a9797b7a757306ed1035009fa7d0694"><hr></p>

#### `public static unsigned char * `[`esni_aead_enc`](#esni_8c_1a7a9797b7a757306ed1035009fa7d0694)`(unsigned char * key,size_t key_len,unsigned char * iv,size_t iv_len,unsigned char * aad,size_t aad_len,unsigned char * plain,size_t plain_len,unsigned char * tag,size_t tag_len,size_t * cipher_len,uint16_t ciph)` 

do the AEAD encryption as per the I-D

Note: The tag output isn't really needed but was useful when I got the aad wrong at one stage to keep it for now. Most parameters obvious but...

#### Parameters
* `cipher_Len` is an output 

#### Returns
NULL (on error) or pointer to alloced buffer for ciphertext

<p id="esni_8c_1a870cb4460d44f015048426db48ad9446"><hr></p>

#### `public static unsigned char * `[`esni_aead_dec`](#esni_8c_1a870cb4460d44f015048426db48ad9446)`(unsigned char * key,size_t key_len,unsigned char * iv,size_t iv_len,unsigned char * aad,size_t aad_len,unsigned char * cipher,size_t cipher_len,size_t * plain_len,uint16_t ciph)` 

do the AEAD decryption as per the I-D

Note: The tag output isn't really needed but was useful when I got the aad wrong at one stage to keep it for now. 
#### Parameters
* `cipher_Len` is an output 

#### Returns
NULL (on error) or pointer to alloced buffer for plaintext

<p id="esni_8c_1a52493599c778fa63f5254cd84e8ae464"><hr></p>

#### `public static int `[`makeesnicontenthash`](#esni_8c_1a52493599c778fa63f5254cd84e8ae464)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys,int server)` 

given an SSL_ESNI create ESNIContent and hash that

encode up TLS client's ESNI public keyshare (in a different part of the SSL_ESNI for client and server) and other parts of ESNIContents, and hash those

#### Parameters
* `esni` is the SSL_ESNI structure 

* `server` is 1 if on the server, 0 for client 

#### Returns
1 for success, other otherwise

<p id="esni_8c_1a42f693ae84206906ae6ff8cd553434ac"><hr></p>

#### `public static int `[`key_derivation`](#esni_8c_1a42f693ae84206906ae6ff8cd553434ac)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys)` 

from Zx and ESNIContent, derive key, iv and aad

#### Parameters
* `esni` is the SSL_ESNI structure 

#### Returns
1 for success, other otherwise

<p id="esni_8c_1ac4b4c67757dece6ab4a26078f749c698"><hr></p>

#### `public int `[`SSL_ESNI_enc`](#esni_8c_1ac4b4c67757dece6ab4a26078f749c698)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esnikeys_in,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,`[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` ** the_esni)` 

Do the client-side SNI encryption during a TLS handshake.

This is an internal API called as part of the state machine dealing with this extension.

#### Parameters
* `esnikeys_in` is an array of SSL_ESNI structures:w 

* `client_random_len` is the number of bytes of 

* `client_random` being the TLS h/s client random 

* `curve_id` is the curve_id of the client keyshare 

* `client_keyshare_len` is the number of bytes of 

* `client_keyshare` is the h/s client keyshare 

#### Returns
1 for success, other otherwise

<p id="esni_8c_1ae4af2d2173a5c3b1513a1dcd04e2e940"><hr></p>

#### `public unsigned char * `[`SSL_ESNI_dec`](#esni_8c_1ae4af2d2173a5c3b1513a1dcd04e2e940)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,size_t client_random_len,unsigned char * client_random,uint16_t curve_id,size_t client_keyshare_len,unsigned char * client_keyshare,size_t * encservername_len)` 

Attempt/do the serveri-side decryption during a TLS handshake.

Server-side decryption during a TLS handshake.

This is the internal API called as part of the state machine dealing with this extension.

Note that the decrypted server name is just a set of octets - there is no guarantee it's a DNS name or printable etc. (Same as with SNI generally.)

#### Parameters
* `esni` is the SSL_ESNI structure 

* `client_random_len` is the number of bytes of 

* `client_random` being the TLS h/s client random 

* `curve_id` is the curve_id of the client keyshare 

* `client_keyshare_len` is the number of bytes of 

* `client_keyshare` is the h/s client keyshare 

#### Returns
NULL for error, or the decrypted servername when it works

<p id="esni_8c_1a55aedc0e921fd36dcc3327124f07da10"><hr></p>

#### `public int `[`SSL_esni_checknames`](#esni_8c_1a55aedc0e921fd36dcc3327124f07da10)`(const char * encservername,const char * covername)` 

Make a basic check of names from CLI or API.

Note: This may disappear as all the checks currently done would result in errors anyway. However, that could change, so we'll keep it for now.

#### Parameters
* `encservername` the hidden servie 

* `convername` the cleartext SNI to send (can be NULL if we don't want any) 

#### Returns
1 for success, other otherwise

<p id="esni_8c_1ab8f184bbd11ca9a01018b3ec381cf377"><hr></p>

#### `public int `[`SSL_esni_enable`](#esni_8c_1ab8f184bbd11ca9a01018b3ec381cf377)`(SSL * s,const char * hidden,const char * cover,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,int nesnis,int require_hidden_match)` 

: Turn on SNI encryption for an (upcoming) TLS session

Turn on SNI encryption for an (upcoming) TLS session.

FIXME: Rationalise the handling of arrays of SSL_ESNI structs. As of now, we sometimes set the number of those as a parameter (as in this case), whereas other bits of code use the num_esni_rrs field inside the first array element to know how many we're dealing with.

#### Parameters
* `s` is the SSL context 

* `hidde` is the hidden service name 

* `cover` is the cleartext SNI name to use 

* `esni` is an array of SSL_ESNI structures 

* `nesnis` says how many structures are in the esni array 

* `require_hidden_match` say whether to require (==1) the TLS server cert matches the hidden name 

#### Returns
1 for success, other otherwise

<p id="esni_8c_1aeef3e81451e59142e5cdec4f26c09fff"><hr></p>

#### `public int `[`SSL_esni_server_enable`](#esni_8c_1aeef3e81451e59142e5cdec4f26c09fff)`(SSL_CTX * s,const char * esnikeyfile,const char * esnipubfile)` 

Turn on SNI Encryption, server-side.

When this works, the server will decrypt any ESNI seen in ClientHellos and subsequently treat those as if they had been send in cleartext SNI.

#### Parameters
* `s` is the SSL server context 

* `esnikeyfile` has the relevant (X25519) private key in PEM format 

* `esnipubfile` has the relevant (binary encoded, not base64) ESNIKeys structure 

#### Returns
1 for success, other otherwise

<p id="esni_8c_1abc2468ba57b69ddaca0344481027d7a1"><hr></p>

#### `public int `[`SSL_get_esni_status`](#esni_8c_1abc2468ba57b69ddaca0344481027d7a1)`(SSL * s,char ** hidden,char ** cover)` 

API to allow calling code know ESNI outcome, post-handshake.

This is intended to be called by applications after the TLS handshake is complete. This works for both client and server. The caller does not have to (and shouldn't) free the hidden or cover strings. TODO: Those are pointers into the SSL struct though so maybe better to allocate fresh ones.

Note that the PR we sent to curl will include a check that this function exists (something like "AC_CHECK_FUNCS( SSL_get_esni_status )" so don't change this name without co-ordinating with that. The curl PR: [https://github.com/curl/curl/pull/4011](https://github.com/curl/curl/pull/4011)

#### Parameters
* `s` The SSL context (if that's the right term) 

* `hidden` will be set to the address of the hidden service 

* `cover` will be set to the address of the hidden service 

#### Returns
1 for success, other otherwise

<p id="esni_8c_1ac4fbad870f00b5b6cb84629c4995be02"><hr></p>

#### `public void `[`SSL_set_esni_callback`](#esni_8c_1ac4fbad870f00b5b6cb84629c4995be02)`(SSL * s,SSL_esni_client_cb_func f)` 

<p id="esni_8c_1a67ce35919f89b9259bb873b7702227ac"><hr></p>

#### `public void `[`SSL_set_esni_callback_ctx`](#esni_8c_1a67ce35919f89b9259bb873b7702227ac)`(SSL_CTX * s,SSL_esni_client_cb_func f)` 

<p id="esni_8c_1ac214a7933d6e5fa9e2be5218b9537a63"><hr></p>

#### `public int `[`SSL_ESNI_get_esni`](#esni_8c_1ac214a7933d6e5fa9e2be5218b9537a63)`(SSL * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)` 

Access an SSL_ESNI structure note - can include sensitive values!

#### Parameters
* `s` is a an SSL structure, as used on TLS client 

* `esni` is an SSL_ESNI structure 

#### Returns
1 for success, anything else for failure

<p id="esni_8c_1acd373a6c0dddd76f399e103e80f538cc"><hr></p>

#### `public int `[`SSL_ESNI_get_esni_ctx`](#esni_8c_1acd373a6c0dddd76f399e103e80f538cc)`(SSL_CTX * s,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** esni)` 

Access an SSL_ESNI structure note - can include sensitive values!

#### Parameters
* `s` is a an SSL_CTX structure, as used on TLS server 

* `esni` is an SSL_ESNI structure 

#### Returns
0 for failure, non-zero is the number of SSL_ESNI in the array

<p id="esni_8c_1a8df1af022d25fc0f7e72683b0bd4667f"><hr></p>

#### `public int `[`SSL_ESNI_set_private`](#esni_8c_1a8df1af022d25fc0f7e72683b0bd4667f)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,char * private_str)` 

Allows caller to set the ECDH private value for ESNI.

This is intended to only be used for interop testing - what was useful was to grab the value from the NSS implemtation, force it into mine and see which of the derived values end up the same.

#### Parameters
* `esni` is the SSL_ESNI struture 

* `private_str` is an ASCII-hex encoded X25519 point (essentially a random 32 octet value:-) 

#### Returns
1 for success, other otherwise

<p id="esni_8c_1a0f48da79909334acee7b24dec440eb4c"><hr></p>

#### `public int `[`SSL_ESNI_set_nonce`](#esni_8c_1a0f48da79909334acee7b24dec440eb4c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * esni,unsigned char * nonce,size_t nlen)` 

Allows caller to set the nonce value for ESNI.

This is intended to only be used for interop testing - what was useful was to grab the value from the NSS implemtation, force it into mine and see which of the derived values end up the same.

#### Parameters
* `esni` is the SSL_ESNI struture 

* `nonce` points to a buffer with the network byte order value  nlen is the size of the nonce buffer 

#### Returns
1 for success, other otherwise

<p id="esni_8c_1a07a28c6e3bb17d0f37f039c25bd7cdfb"><hr></p>

#### `public `[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * `[`SSL_ESNI_dup`](#esni_8c_1a07a28c6e3bb17d0f37f039c25bd7cdfb)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * orig,size_t nesni,int selector)` 

Duplicate the configuration related fields of an SSL_ESNI.

This is needed to handle the SSL_CTX->SSL factory model in the server. Clients don't need this. There aren't too many fields populated when this is called - essentially just the ESNIKeys and the server private value. For the moment, we actually only deep-copy those.

#### Parameters
* `orig` is the input array of SSL_ESNI to be partly deep-copied 

* `nesni` is the number of elements in the array 

* `selector` allows for picking all (ESNI_SELECT_ALL==-1) or just one of the RR values in orig 

#### Returns
a partial deep-copy array or NULL if errors occur

<p id="esni_8c_1a90dc2776e24df4afed11ed5f87f9775c"><hr></p>

#### `public int `[`SSL_esni_query`](#esni_8c_1a90dc2776e24df4afed11ed5f87f9775c)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * in,`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` ** out,int * nindices)` 

query the content of an SSL_ESNI structure

This function allows the application to examine some internals of an SSL_ESNI structure so that it can then down-select some options. In particular, the caller can see the public_name and IP address related information associated with each ESNIKeys RR value (after decoding and initial checking within the library), and can then choose which of the RR value options the application would prefer to use.

#### Parameters
* `in` is the internal form of SSL_ESNI structure 

* `out` is the returned externally array of visible detailed forms of the SSL_ESNI structure 

* `nindices` is an output saying how many indices are in the SSL_ESNI_ext structure 

#### Returns
1 for success, error otherwise

<p id="esni_8c_1ad0558a0a329a96dcd5df41120692e08e"><hr></p>

#### `public void `[`SSL_ESNI_ext_free`](#esni_8c_1ad0558a0a329a96dcd5df41120692e08e)`(`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` * in,int size)` 

free up memory for an SSL_ESNI_ext

#### Parameters
* `in` is the structure to free up 

* `size` says how many indices are in in

<p id="esni_8c_1a5d34c8e2d50475b71c6b386ae27dab61"><hr></p>

#### `public int `[`SSL_esni_reduce`](#esni_8c_1a5d34c8e2d50475b71c6b386ae27dab61)`(`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` * in,int index,`[`SSL_ESNI`](#esni_8h_1afeadfe79a7d92e7978789cc1c4ee3e7f)` ** out)` 

down-select to use of one option with an SSL_ESNI

This allows the caller to select one of the RR values within an SSL_ESNI for later use.

#### Parameters
* `in` is an SSL_ESNI structure with possibly multiple RR values 

* `index` is the index value from an SSL_ESNI_ext produced from the 'in' 

* `out` is a returned SSL_ESNI containing only that indexed RR value 

#### Returns
1 for success, error otherwise

<p id="esni_8c_1ae9c0193105f5bffc743bfd8b9c29b561"><hr></p>

#### `public int `[`SSL_ESNI_ext_print`](#esni_8c_1ae9c0193105f5bffc743bfd8b9c29b561)`(BIO * out,`[`SSL_ESNI_ext`](#esni_8h_1a816a3f63a46cc12e65a0b6ab0fbda411)` * se,int count)` 

utility fnc for application that wants to print an SSL_ESNI_ext

#### Parameters
* `out` is the BIO to use (e.g. stdout/whatever) 

* `se` is a pointer to an SSL_ESNI_ext struture 

* `count` is the number of elements in se 

#### Returns
1 for success, error othewise

<p id="extensions_8c_1a07941fe88fcdb65271ad678cd41e7d57"><hr></p>

#### `public static int `[`init_esni`](#extensions_8c_1a07941fe88fcdb65271ad678cd41e7d57)`(SSL * s,unsigned int context)` 

Just note that esni is not yet done.

<p id="extensions_8c_1a4027805482e89339fd2870f852db4b4e"><hr></p>

#### `public static int `[`final_esni`](#extensions_8c_1a4027805482e89339fd2870f852db4b4e)`(SSL * s,unsigned int context,int sent)` 

check result of esni and return error or ok

<p id="extensions__clnt_8c_1a2454a14e823689509154ca3bfb4cdaea"><hr></p>

#### `public static EXT_RETURN `[`esni_server_name_fixup`](#extensions__clnt_8c_1a2454a14e823689509154ca3bfb4cdaea)`(SSL * s,WPACKET * pkt,unsigned int context,X509 * x,size_t chainidx)` 

Possibly do/don't send SNI if doing ESNI.

Check if s.ext.hostname == s.esni.covername and s.esni.covername != s.esni.encservername (which shouldn't happen ever but who knows...) If either test fails don't send server_name. That is, if we want to send ESNI, then we only send SNI if the covername was explicitly set and is the same as the SNI (that maybe got set via some weirdo application API that we couldn't change when ESNI enabling perhaps)

Draft-03 update: public_name can be set in the ESNIKeys RR and if so, that overrides the locally supplied covername. TODO: Maybe re-consider that.

When the name is fixed up, we record the original encservername, covername and public_name in the SSL_SESSION.ext so that later printing etc. can do the right thing. The ext.hostname will be the one used for keying as if it had been the SNI provided.

#### Parameters
* `s` is the SSL context 

* `pkt` is seemingly unused here 

* `context` is unused here 

* `x` is the certificate associated with the session 

* `chainidx` is unused here 

#### Returns
"send-it" (EXT_RETURN_SENT) or not

<p id="extensions__clnt_8c_1afca936de2d3ae315b5e8b8b200d17462"><hr></p>

#### `public EXT_RETURN `[`tls_construct_ctos_esni`](#extensions__clnt_8c_1afca936de2d3ae315b5e8b8b200d17462)`(SSL * s,WPACKET * pkt,unsigned int context,X509 * x,size_t chainidx)` 

Create the ESNI extension for the ClientHello.

This gets the TLS h/w values needed (client_random, curve_id and TLS h/s key_share) and then calls SSL_ESNI_enc and encodes the resulting CLIENT_ESNI into the ClientHello.

<p id="extensions__clnt_8c_1ac388d56d20b4d3b507e56203f1c08303"><hr></p>

#### `public int `[`tls_parse_stoc_esni`](#extensions__clnt_8c_1ac388d56d20b4d3b507e56203f1c08303)`(SSL * s,PACKET * pkt,unsigned int context,X509 * x,size_t chainidx)` 

Parse and check the ESNI value returned in the EncryptedExtensions to make sure it has the nonce we sent in the ClientHello.

This is just checking the nonce.

<p id="extensions__srvr_8c_1a4a75b5940e39e1b5da10aefc8ed0ac69"><hr></p>

#### `public int `[`tls_parse_ctos_esni`](#extensions__srvr_8c_1a4a75b5940e39e1b5da10aefc8ed0ac69)`(SSL * s,PACKET * pkt,unsigned int context,X509 * x,size_t chainidx)` 

Decodes inbound ESNI extension into SSL_ESNI structure.

The ESNI stuff:

    struct {
       CipherSuite suite; from c->ciphersuite (SSL_CIPHER)
       KeyShareEntry key_share; from c->encoded_keshare (buffer)
       opaque record_digest<0..2^16-1>; from c->record_digest (buffer)
       opaque encrypted_sni<0..2^16-1>; from c->encrypted_sni (buffer)
    } ClientEncryptedSNI;

Parse, decrypt etc inbound ESNI extension.

<p id="extensions__srvr_8c_1ae56ce4660abc014b273c5f743bc3eb63"><hr></p>

#### `public EXT_RETURN `[`tls_construct_stoc_esni`](#extensions__srvr_8c_1ae56ce4660abc014b273c5f743bc3eb63)`(SSL * s,WPACKET * pkt,unsigned int context,X509 * x,size_t chainidx)` 

If ESNI all went well, and we have a nonce then send that back.

Just do the biz... :-)

<p id="structclient__esni__st"><hr></p>

# struct `client_esni_st` 

What we send in the esni CH extension:

The TLS presentation language version is:

    struct {
        CipherSuite suite;
        KeyShareEntry key_share;
        opaque record_digest<0..2^16-1>;
        opaque encrypted_sni<0..2^16-1>;
    } ClientEncryptedSNI;

Fields encoded in extension, these are copies, (not malloc'd) of pointers elsewhere in SSL_ESNI. One of these is returned from SSL_ESNI_enc, and is also pointed to from the SSL_ESNI structure.

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public uint16_t `[`ciphersuite`](#structclient__esni__st_1a9e55dac79113ba355d329f86fbdb7f50) | 
`public size_t `[`encoded_keyshare_len`](#structclient__esni__st_1a5647ef9466b0de060a8fdbadeab16ca9) | 
`public unsigned char * `[`encoded_keyshare`](#structclient__esni__st_1ada7c87c8765f080c25255c336c8f3dd8) | 
`public size_t `[`record_digest_len`](#structclient__esni__st_1ab975fc71e1200e4e15462149377ea18c) | 
`public unsigned char * `[`record_digest`](#structclient__esni__st_1af3490c8abb917246296c8c7ce51106c3) | 
`public size_t `[`encrypted_sni_len`](#structclient__esni__st_1ae2811613d6126039a546db956858db5c) | 
`public unsigned char * `[`encrypted_sni`](#structclient__esni__st_1aafe13f76c23f8743e110c116eaaed174) | 

## Members

<p id="structclient__esni__st_1a9e55dac79113ba355d329f86fbdb7f50"><hr></p>

#### `public uint16_t `[`ciphersuite`](#structclient__esni__st_1a9e55dac79113ba355d329f86fbdb7f50) 

<p id="structclient__esni__st_1a5647ef9466b0de060a8fdbadeab16ca9"><hr></p>

#### `public size_t `[`encoded_keyshare_len`](#structclient__esni__st_1a5647ef9466b0de060a8fdbadeab16ca9) 

<p id="structclient__esni__st_1ada7c87c8765f080c25255c336c8f3dd8"><hr></p>

#### `public unsigned char * `[`encoded_keyshare`](#structclient__esni__st_1ada7c87c8765f080c25255c336c8f3dd8) 

<p id="structclient__esni__st_1ab975fc71e1200e4e15462149377ea18c"><hr></p>

#### `public size_t `[`record_digest_len`](#structclient__esni__st_1ab975fc71e1200e4e15462149377ea18c) 

<p id="structclient__esni__st_1af3490c8abb917246296c8c7ce51106c3"><hr></p>

#### `public unsigned char * `[`record_digest`](#structclient__esni__st_1af3490c8abb917246296c8c7ce51106c3) 

<p id="structclient__esni__st_1ae2811613d6126039a546db956858db5c"><hr></p>

#### `public size_t `[`encrypted_sni_len`](#structclient__esni__st_1ae2811613d6126039a546db956858db5c) 

<p id="structclient__esni__st_1aafe13f76c23f8743e110c116eaaed174"><hr></p>

#### `public unsigned char * `[`encrypted_sni`](#structclient__esni__st_1aafe13f76c23f8743e110c116eaaed174) 

<p id="structesni__padding__sizes"><hr></p>

# struct `esni_padding_sizes` 

Padding size info.

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public size_t `[`certpad`](#structesni__padding__sizes_1a8ea988832a757092b11f1b2d6acc8d98) | Certificate messages to be a multiple of this size.
`public size_t `[`certverifypad`](#structesni__padding__sizes_1ae573edaa1c0c0f2fc7aea357d606b83a) | CertificateVerify messages to be a multiple of this size.

## Members

<p id="structesni__padding__sizes_1a8ea988832a757092b11f1b2d6acc8d98"><hr></p>

#### `public size_t `[`certpad`](#structesni__padding__sizes_1a8ea988832a757092b11f1b2d6acc8d98) 

Certificate messages to be a multiple of this size.

<p id="structesni__padding__sizes_1ae573edaa1c0c0f2fc7aea357d606b83a"><hr></p>

#### `public size_t `[`certverifypad`](#structesni__padding__sizes_1ae573edaa1c0c0f2fc7aea357d606b83a) 

CertificateVerify messages to be a multiple of this size.

<p id="structesni__record__st"><hr></p>

# struct `esni_record_st` 

Representation of what goes in DNS.

This is from the -02 I-D, in TLS presentation language:

    struct {
        uint16 version;
        uint8 checksum[4];
        KeyShareEntry keys<4..2^16-1>;
        CipherSuite cipher_suites<2..2^16-2>;
        uint16 padded_length;
        uint64 not_before;
        uint64 not_after;
        Extension extensions<0..2^16-1>;
    } ESNIKeys;

Note that I don't like the above, but it's what we have to work with at the moment.

This structure is purely used when decoding the RR value and is then discarded (selected values mapped into the SSL_ESNI structure).

draft-03 changed this some ... 
 struct {
        uint16 version;
        uint8 checksum[4];
        opaque public_name<1..2^16-1>;
        KeyShareEntry keys<4..2^16-1>;
        CipherSuite cipher_suites<2..2^16-2>;
        uint16 padded_length;
        uint64 not_before;
        uint64 not_after;
        Extension extensions<0..2^16-1>;
    } ESNIKeys;

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public unsigned int `[`version`](#structesni__record__st_1aa3c5b36b02f8154f6ced8a36f04d25c3) | 
`public unsigned char `[`checksum`](#structesni__record__st_1a2280cfc2817e94b494a3e120a44c82b3) | 
`public int `[`public_name_len`](#structesni__record__st_1ad7e7cf7be5d35bd2af14105d89939d3e) | 
`public unsigned char * `[`public_name`](#structesni__record__st_1a8b811666edfa88ad9e76970caaaabfbe) | 
`public unsigned int `[`nkeys`](#structesni__record__st_1a128d54ebb6abfe2494da42b5706795d3) | 
`public uint16_t * `[`group_ids`](#structesni__record__st_1a323df5cbace94f73e1bbf922fb3cf64d) | 
`public EVP_PKEY ** `[`keys`](#structesni__record__st_1abc46d13be54f79110778946df8defbc6) | 
`public size_t * `[`encoded_lens`](#structesni__record__st_1ac6ab8f5ea17c69c4bd4bf51be55e30d3) | 
`public unsigned char ** `[`encoded_keys`](#structesni__record__st_1abe59c6e8bf0ff07cb3e4f185fabe1b07) | 
`public size_t `[`nsuites`](#structesni__record__st_1a221e917cb9ad6f6501a57330d13e5084) | 
`public uint16_t * `[`ciphersuites`](#structesni__record__st_1ae6845bbe19a868942f0125cc4007e48c) | 
`public unsigned int `[`padded_length`](#structesni__record__st_1a4fa1f10a8635d5dfed501815f928570d) | 
`public uint64_t `[`not_before`](#structesni__record__st_1a4db76296d4da4dd2c202ced371859a29) | 
`public uint64_t `[`not_after`](#structesni__record__st_1ae9ee01b4d38d36242d8f4300d98416e9) | 
`public unsigned int `[`nexts`](#structesni__record__st_1ad0ae17a1a37af37fae9d8a70ea74a996) | 
`public unsigned int * `[`exttypes`](#structesni__record__st_1a12b5bdb880a6b035a62a62e297809ad0) | 
`public size_t * `[`extlens`](#structesni__record__st_1a7f30a1ba6862cf5a7946a5d414b54cec) | 
`public unsigned char ** `[`exts`](#structesni__record__st_1ae537bfe960ef7d7d16cfc6f04e468bc3) | 

## Members

<p id="structesni__record__st_1aa3c5b36b02f8154f6ced8a36f04d25c3"><hr></p>

#### `public unsigned int `[`version`](#structesni__record__st_1aa3c5b36b02f8154f6ced8a36f04d25c3) 

<p id="structesni__record__st_1a2280cfc2817e94b494a3e120a44c82b3"><hr></p>

#### `public unsigned char `[`checksum`](#structesni__record__st_1a2280cfc2817e94b494a3e120a44c82b3) 

<p id="structesni__record__st_1ad7e7cf7be5d35bd2af14105d89939d3e"><hr></p>

#### `public int `[`public_name_len`](#structesni__record__st_1ad7e7cf7be5d35bd2af14105d89939d3e) 

<p id="structesni__record__st_1a8b811666edfa88ad9e76970caaaabfbe"><hr></p>

#### `public unsigned char * `[`public_name`](#structesni__record__st_1a8b811666edfa88ad9e76970caaaabfbe) 

<p id="structesni__record__st_1a128d54ebb6abfe2494da42b5706795d3"><hr></p>

#### `public unsigned int `[`nkeys`](#structesni__record__st_1a128d54ebb6abfe2494da42b5706795d3) 

<p id="structesni__record__st_1a323df5cbace94f73e1bbf922fb3cf64d"><hr></p>

#### `public uint16_t * `[`group_ids`](#structesni__record__st_1a323df5cbace94f73e1bbf922fb3cf64d) 

<p id="structesni__record__st_1abc46d13be54f79110778946df8defbc6"><hr></p>

#### `public EVP_PKEY ** `[`keys`](#structesni__record__st_1abc46d13be54f79110778946df8defbc6) 

<p id="structesni__record__st_1ac6ab8f5ea17c69c4bd4bf51be55e30d3"><hr></p>

#### `public size_t * `[`encoded_lens`](#structesni__record__st_1ac6ab8f5ea17c69c4bd4bf51be55e30d3) 

<p id="structesni__record__st_1abe59c6e8bf0ff07cb3e4f185fabe1b07"><hr></p>

#### `public unsigned char ** `[`encoded_keys`](#structesni__record__st_1abe59c6e8bf0ff07cb3e4f185fabe1b07) 

<p id="structesni__record__st_1a221e917cb9ad6f6501a57330d13e5084"><hr></p>

#### `public size_t `[`nsuites`](#structesni__record__st_1a221e917cb9ad6f6501a57330d13e5084) 

<p id="structesni__record__st_1ae6845bbe19a868942f0125cc4007e48c"><hr></p>

#### `public uint16_t * `[`ciphersuites`](#structesni__record__st_1ae6845bbe19a868942f0125cc4007e48c) 

<p id="structesni__record__st_1a4fa1f10a8635d5dfed501815f928570d"><hr></p>

#### `public unsigned int `[`padded_length`](#structesni__record__st_1a4fa1f10a8635d5dfed501815f928570d) 

<p id="structesni__record__st_1a4db76296d4da4dd2c202ced371859a29"><hr></p>

#### `public uint64_t `[`not_before`](#structesni__record__st_1a4db76296d4da4dd2c202ced371859a29) 

<p id="structesni__record__st_1ae9ee01b4d38d36242d8f4300d98416e9"><hr></p>

#### `public uint64_t `[`not_after`](#structesni__record__st_1ae9ee01b4d38d36242d8f4300d98416e9) 

<p id="structesni__record__st_1ad0ae17a1a37af37fae9d8a70ea74a996"><hr></p>

#### `public unsigned int `[`nexts`](#structesni__record__st_1ad0ae17a1a37af37fae9d8a70ea74a996) 

<p id="structesni__record__st_1a12b5bdb880a6b035a62a62e297809ad0"><hr></p>

#### `public unsigned int * `[`exttypes`](#structesni__record__st_1a12b5bdb880a6b035a62a62e297809ad0) 

<p id="structesni__record__st_1a7f30a1ba6862cf5a7946a5d414b54cec"><hr></p>

#### `public size_t * `[`extlens`](#structesni__record__st_1a7f30a1ba6862cf5a7946a5d414b54cec) 

<p id="structesni__record__st_1ae537bfe960ef7d7d16cfc6f04e468bc3"><hr></p>

#### `public unsigned char ** `[`exts`](#structesni__record__st_1ae537bfe960ef7d7d16cfc6f04e468bc3) 

<p id="structssl__esni__ext__st"><hr></p>

# struct `ssl_esni_ext_st` 

Exterally visible form of an ESNIKeys RR value.

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public int `[`index`](#structssl__esni__ext__st_1a27accbaa2a709437a3b50d4902eca321) | externally re-usable reference to this RR value
`public char * `[`public_name`](#structssl__esni__ext__st_1a57b914b05b49fab55294005ef5adc8b7) | public_name from ESNIKeys
`public char * `[`prefixes`](#structssl__esni__ext__st_1a9b99b3bc8a79e6f408df79860d8a918f) | comman seperated list of IP address prefixes, in CIDR form
`public uint64_t `[`not_before`](#structssl__esni__ext__st_1a8ee5d62612efe6b7a1ecb6df8ed4c389) | from ESNIKeys (not currently used)
`public uint64_t `[`not_after`](#structssl__esni__ext__st_1a9c32fd4d4773626fa4e95f127922c2a3) | from ESNIKeys (not currently used)

## Members

<p id="structssl__esni__ext__st_1a27accbaa2a709437a3b50d4902eca321"><hr></p>

#### `public int `[`index`](#structssl__esni__ext__st_1a27accbaa2a709437a3b50d4902eca321) 

externally re-usable reference to this RR value

<p id="structssl__esni__ext__st_1a57b914b05b49fab55294005ef5adc8b7"><hr></p>

#### `public char * `[`public_name`](#structssl__esni__ext__st_1a57b914b05b49fab55294005ef5adc8b7) 

public_name from ESNIKeys

<p id="structssl__esni__ext__st_1a9b99b3bc8a79e6f408df79860d8a918f"><hr></p>

#### `public char * `[`prefixes`](#structssl__esni__ext__st_1a9b99b3bc8a79e6f408df79860d8a918f) 

comman seperated list of IP address prefixes, in CIDR form

<p id="structssl__esni__ext__st_1a8ee5d62612efe6b7a1ecb6df8ed4c389"><hr></p>

#### `public uint64_t `[`not_before`](#structssl__esni__ext__st_1a8ee5d62612efe6b7a1ecb6df8ed4c389) 

from ESNIKeys (not currently used)

<p id="structssl__esni__ext__st_1a9c32fd4d4773626fa4e95f127922c2a3"><hr></p>

#### `public uint64_t `[`not_after`](#structssl__esni__ext__st_1a9c32fd4d4773626fa4e95f127922c2a3) 

from ESNIKeys (not currently used)

<p id="structssl__esni__st"><hr></p>

# struct `ssl_esni_st` 

The ESNI data structure that's part of the SSL structure.

On the client-side, one of these is part of the SSL structure. On the server-side, an array of these is part of the SSL_CTX structure, and we match one of 'em to be part of the SSL structure when a handshake is in porgress. (Well, hopefully:-)

Note that SSL_ESNI_dup copies all these fields (when values are set), so if you add, change or remove a field here, you'll also need to modify that (in ssl/esni.c)

## Summary

 Members                        | Descriptions                                
--------------------------------|---------------------------------------------
`public unsigned int `[`version`](#structssl__esni__st_1ad6a09746b7482663c81449c6a59014b2) | version from underlying ESNI_RECORD/ESNIKeys
`public char * `[`encservername`](#structssl__esni__st_1a2468815c9c565e18fd3c3bbe8deb5ac9) | hidden server name
`public char * `[`covername`](#structssl__esni__st_1a97b71311959fbdb7cd424106c9e2afab) | cleartext SNI (can be NULL)
`public char * `[`public_name`](#structssl__esni__st_1ae390b90be4f317d868c79663ff47fb32) | public_name from ESNIKeys
`public int `[`require_hidden_match`](#structssl__esni__st_1a37524b2d52a46fa9df7193a2efcae39c) | If 1 then SSL_get_esni_status will barf if hidden name doesn't match TLS server cert. If 0, don't care.
`public int `[`num_esni_rrs`](#structssl__esni__st_1ab35546dfbb3ae44803e148bfef39c9d0) | the number of ESNIKeys structures in this array
`public size_t `[`encoded_rr_len`](#structssl__esni__st_1a27ada5b21000aeb74ca5ed8e76bca329) | 
`public unsigned char * `[`encoded_rr`](#structssl__esni__st_1a71c8c509c7d198e8a719c65f99137f42) | Binary (base64 decoded) RR value.
`public size_t `[`rd_len`](#structssl__esni__st_1a14dda82e4a3ff57fe2dc856e67a2c971) | 
`public unsigned char * `[`rd`](#structssl__esni__st_1a40750765b83b53e6b12c24d580dc6894) | Hash of the above (record_digest), using the relevant hash from the ciphersuite.
`public uint16_t `[`ciphersuite`](#structssl__esni__st_1abc06fe1b51acac92401d48fee0c97d1b) | from ESNIKeys after selection of local preference
`public uint16_t `[`group_id`](#structssl__esni__st_1ac47e519775c29bd9129eba95cbed25f9) | our chosen group e.g. X25519
`public size_t `[`esni_peer_keyshare_len`](#structssl__esni__st_1a45018bd6c55f58e594463ce17e6e96bb) | 
`public unsigned char * `[`esni_peer_keyshare`](#structssl__esni__st_1a45058e28bb36447e277246e7d382e8cd) | the encoded peer's public value
`public EVP_PKEY * `[`esni_peer_pkey`](#structssl__esni__st_1ae309319de3d8979b8f650567511b5db9) | the peer public as a key
`public size_t `[`padded_length`](#structssl__esni__st_1adf84b36cfa57d84629cac876c5330ba8) | from ESNIKeys
`public uint64_t `[`not_before`](#structssl__esni__st_1a4cb0d34f50b80a38964af87c544f7ce9) | from ESNIKeys (not currently used)
`public uint64_t `[`not_after`](#structssl__esni__st_1ac6d2a892f59c287cc6ee7aa35f23c593) | from ESNIKeys (not currently used)
`public int `[`nexts`](#structssl__esni__st_1ad378e22df57746ad53996b3557ad8b84) | number of extensions (not yet supported so >0 => fail)
`public unsigned int * `[`exttypes`](#structssl__esni__st_1aed5ab577a0c090aecbd9571f712e8e86) | array of extension types
`public size_t * `[`extlens`](#structssl__esni__st_1aea13d9bef126ae321be21787ecbe12ad) | lengths of encoded extension octets
`public unsigned char ** `[`exts`](#structssl__esni__st_1aad3d2ead608e77f15fb27e98f1cdc2b7) | encoded extension octets
`public int `[`naddrs`](#structssl__esni__st_1a0325c20968f9cdb6599b8b5f82c9f4a2) | decoded AddressSet cardinality
`public BIO_ADDR * `[`addrs`](#structssl__esni__st_1a18f970d19d72329586f86f7a87b999af) | decoded AddressSet values (v4 or v6)
`public size_t `[`nonce_len`](#structssl__esni__st_1aa3e7c7adffc576490b12cb397398e9e4) | 
`public unsigned char * `[`nonce`](#structssl__esni__st_1a1b1a621faf0c5661d399f74a15f53ff4) | Nonce we challenge server to respond with.
`public size_t `[`hs_cr_len`](#structssl__esni__st_1a60c77ce40536a46dd82d534e305c841d) | 
`public unsigned char * `[`hs_cr`](#structssl__esni__st_1a41cc4a76f8c5791c2d56cda576f99b2e) | Client random from TLS h/s.
`public size_t `[`hs_kse_len`](#structssl__esni__st_1aaa28d8aae330ffb7d54690362dbbd099) | 
`public unsigned char * `[`hs_kse`](#structssl__esni__st_1ace5b1a36ef299d60894e6c12fb87efa8) | Client key share from TLS h/s.
`public EVP_PKEY * `[`keyshare`](#structssl__esni__st_1a26fe847e4d6ef31e052388db50ea6dfe) | my own private keyshare to use with server's ESNI share
`public size_t `[`encoded_keyshare_len`](#structssl__esni__st_1a996ba562dc4023f24f5f7b9e06cf7ea9) | 
`public unsigned char * `[`encoded_keyshare`](#structssl__esni__st_1a4d01bbfec69faa47688893bf97c3d517) | my own public key share
`public size_t `[`hi_len`](#structssl__esni__st_1a736fa2d396148e03dda2b6f16bf2f2b3) | 
`public unsigned char * `[`hi`](#structssl__esni__st_1a4a90ef99a66189196461a24be3228e88) | ESNIContent encoded (hash input)
`public size_t `[`hash_len`](#structssl__esni__st_1adc8cd5f2e038050f8f8c943ce83a69e7) | 
`public unsigned char * `[`hash`](#structssl__esni__st_1a13aa60c6ec57e21c72f3ad9a08501de0) | hash of hi (encoded ESNIContent)
`public size_t `[`realSNI_len`](#structssl__esni__st_1a6908a094db5191657c7215fc53c07cac) | 
`public unsigned char * `[`realSNI`](#structssl__esni__st_1a13b4a4088c85d54354a4d0b762b6ecf1) | padded ESNI
`public size_t `[`Z_len`](#structssl__esni__st_1a7481a2e9fa19146dc73daa985ab48299) | 
`public unsigned char * `[`Z`](#structssl__esni__st_1a34834976fb049c9648199f4d5d30ce5a) | ECDH shared secret.
`public size_t `[`Zx_len`](#structssl__esni__st_1a32851db584691fef7515514c3633cd10) | 
`public unsigned char * `[`Zx`](#structssl__esni__st_1a0e7f1692a4a10d5f4379ba416dfc8f9b) | derived from Z as per I-D
`public size_t `[`key_len`](#structssl__esni__st_1a2ba57f56ad092ad7aa99d1bf13c7ba4f) | 
`public unsigned char * `[`key`](#structssl__esni__st_1a82a0329090f1e41c1f194b965649c578) | derived key
`public size_t `[`iv_len`](#structssl__esni__st_1a860a6a8162ff52d946e501f70cb8cab3) | 
`public unsigned char * `[`iv`](#structssl__esni__st_1a68620bc395b1faeefd4ff616c987a762) | derived iv
`public size_t `[`aad_len`](#structssl__esni__st_1a3293081d097ffe98ee954fad33da1527) | 
`public unsigned char * `[`aad`](#structssl__esni__st_1a047ff937dc8738a348c38a1430d2a748) | derived aad
`public size_t `[`plain_len`](#structssl__esni__st_1a16cf3490d5e685f020d4b0dfebae20b4) | 
`public unsigned char * `[`plain`](#structssl__esni__st_1a8138dff60c8e4b4aefa3fca687071c72) | plaintext value for ESNI
`public size_t `[`cipher_len`](#structssl__esni__st_1ad8cff17bc628d23a8f07f222faea037b) | 
`public unsigned char * `[`cipher`](#structssl__esni__st_1a19d1bfe34738bd14d62c5f98d25ed9d8) | ciphetext value of ESNI
`public size_t `[`tag_len`](#structssl__esni__st_1a422257e7b151614e7873443572e380af) | 
`public unsigned char * `[`tag`](#structssl__esni__st_1ae12ddfc5fb31d43b68c9febca9730e94) | GCM tag (already also in ciphertext)
`public char * `[`private_str`](#structssl__esni__st_1ab623dc6359f2c62ade27719be580c438) | for debug purposes, requires special build
`public `[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` * `[`the_esni`](#structssl__esni__st_1acc1e4d390a3f6fc96c52a10cac4fd6c1) | the final outputs for the caller (note: not separately alloc'd)

## Members

<p id="structssl__esni__st_1ad6a09746b7482663c81449c6a59014b2"><hr></p>

#### `public unsigned int `[`version`](#structssl__esni__st_1ad6a09746b7482663c81449c6a59014b2) 

version from underlying ESNI_RECORD/ESNIKeys

<p id="structssl__esni__st_1a2468815c9c565e18fd3c3bbe8deb5ac9"><hr></p>

#### `public char * `[`encservername`](#structssl__esni__st_1a2468815c9c565e18fd3c3bbe8deb5ac9) 

hidden server name

<p id="structssl__esni__st_1a97b71311959fbdb7cd424106c9e2afab"><hr></p>

#### `public char * `[`covername`](#structssl__esni__st_1a97b71311959fbdb7cd424106c9e2afab) 

cleartext SNI (can be NULL)

<p id="structssl__esni__st_1ae390b90be4f317d868c79663ff47fb32"><hr></p>

#### `public char * `[`public_name`](#structssl__esni__st_1ae390b90be4f317d868c79663ff47fb32) 

public_name from ESNIKeys

<p id="structssl__esni__st_1a37524b2d52a46fa9df7193a2efcae39c"><hr></p>

#### `public int `[`require_hidden_match`](#structssl__esni__st_1a37524b2d52a46fa9df7193a2efcae39c) 

If 1 then SSL_get_esni_status will barf if hidden name doesn't match TLS server cert. If 0, don't care.

<p id="structssl__esni__st_1ab35546dfbb3ae44803e148bfef39c9d0"><hr></p>

#### `public int `[`num_esni_rrs`](#structssl__esni__st_1ab35546dfbb3ae44803e148bfef39c9d0) 

the number of ESNIKeys structures in this array

<p id="structssl__esni__st_1a27ada5b21000aeb74ca5ed8e76bca329"><hr></p>

#### `public size_t `[`encoded_rr_len`](#structssl__esni__st_1a27ada5b21000aeb74ca5ed8e76bca329) 

<p id="structssl__esni__st_1a71c8c509c7d198e8a719c65f99137f42"><hr></p>

#### `public unsigned char * `[`encoded_rr`](#structssl__esni__st_1a71c8c509c7d198e8a719c65f99137f42) 

Binary (base64 decoded) RR value.

<p id="structssl__esni__st_1a14dda82e4a3ff57fe2dc856e67a2c971"><hr></p>

#### `public size_t `[`rd_len`](#structssl__esni__st_1a14dda82e4a3ff57fe2dc856e67a2c971) 

<p id="structssl__esni__st_1a40750765b83b53e6b12c24d580dc6894"><hr></p>

#### `public unsigned char * `[`rd`](#structssl__esni__st_1a40750765b83b53e6b12c24d580dc6894) 

Hash of the above (record_digest), using the relevant hash from the ciphersuite.

<p id="structssl__esni__st_1abc06fe1b51acac92401d48fee0c97d1b"><hr></p>

#### `public uint16_t `[`ciphersuite`](#structssl__esni__st_1abc06fe1b51acac92401d48fee0c97d1b) 

from ESNIKeys after selection of local preference

<p id="structssl__esni__st_1ac47e519775c29bd9129eba95cbed25f9"><hr></p>

#### `public uint16_t `[`group_id`](#structssl__esni__st_1ac47e519775c29bd9129eba95cbed25f9) 

our chosen group e.g. X25519

<p id="structssl__esni__st_1a45018bd6c55f58e594463ce17e6e96bb"><hr></p>

#### `public size_t `[`esni_peer_keyshare_len`](#structssl__esni__st_1a45018bd6c55f58e594463ce17e6e96bb) 

<p id="structssl__esni__st_1a45058e28bb36447e277246e7d382e8cd"><hr></p>

#### `public unsigned char * `[`esni_peer_keyshare`](#structssl__esni__st_1a45058e28bb36447e277246e7d382e8cd) 

the encoded peer's public value

<p id="structssl__esni__st_1ae309319de3d8979b8f650567511b5db9"><hr></p>

#### `public EVP_PKEY * `[`esni_peer_pkey`](#structssl__esni__st_1ae309319de3d8979b8f650567511b5db9) 

the peer public as a key

<p id="structssl__esni__st_1adf84b36cfa57d84629cac876c5330ba8"><hr></p>

#### `public size_t `[`padded_length`](#structssl__esni__st_1adf84b36cfa57d84629cac876c5330ba8) 

from ESNIKeys

<p id="structssl__esni__st_1a4cb0d34f50b80a38964af87c544f7ce9"><hr></p>

#### `public uint64_t `[`not_before`](#structssl__esni__st_1a4cb0d34f50b80a38964af87c544f7ce9) 

from ESNIKeys (not currently used)

<p id="structssl__esni__st_1ac6d2a892f59c287cc6ee7aa35f23c593"><hr></p>

#### `public uint64_t `[`not_after`](#structssl__esni__st_1ac6d2a892f59c287cc6ee7aa35f23c593) 

from ESNIKeys (not currently used)

<p id="structssl__esni__st_1ad378e22df57746ad53996b3557ad8b84"><hr></p>

#### `public int `[`nexts`](#structssl__esni__st_1ad378e22df57746ad53996b3557ad8b84) 

number of extensions (not yet supported so >0 => fail)

<p id="structssl__esni__st_1aed5ab577a0c090aecbd9571f712e8e86"><hr></p>

#### `public unsigned int * `[`exttypes`](#structssl__esni__st_1aed5ab577a0c090aecbd9571f712e8e86) 

array of extension types

<p id="structssl__esni__st_1aea13d9bef126ae321be21787ecbe12ad"><hr></p>

#### `public size_t * `[`extlens`](#structssl__esni__st_1aea13d9bef126ae321be21787ecbe12ad) 

lengths of encoded extension octets

<p id="structssl__esni__st_1aad3d2ead608e77f15fb27e98f1cdc2b7"><hr></p>

#### `public unsigned char ** `[`exts`](#structssl__esni__st_1aad3d2ead608e77f15fb27e98f1cdc2b7) 

encoded extension octets

<p id="structssl__esni__st_1a0325c20968f9cdb6599b8b5f82c9f4a2"><hr></p>

#### `public int `[`naddrs`](#structssl__esni__st_1a0325c20968f9cdb6599b8b5f82c9f4a2) 

decoded AddressSet cardinality

<p id="structssl__esni__st_1a18f970d19d72329586f86f7a87b999af"><hr></p>

#### `public BIO_ADDR * `[`addrs`](#structssl__esni__st_1a18f970d19d72329586f86f7a87b999af) 

decoded AddressSet values (v4 or v6)

<p id="structssl__esni__st_1aa3e7c7adffc576490b12cb397398e9e4"><hr></p>

#### `public size_t `[`nonce_len`](#structssl__esni__st_1aa3e7c7adffc576490b12cb397398e9e4) 

<p id="structssl__esni__st_1a1b1a621faf0c5661d399f74a15f53ff4"><hr></p>

#### `public unsigned char * `[`nonce`](#structssl__esni__st_1a1b1a621faf0c5661d399f74a15f53ff4) 

Nonce we challenge server to respond with.

<p id="structssl__esni__st_1a60c77ce40536a46dd82d534e305c841d"><hr></p>

#### `public size_t `[`hs_cr_len`](#structssl__esni__st_1a60c77ce40536a46dd82d534e305c841d) 

<p id="structssl__esni__st_1a41cc4a76f8c5791c2d56cda576f99b2e"><hr></p>

#### `public unsigned char * `[`hs_cr`](#structssl__esni__st_1a41cc4a76f8c5791c2d56cda576f99b2e) 

Client random from TLS h/s.

<p id="structssl__esni__st_1aaa28d8aae330ffb7d54690362dbbd099"><hr></p>

#### `public size_t `[`hs_kse_len`](#structssl__esni__st_1aaa28d8aae330ffb7d54690362dbbd099) 

<p id="structssl__esni__st_1ace5b1a36ef299d60894e6c12fb87efa8"><hr></p>

#### `public unsigned char * `[`hs_kse`](#structssl__esni__st_1ace5b1a36ef299d60894e6c12fb87efa8) 

Client key share from TLS h/s.

<p id="structssl__esni__st_1a26fe847e4d6ef31e052388db50ea6dfe"><hr></p>

#### `public EVP_PKEY * `[`keyshare`](#structssl__esni__st_1a26fe847e4d6ef31e052388db50ea6dfe) 

my own private keyshare to use with server's ESNI share

<p id="structssl__esni__st_1a996ba562dc4023f24f5f7b9e06cf7ea9"><hr></p>

#### `public size_t `[`encoded_keyshare_len`](#structssl__esni__st_1a996ba562dc4023f24f5f7b9e06cf7ea9) 

<p id="structssl__esni__st_1a4d01bbfec69faa47688893bf97c3d517"><hr></p>

#### `public unsigned char * `[`encoded_keyshare`](#structssl__esni__st_1a4d01bbfec69faa47688893bf97c3d517) 

my own public key share

<p id="structssl__esni__st_1a736fa2d396148e03dda2b6f16bf2f2b3"><hr></p>

#### `public size_t `[`hi_len`](#structssl__esni__st_1a736fa2d396148e03dda2b6f16bf2f2b3) 

<p id="structssl__esni__st_1a4a90ef99a66189196461a24be3228e88"><hr></p>

#### `public unsigned char * `[`hi`](#structssl__esni__st_1a4a90ef99a66189196461a24be3228e88) 

ESNIContent encoded (hash input)

<p id="structssl__esni__st_1adc8cd5f2e038050f8f8c943ce83a69e7"><hr></p>

#### `public size_t `[`hash_len`](#structssl__esni__st_1adc8cd5f2e038050f8f8c943ce83a69e7) 

<p id="structssl__esni__st_1a13aa60c6ec57e21c72f3ad9a08501de0"><hr></p>

#### `public unsigned char * `[`hash`](#structssl__esni__st_1a13aa60c6ec57e21c72f3ad9a08501de0) 

hash of hi (encoded ESNIContent)

<p id="structssl__esni__st_1a6908a094db5191657c7215fc53c07cac"><hr></p>

#### `public size_t `[`realSNI_len`](#structssl__esni__st_1a6908a094db5191657c7215fc53c07cac) 

<p id="structssl__esni__st_1a13b4a4088c85d54354a4d0b762b6ecf1"><hr></p>

#### `public unsigned char * `[`realSNI`](#structssl__esni__st_1a13b4a4088c85d54354a4d0b762b6ecf1) 

padded ESNI

<p id="structssl__esni__st_1a7481a2e9fa19146dc73daa985ab48299"><hr></p>

#### `public size_t `[`Z_len`](#structssl__esni__st_1a7481a2e9fa19146dc73daa985ab48299) 

<p id="structssl__esni__st_1a34834976fb049c9648199f4d5d30ce5a"><hr></p>

#### `public unsigned char * `[`Z`](#structssl__esni__st_1a34834976fb049c9648199f4d5d30ce5a) 

ECDH shared secret.

<p id="structssl__esni__st_1a32851db584691fef7515514c3633cd10"><hr></p>

#### `public size_t `[`Zx_len`](#structssl__esni__st_1a32851db584691fef7515514c3633cd10) 

<p id="structssl__esni__st_1a0e7f1692a4a10d5f4379ba416dfc8f9b"><hr></p>

#### `public unsigned char * `[`Zx`](#structssl__esni__st_1a0e7f1692a4a10d5f4379ba416dfc8f9b) 

derived from Z as per I-D

<p id="structssl__esni__st_1a2ba57f56ad092ad7aa99d1bf13c7ba4f"><hr></p>

#### `public size_t `[`key_len`](#structssl__esni__st_1a2ba57f56ad092ad7aa99d1bf13c7ba4f) 

<p id="structssl__esni__st_1a82a0329090f1e41c1f194b965649c578"><hr></p>

#### `public unsigned char * `[`key`](#structssl__esni__st_1a82a0329090f1e41c1f194b965649c578) 

derived key

<p id="structssl__esni__st_1a860a6a8162ff52d946e501f70cb8cab3"><hr></p>

#### `public size_t `[`iv_len`](#structssl__esni__st_1a860a6a8162ff52d946e501f70cb8cab3) 

<p id="structssl__esni__st_1a68620bc395b1faeefd4ff616c987a762"><hr></p>

#### `public unsigned char * `[`iv`](#structssl__esni__st_1a68620bc395b1faeefd4ff616c987a762) 

derived iv

<p id="structssl__esni__st_1a3293081d097ffe98ee954fad33da1527"><hr></p>

#### `public size_t `[`aad_len`](#structssl__esni__st_1a3293081d097ffe98ee954fad33da1527) 

<p id="structssl__esni__st_1a047ff937dc8738a348c38a1430d2a748"><hr></p>

#### `public unsigned char * `[`aad`](#structssl__esni__st_1a047ff937dc8738a348c38a1430d2a748) 

derived aad

<p id="structssl__esni__st_1a16cf3490d5e685f020d4b0dfebae20b4"><hr></p>

#### `public size_t `[`plain_len`](#structssl__esni__st_1a16cf3490d5e685f020d4b0dfebae20b4) 

<p id="structssl__esni__st_1a8138dff60c8e4b4aefa3fca687071c72"><hr></p>

#### `public unsigned char * `[`plain`](#structssl__esni__st_1a8138dff60c8e4b4aefa3fca687071c72) 

plaintext value for ESNI

<p id="structssl__esni__st_1ad8cff17bc628d23a8f07f222faea037b"><hr></p>

#### `public size_t `[`cipher_len`](#structssl__esni__st_1ad8cff17bc628d23a8f07f222faea037b) 

<p id="structssl__esni__st_1a19d1bfe34738bd14d62c5f98d25ed9d8"><hr></p>

#### `public unsigned char * `[`cipher`](#structssl__esni__st_1a19d1bfe34738bd14d62c5f98d25ed9d8) 

ciphetext value of ESNI

<p id="structssl__esni__st_1a422257e7b151614e7873443572e380af"><hr></p>

#### `public size_t `[`tag_len`](#structssl__esni__st_1a422257e7b151614e7873443572e380af) 

<p id="structssl__esni__st_1ae12ddfc5fb31d43b68c9febca9730e94"><hr></p>

#### `public unsigned char * `[`tag`](#structssl__esni__st_1ae12ddfc5fb31d43b68c9febca9730e94) 

GCM tag (already also in ciphertext)

<p id="structssl__esni__st_1ab623dc6359f2c62ade27719be580c438"><hr></p>

#### `public char * `[`private_str`](#structssl__esni__st_1ab623dc6359f2c62ade27719be580c438) 

for debug purposes, requires special build

<p id="structssl__esni__st_1acc1e4d390a3f6fc96c52a10cac4fd6c1"><hr></p>

#### `public `[`CLIENT_ESNI`](#esni_8h_1add3c7579c9f0d7bd5959b37f9c017461)` * `[`the_esni`](#structssl__esni__st_1acc1e4d390a3f6fc96c52a10cac4fd6c1) 

the final outputs for the caller (note: not separately alloc'd)

Generated by [Moxygen](https://sourcey.com/moxygen)