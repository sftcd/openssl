struct ssl_connection_st {
    /* type identifier and common data */
    struct ssl_st ssl;
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;
    /*
     * There are 2 BIO's even though they are normally both the same.  This
     * is so data can be read and written to different handlers
     */
    /* used by SSL_read */
    BIO *rbio;
    /* used by SSL_write */
    BIO *wbio;
    /* used during session-id reuse to concatenate messages */
    BIO *bbio;
    /*
     * This holds a variable that indicates what we were doing when a 0 or -1
     * is returned.  This is needed for non-blocking IO so we know what
     * request needs re-doing when in SSL_accept or SSL_connect
     */
    int rwstate;
    int (*handshake_func) (SSL *);
    /*
     * Imagine that here's a boolean member "init" that is switched as soon
     * as SSL_set_{accept/connect}_state is called for the first time, so
     * that "state" and "handshake_func" are properly initialized.  But as
     * handshake_func is == 0 until then, we use this test instead of an
     * "init" member.
     */
    /* are we the server side? */
    int server;
    /*
     * Generate a new session or reuse an old one.
     * NB: For servers, the 'new' session may actually be a previously
     * cached session or even the previous session unless
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set
     */
    int new_session;
    /* don't send shutdown packets */
    int quiet_shutdown;
    /* we have shut things down, 0x01 sent, 0x02 for received */
    int shutdown;
    /* Timestamps used to calculate the handshake RTT */
    OSSL_TIME ts_msg_write;
    OSSL_TIME ts_msg_read;
    /* where we are */
    OSSL_STATEM statem;
    SSL_EARLY_DATA_STATE early_data_state;
    BUF_MEM *init_buf;          /* buffer used during init */
    void *init_msg;             /* pointer to handshake message body, set by
                                 * tls_get_message_header() */
    size_t init_num;               /* amount read/written */
    size_t init_off;               /* amount read/written */

    size_t ssl_pkey_num;

    struct {
        long flags;
        unsigned char server_random[SSL3_RANDOM_SIZE];
        unsigned char client_random[SSL3_RANDOM_SIZE];

        /* used during startup, digest all incoming/outgoing packets */
        BIO *handshake_buffer;
        /*
         * When handshake digest is determined, buffer is hashed and
         * freed and MD_CTX for the required digest is stored here.
         */
        EVP_MD_CTX *handshake_dgst;
        /*
         * Set whenever an expected ChangeCipherSpec message is processed.
         * Unset when the peer's Finished message is received.
         * Unexpected ChangeCipherSpec messages trigger a fatal alert.
         */
        int change_cipher_spec;
        int warn_alert;
        int fatal_alert;
        /*
         * we allow one fatal and one warning alert to be outstanding, send close
         * alert via the warning alert
         */
        int alert_dispatch;
        unsigned char send_alert[2];
        /*
         * This flag is set when we should renegotiate ASAP, basically when there
         * is no more data in the read or write buffers
         */
        int renegotiate;
        int total_renegotiations;
        int num_renegotiations;
        int in_read_app_data;

        struct {
            /* actually only need to be 16+20 for SSLv3 and 12 for TLS */
            unsigned char finish_md[EVP_MAX_MD_SIZE * 2];
            size_t finish_md_len;
            unsigned char peer_finish_md[EVP_MAX_MD_SIZE * 2];
            size_t peer_finish_md_len;
            size_t message_size;
            int message_type;
            /* used to hold the new cipher we are going to use */
            const SSL_CIPHER *new_cipher;
            EVP_PKEY *pkey;         /* holds short lived key exchange key */
            /* used for certificate requests */
            int cert_req;
            /* Certificate types in certificate request message. */
            uint8_t *ctype;
            size_t ctype_len;
            /* Certificate authorities list peer sent */
            STACK_OF(X509_NAME) *peer_ca_names;
            size_t key_block_length;
            unsigned char *key_block;
            const EVP_CIPHER *new_sym_enc;
            const EVP_MD *new_hash;
            int new_mac_pkey_type;
            size_t new_mac_secret_size;
# ifndef OPENSSL_NO_COMP
            const SSL_COMP *new_compression;
# else
            char *new_compression;
# endif
            int cert_request;
            /* Raw values of the cipher list from a client */
            unsigned char *ciphers_raw;
            size_t ciphers_rawlen;
            /* Temporary storage for premaster secret */
            unsigned char *pms;
            size_t pmslen;
# ifndef OPENSSL_NO_PSK
            /* Temporary storage for PSK key */
            unsigned char *psk;
            size_t psklen;
# endif
            /* Signature algorithm we actually use */
            const struct sigalg_lookup_st *sigalg;
            /* Pointer to certificate we use */
            CERT_PKEY *cert;
            /*
             * signature algorithms peer reports: e.g. supported signature
             * algorithms extension for server or as part of a certificate
             * request for client.
             * Keep track of the algorithms for TLS and X.509 usage separately.
             */
            uint16_t *peer_sigalgs;
            uint16_t *peer_cert_sigalgs;
            /* Size of above arrays */
            size_t peer_sigalgslen;
            size_t peer_cert_sigalgslen;
            /* Sigalg peer actually uses */
            const struct sigalg_lookup_st *peer_sigalg;
            /*
             * Set if corresponding CERT_PKEY can be used with current
             * SSL session: e.g. appropriate curve, signature algorithms etc.
             * If zero it can't be used at all.
             */
            uint32_t *valid_flags;
            /*
             * For servers the following masks are for the key and auth algorithms
             * that are supported by the certs below. For clients they are masks of
             * *disabled* algorithms based on the current session.
             */
            uint32_t mask_k;
            uint32_t mask_a;
            /*
             * The following are used by the client to see if a cipher is allowed or
             * not.  It contains the minimum and maximum version the client's using
             * based on what it knows so far.
             */
            int min_ver;
            int max_ver;
        } tmp;

        /* Connection binding to prevent renegotiation attacks */
        unsigned char previous_client_finished[EVP_MAX_MD_SIZE];
        size_t previous_client_finished_len;
        unsigned char previous_server_finished[EVP_MAX_MD_SIZE];
        size_t previous_server_finished_len;
        int send_connection_binding;

# ifndef OPENSSL_NO_NEXTPROTONEG
        /*
         * Set if we saw the Next Protocol Negotiation extension from our peer.
         */
        int npn_seen;
# endif

        /*
         * ALPN information (we are in the process of transitioning from NPN to
         * ALPN.)
         */

        /*
         * In a server these point to the selected ALPN protocol after the
         * ClientHello has been processed. In a client these contain the protocol
         * that the server selected once the ServerHello has been processed.
         */
        unsigned char *alpn_selected;
        size_t alpn_selected_len;
        /* used by the server to know what options were proposed */
        unsigned char *alpn_proposed;
        size_t alpn_proposed_len;
        /* used by the client to know if it actually sent alpn */
        int alpn_sent;

        /*
         * This is set to true if we believe that this is a version of Safari
         * running on OS X 10.6 or newer. We wish to know this because Safari on
         * 10.8 .. 10.8.3 has broken ECDHE-ECDSA support.
         */
        char is_probably_safari;

        /*
         * Track whether we did a key exchange this handshake or not, so
         * SSL_get_negotiated_group() knows whether to fall back to the
         * value in the SSL_SESSION.
         */
        char did_kex;
        /* For clients: peer temporary key */
        /* The group_id for the key exchange key */
        uint16_t group_id;
        EVP_PKEY *peer_tmp;

    } s3;

    struct dtls1_state_st *d1;  /* DTLSv1 variables */
    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;
    int hit;                    /* reusing a previous session */
    X509_VERIFY_PARAM *param;
    /* Per connection DANE state */
    SSL_DANE dane;
    /* crypto */
    STACK_OF(SSL_CIPHER) *peer_ciphers;
    STACK_OF(SSL_CIPHER) *cipher_list;
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    /* TLSv1.3 specific ciphersuites */
    STACK_OF(SSL_CIPHER) *tls13_ciphersuites;
    /*
     * These are the ones being used, the ones in SSL_SESSION are the ones to
     * be 'copied' into these ones
     */
    uint32_t mac_flags;
    /*
     * The TLS1.3 secrets.
     */
    unsigned char early_secret[EVP_MAX_MD_SIZE];
    unsigned char handshake_secret[EVP_MAX_MD_SIZE];
    unsigned char master_secret[EVP_MAX_MD_SIZE];
    unsigned char resumption_master_secret[EVP_MAX_MD_SIZE];
    unsigned char client_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_hash[EVP_MAX_MD_SIZE];
    unsigned char handshake_traffic_hash[EVP_MAX_MD_SIZE];
    unsigned char client_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char server_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char exporter_master_secret[EVP_MAX_MD_SIZE];
    unsigned char early_exporter_master_secret[EVP_MAX_MD_SIZE];

    /* session info */
    /* client cert? */
    /* This is used to hold the server certificate used */
    struct cert_st /* CERT */ *cert;

    /*
     * The hash of all messages prior to the CertificateVerify, and the length
     * of that hash.
     */
    unsigned char cert_verify_hash[EVP_MAX_MD_SIZE];
    size_t cert_verify_hash_len;

    /* Flag to indicate whether we should send a HelloRetryRequest or not */
    enum {SSL_HRR_NONE = 0, SSL_HRR_PENDING, SSL_HRR_COMPLETE}
        hello_retry_request;

    /*
     * the session_id_context is used to ensure sessions are only reused in
     * the appropriate context
     */
    size_t sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* This can also be in the session once a session is established */
    SSL_SESSION *session;
    /* TLSv1.3 PSK session */
    SSL_SESSION *psksession;
    unsigned char *psksession_id;
    size_t psksession_id_len;
    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;
    /*
     * The temporary TLSv1.3 session id. This isn't really a session id at all
     * but is a random value sent in the legacy session id field.
     */
    unsigned char tmp_session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    size_t tmp_session_id_len;
    /* Used in SSL3 */
    /*
     * 0 don't care about verify failure.
     * 1 fail if verify fails
     */
    uint32_t verify_mode;
    /* fail if callback returns 0 */
    int (*verify_callback) (int ok, X509_STORE_CTX *ctx);
    /* optional informational callback */
    void (*info_callback) (const SSL *ssl, int type, int val);
    /* error bytes to be written */
    int error;
    /* actual code */
    int error_code;
# ifndef OPENSSL_NO_PSK
    SSL_psk_client_cb_func psk_client_callback;
    SSL_psk_server_cb_func psk_server_callback;
# endif
    SSL_psk_find_session_cb_func psk_find_session_cb;
    SSL_psk_use_session_cb_func psk_use_session_cb;

    /* Verified chain of peer */
    STACK_OF(X509) *verified_chain;
    long verify_result;
    /*
     * What we put in certificate_authorities extension for TLS 1.3
     * (ClientHello and CertificateRequest) or just client cert requests for
     * earlier versions. If client_ca_names is populated then it is only used
     * for client cert requests, and in preference to ca_names.
     */
    STACK_OF(X509_NAME) *ca_names;
    STACK_OF(X509_NAME) *client_ca_names;
    /* protocol behaviour */
    uint64_t options;
    /* API behaviour */
    uint32_t mode;
    int min_proto_version;
    int max_proto_version;
    size_t max_cert_list;
    int first_packet;
    /*
     * What was passed in ClientHello.legacy_version. Used for RSA pre-master
     * secret and SSLv3/TLS (<=1.2) rollback check
     */
    int client_version;
    /*
     * If we're using more than one pipeline how should we divide the data
     * up between the pipes?
     */
    size_t split_send_fragment;
    /*
     * Maximum amount of data to send in one fragment. actual record size can
     * be more than this due to padding and MAC overheads.
     */
    size_t max_send_fragment;
    /* Up to how many pipelines should we use? If 0 then 1 is assumed */
    size_t max_pipelines;

    struct {
        /* Built-in extension flags */
        uint8_t extflags[TLSEXT_IDX_num_builtins];
        /* TLS extension debug callback */
        void (*debug_cb)(SSL *s, int client_server, int type,
                         const unsigned char *data, int len, void *arg);
        void *debug_arg;
        char *hostname;
#ifndef OPENSSL_NO_ECH
        SSL_CONNECTION_ECH ech;
#endif
        /* certificate status request info */
        /* Status type or -1 if no status type */
        int status_type;
        /* Raw extension data, if seen */
        unsigned char *scts;
        /* Length of raw extension data, if seen */
        uint16_t scts_len;
        /* Expect OCSP CertificateStatus message */
        int status_expected;

        struct {
            /* OCSP status request only */
            STACK_OF(OCSP_RESPID) *ids;
            X509_EXTENSIONS *exts;
            /* OCSP response received or to be sent */
            unsigned char *resp;
            size_t resp_len;
        } ocsp;

        /* RFC4507 session ticket expected to be received or sent */
        int ticket_expected;
        /* TLS 1.3 tickets requested by the application. */
        int extra_tickets_expected;
        size_t ecpointformats_len;
        /* our list */
        unsigned char *ecpointformats;

        size_t peer_ecpointformats_len;
        /* peer's list */
        unsigned char *peer_ecpointformats;
        size_t supportedgroups_len;
        /* our list */
        uint16_t *supportedgroups;

        size_t peer_supportedgroups_len;
         /* peer's list */
        uint16_t *peer_supportedgroups;

        /* TLS Session Ticket extension override */
        TLS_SESSION_TICKET_EXT *session_ticket;
        /* TLS Session Ticket extension callback */
        tls_session_ticket_ext_cb_fn session_ticket_cb;
        void *session_ticket_cb_arg;
        /* TLS pre-shared secret session resumption */
        tls_session_secret_cb_fn session_secret_cb;
        void *session_secret_cb_arg;
        /*
         * For a client, this contains the list of supported protocols in wire
         * format.
         */
        unsigned char *alpn;
        size_t alpn_len;

        /*
         * Next protocol negotiation. For the client, this is the protocol that
         * we sent in NextProtocol and is set when handling ServerHello
         * extensions. For a server, this is the client's selected_protocol from
         * NextProtocol and is set when handling the NextProtocol message, before
         * the Finished message.
         */
        unsigned char *npn;
        size_t npn_len;

        /* The available PSK key exchange modes */
        int psk_kex_mode;

        /* Set to one if we have negotiated ETM */
        int use_etm;

        /* Are we expecting to receive early data? */
        int early_data;
        /* Is the session suitable for early data? */
        int early_data_ok;

        /* May be sent by a server in HRR. Must be echoed back in ClientHello */
        unsigned char *tls13_cookie;
        size_t tls13_cookie_len;
        /* Have we received a cookie from the client? */
        int cookieok;

        /*
         * Maximum Fragment Length as per RFC 4366.
         * If this member contains one of the allowed values (1-4)
         * then we should include Maximum Fragment Length Negotiation
         * extension in Client Hello.
         * Please note that value of this member does not have direct
         * effect. The actual (binding) value is stored in SSL_SESSION,
         * as this extension is optional on server side.
         */
        uint8_t max_fragment_len_mode;

        /*
         * On the client side the number of ticket identities we sent in the
         * ClientHello. On the server side the identity of the ticket we
         * selected.
         */
        int tick_identity;

        /* This is the list of algorithms the peer supports that we also support */
        int compress_certificate_from_peer[TLSEXT_comp_cert_limit];
        /* indicate that we sent the extension, so we'll accept it */
        int compress_certificate_sent;

        uint8_t client_cert_type;
        uint8_t client_cert_type_ctos;
        uint8_t server_cert_type;
        uint8_t server_cert_type_ctos;
    } ext;

#ifndef OPENSSL_NO_SECH
    struct {
        char * symmetric_key;
        int symmetric_key_len;
    } sech;
#endif//OPENSSL_NO_SECH


    /*
     * Parsed form of the ClientHello, kept around across client_hello_cb
     * calls.
     */
    CLIENTHELLO_MSG *clienthello;

    /*-
     * no further mod of servername
     * 0 : call the servername extension callback.
     * 1 : prepare 2, allow last ack just after in server callback.
     * 2 : don't call servername callback, no ack in server hello
     */
    int servername_done;
# ifndef OPENSSL_NO_CT
    /*
     * Validates that the SCTs (Signed Certificate Timestamps) are sufficient.
     * If they are not, the connection should be aborted.
     */
    ssl_ct_validation_cb ct_validation_callback;
    /* User-supplied argument that is passed to the ct_validation_callback */
    void *ct_validation_callback_arg;
    /*
     * Consolidated stack of SCTs from all sources.
     * Lazily populated by CT_get_peer_scts(SSL*)
     */
    STACK_OF(SCT) *scts;
    /* Have we attempted to find/parse SCTs yet? */
    int scts_parsed;
# endif
    SSL_CTX *session_ctx;       /* initial ctx, used to store sessions */
# ifndef OPENSSL_NO_SRTP
    /* What we'll do */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
    /* What's been chosen */
    SRTP_PROTECTION_PROFILE *srtp_profile;
# endif
    /*-
     * 1 if we are renegotiating.
     * 2 if we are a server and are inside a handshake
     * (i.e. not just sending a HelloRequest)
     */
    int renegotiate;
    /* If sending a KeyUpdate is pending */
    int key_update;
    /* Post-handshake authentication state */
    SSL_PHA_STATE post_handshake_auth;
    int pha_enabled;
    uint8_t* pha_context;
    size_t pha_context_len;
    int certreqs_sent;
    EVP_MD_CTX *pha_dgst; /* this is just the digest through ClientFinished */

# ifndef OPENSSL_NO_SRP
    /* ctx for SRP authentication */
    SRP_CTX srp_ctx;
# endif
    /*
     * Callback for disabling session caching and ticket support on a session
     * basis, depending on the chosen cipher.
     */
    int (*not_resumable_session_cb) (SSL *ssl, int is_forward_secure);

    /* Record layer data */
    RECORD_LAYER rlayer;

    /* Default password callback. */
    pem_password_cb *default_passwd_callback;
    /* Default password callback user data. */
    void *default_passwd_callback_userdata;
    /* Async Job info */
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    size_t asyncrw;

    /*
     * The maximum number of bytes advertised in session tickets that can be
     * sent as early data.
     */
    uint32_t max_early_data;
    /*
     * The maximum number of bytes of early data that a server will tolerate
     * (which should be at least as much as max_early_data).
     */
    uint32_t recv_max_early_data;

    /*
     * The number of bytes of early data received so far. If we accepted early
     * data then this is a count of the plaintext bytes. If we rejected it then
     * this is a count of the ciphertext bytes.
     */
    uint32_t early_data_count;

    /* The number of TLS1.3 tickets to automatically send */
    size_t num_tickets;
    /* The number of TLS1.3 tickets actually sent so far */
    size_t sent_tickets;
    /* The next nonce value to use when we send a ticket on this connection */
    uint64_t next_ticket_nonce;

    /* Callback to determine if early_data is acceptable or not */
    SSL_allow_early_data_cb_fn allow_early_data_cb;
    void *allow_early_data_cb_data;

    /* Callback for SSL async handling */
    SSL_async_callback_fn async_cb;
    void *async_cb_arg;

    /*
     * Signature algorithms shared by client and server: cached because these
     * are used most often.
     */
    const struct sigalg_lookup_st **shared_sigalgs;
    size_t shared_sigalgslen;

#ifndef OPENSSL_NO_COMP_ALG
    /* certificate compression preferences */
    int cert_comp_prefs[TLSEXT_comp_cert_limit];
#endif

    /* Certificate Type stuff - for RPK vs X.509 */
    unsigned char *client_cert_type;
    size_t client_cert_type_len;
    unsigned char *server_cert_type;
    size_t server_cert_type_len;
};
