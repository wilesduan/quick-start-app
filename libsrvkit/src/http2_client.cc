#include <http2_client.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>


static int ctl_http2_event(worker_thread_t* worker, struct proto_client_inst_t* cli);

static int do_read_msg_from_http2(void* arg);
static int do_write_msg_2_http2(void * arg);

static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                     unsigned char *outlen, const unsigned char *in,
                     unsigned int inlen, void *arg)
{
    int rv;
  /* nghttp2_select_next_protocol() selects HTTP/2 protocol the
     nghttp2 library supports. */
    rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
    if (rv <= 0) {
        LOG_ERR("Server did not advertise HTTP/2 protocol");
		return -2;
    }
    return SSL_TLSEXT_ERR_OK;
}

static void init_ssl_ctx(SSL_CTX *ssl_ctx)
{
  /* Disable SSLv2 and enable all workarounds for buggy servers */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  /* Set NPN callback */
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
}

static X509*
read_x509_certificate(const char* path)
{
    BIO  *bio = NULL;
    X509 *x509 = NULL;
    if (NULL == (bio = BIO_new_file(path, "r"))) {
        return NULL;
    }
    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return x509;
}

static int ssl_allocate(struct proto_client_inst_t *cli)
{
    int rv;
    X509 *x509 = NULL;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    if (NULL == (x509 = read_x509_certificate(cli->ssl_cert_path))) {
		LOG_ERR("read x509 error");
        return -1;
    }

    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL) {
        X509_free(x509);
		return -10;
    }

    init_ssl_ctx(ssl_ctx);

    rv = SSL_CTX_use_certificate(ssl_ctx, x509);
    X509_free(x509);
    if (rv != 1) {
        SSL_CTX_free(ssl_ctx);
		LOG_ERR("failed to user certificate");
        return -2;
    }

    rv = SSL_CTX_use_PrivateKey_file(ssl_ctx, cli->ssl_cert_path, SSL_FILETYPE_PEM);
    if (rv != 1) {
        SSL_CTX_free(ssl_ctx);
		LOG_ERR("failed to user privatekey");
        return -3;
    }

    rv = SSL_CTX_check_private_key(ssl_ctx);
    if (rv != 1) {
        SSL_CTX_free(ssl_ctx);
		LOG_ERR("failed to check key");
        return -4;
    }

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ssl_ctx);
		LOG_ERR("failed to new ssl");
        return -5;
    }

    cli->ssl_conn.ssl_ctx = ssl_ctx;
    cli->ssl_conn.ssl = ssl;
    return 0;
}

static int ssl_handshake(proto_client_inst_t *cli)
{
    int rv;
    if (SSL_set_fd(cli->ssl_conn.ssl, cli->ssl_conn.fd) == 0) {
        return -1;
    }
    ERR_clear_error();
    //rv = SSL_connect(ssl);
    SSL_set_connect_state(cli->ssl_conn.ssl);
    rv = SSL_do_handshake(cli->ssl_conn.ssl);

    if(rv==1) {
		LOG_DBG("Connected with encryption: %s\n", SSL_get_cipher(cli->ssl_conn.ssl));
		return 0;
    }

	LOG_DBG("rv = %d\n",rv);
	unsigned long ssl_err = SSL_get_error(cli->ssl_conn.ssl,rv);
	int geterror = ERR_peek_error();
	int reason = ERR_GET_REASON(geterror);
	LOG_DBG("rv %d, ssl_error %lu, get_err %d, reason %d \n",rv, ssl_err, geterror ,reason);
	LOG_DBG("errmsg: %s\n", ERR_error_string(ERR_get_error(), NULL));
	LOG_DBG("errmsg msg: %s\n", ERR_reason_error_string(ERR_peek_error()));
	LOG_ERR("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
	return -2;
}

#define _U_
static ssize_t send_callback(nghttp2_session *session _U_, const uint8_t *data,
                             size_t length, int flags _U_, void *user_data) 
{
	int rv;
	struct http2_ssl_connection_t* conn = &(((proto_client_inst_t*)user_data)->ssl_conn);
	ERR_clear_error();
	rv = SSL_write(conn->ssl, data, (int)length);
	if (rv <= 0) {
		int err = SSL_get_error(conn->ssl, rv);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			rv = NGHTTP2_ERR_WOULDBLOCK;
		} else {
			rv = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}
	return rv;
}

static ssize_t recv_callback(nghttp2_session *session _U_, uint8_t *buf,
		size_t length, int flags _U_, void *user_data) 
{
	struct http2_ssl_connection_t* conn = &(((proto_client_inst_t*)user_data)->ssl_conn);
	int rv;
	ERR_clear_error();
	rv = SSL_read(conn->ssl, buf, (int)length);
	if (rv < 0) {
		int err = SSL_get_error(conn->ssl, rv);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			rv = NGHTTP2_ERR_WOULDBLOCK;
		} else {
			rv = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	} else if (rv == 0) {
		rv = NGHTTP2_ERR_EOF;
	}
	return rv;
}

static int on_frame_send_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		void *user_data _U_) 
{
	size_t i;
	switch (frame->hd.type) {
		case NGHTTP2_DATA:
			//LOG_DBG("NGHTTP2_DATA");
			break;
		case NGHTTP2_HEADERS:
			if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id))
			{
				const nghttp2_nv *nva = frame->headers.nva;
				LOG_DBG("NGHTTP2_HEADERS,stream_id: %d", frame->hd.stream_id);
				for (i = 0; i < frame->headers.nvlen; ++i) {
					LOG_DBG("%s: %s", nva[i].name, nva[i].value);
				}
			}
			else
			{
				LOG_DBG("NGHTTP2_HEADERS,stream_id: %d not find user data", frame->hd.stream_id);
			}
			break;
		case NGHTTP2_PRIORITY:
			LOG_DBG("NGHTTP2_PRIORITY");
			break;
		case NGHTTP2_RST_STREAM:
			LOG_DBG("NGHTTP2_RST_STREAM");
			break;
		case NGHTTP2_SETTINGS:
			//LOG_DBG("NGHTTP2_SETTINGS");
			break;
		case NGHTTP2_PUSH_PROMISE:
			LOG_DBG("NGHTTP2_PUSH_PROMISE");
			break;
		case NGHTTP2_PING:
			//LOG_DBG("NGHTTP2_PING");
			break;
		case NGHTTP2_GOAWAY:
			LOG_DBG("NGHTTP2_GOAWAY");
			break;
		case NGHTTP2_WINDOW_UPDATE:
			LOG_DBG("NGHTTP2_WINDOW_UPDATE");
			break;
		case NGHTTP2_CONTINUATION:
			LOG_DBG("NGHTTP2_CONTINUATION");
			break;
		case NGHTTP2_ALTSVC:
			LOG_DBG("NGHTTP2_ALTSVC");
			break;
		default:
			LOG_DBG("unknown type: %d", frame->hd.type);
			break;
	}
	return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		void *user_data _U_) 
{
	switch (frame->hd.type)
	{
		case NGHTTP2_DATA:
			//LOG_DBG("NGHTTP2_DATA");
			break;
		case NGHTTP2_HEADERS:
			LOG_DBG("NGHTTP2_HEADERS");
			break;
		case NGHTTP2_PRIORITY:
			LOG_DBG("NGHTTP2_PRIORITY");
			break;
		case NGHTTP2_RST_STREAM:
			LOG_DBG("NGHTTP2_RST_STREAM");
			break;
		case NGHTTP2_SETTINGS:
			//LOG_DBG("NGHTTP2_SETTINGS");
			break;
		case NGHTTP2_PUSH_PROMISE:
			LOG_DBG("NGHTTP2_PUSH_PROMISE");
			break;
		case NGHTTP2_PING:
			//LOG_DBG("NGHTTP2_PING");
			break;
		case NGHTTP2_GOAWAY:
			LOG_DBG("NGHTTP2_GOAWAY");
			break;
		case NGHTTP2_WINDOW_UPDATE:
			LOG_DBG("NGHTTP2_WINDOW_UPDATE");
			break;
		case NGHTTP2_CONTINUATION:
			LOG_DBG("NGHTTP2_CONTINUATION");
			break;
		case NGHTTP2_ALTSVC:
			LOG_DBG("NGHTTP2_ALTSVC");
			break;
		default:
			LOG_DBG("unknown type: %d", frame->hd.type);
			break;
	}
	return 0;
}

static int on_header_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		const uint8_t *name, size_t namelen,
		const uint8_t *value, size_t valuelen,
		uint8_t flags, void *user_data) {
	if (frame->hd.type == NGHTTP2_HEADERS)
	{
		std::string name_header((char*)name, namelen);
		std::string value_header((char*)value, valuelen);
		LOG_DBG("stream_id: %d, NGHTTP2_HEADERS: %s: %s", frame->hd.stream_id, name_header.c_str(), value_header.c_str());
	}
	return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		void *user_data) {
	return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
		uint32_t error_code _U_,
		void *user_data _U_) {
	return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session,
		uint8_t flags _U_, int32_t stream_id,
		const uint8_t *data, size_t len,
		void *user_data _U_) {
	if(nghttp2_session_get_stream_user_data(session, stream_id))
	{
		std::string buf((char*)data, len);
		LOG_DBG("stream_id: %d, NGHTTP2_DATA: %s", stream_id, buf.c_str());
	}
	return 0;
}

static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{
	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
	nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks,on_header_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,on_begin_headers_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);

}

int clean_http2_cli(worker_thread_t* worker, struct proto_client_inst_t* cli)
{
	LOG_ERR("clean_http2_cli");
	ev_ptr_t* ptr = get_ev_ptr(worker, cli->ssl_conn.fd);
	if(NULL == ptr){
		LOG_ERR("null ev ptr");
		return -1;
	}

	recycle_ev_ptr(ptr);
	http2_ssl_connection_t* conn = &(cli->ssl_conn);

	if(conn->session){
		nghttp2_session_del(conn->session);
	}

	if(conn->ssl){
		if(SSL_get_shutdown(conn->ssl)){
			SSL_shutdown(conn->ssl);
		}
		SSL_free(conn->ssl);
	}

	if(conn->ssl_ctx){
		SSL_CTX_free(conn->ssl_ctx);
	}

	if(conn->fd){
		shutdown(conn->fd, SHUT_WR);
		close(conn->fd);
	}

	bzero(conn, sizeof(http2_ssl_connection_t));
	return 0;
}

static int ctl_http2_event(worker_thread_t* worker, struct proto_client_inst_t* cli)
{
	ev_ptr_t* ptr = get_ev_ptr(worker, cli->ssl_conn.fd);
	if(NULL == ptr){
		LOG_ERR("null ev ptr");
		return -1;
	}

	int ev = 0;
	if(nghttp2_session_want_read(cli->ssl_conn.session)){
		ev |= EPOLLIN;
		ptr->do_read_ev = do_read_msg_from_http2;
	}

	int want_write = nghttp2_session_want_write(cli->ssl_conn.session);
	if(want_write){
		ev |= EPOLLOUT;
		ptr->do_write_ev = do_write_msg_2_http2;
	}

	if( 0 == ev){
		LOG_ERR("no session want read or write. %s:%d", cli->ip, cli->port);
		clean_http2_cli(worker, cli);
		return -2;
	}

	ptr->arg = worker;
	int op = (ptr->ev == 0?EPOLL_CTL_ADD:EPOLL_CTL_MOD);
	ptr->ev = ev;
	struct epoll_event event;
	event.events = ev;
	event.data.ptr = ptr;
	epoll_ctl(worker->epoll_fd, op, ptr->fd, &event);
	return 0;
}

static int set_nghttp2_session_info(worker_thread_t* worker, struct proto_client_inst_t* cli)
{
	int rv;
	nghttp2_session_callbacks *callbacks;

	rv = nghttp2_session_callbacks_new(&callbacks);
	if (rv != 0) {
		LOG_ERR("nghttp2_session_callbacks_new");
	}

	setup_nghttp2_callbacks(callbacks);
	rv = nghttp2_session_client_new(&(cli->ssl_conn.session), callbacks, cli);
	if (rv != 0) {
		LOG_ERR("nghttp2_session_client_new");
	}
	nghttp2_session_callbacks_del(callbacks);

	rv = nghttp2_submit_settings(cli->ssl_conn.session, NGHTTP2_FLAG_NONE, NULL, 0);
	if (rv != 0) {
		LOG_ERR("nghttp2_submit_settings %d",rv);
	}

	ctl_http2_event(worker, cli);
	return 0;
}

int http2_ssl_connect(worker_thread_t* worker, proto_client_inst_t* cli, int fd)
{
	cli->ssl_conn.fd = fd;
	if(ssl_allocate(cli)){
		LOG_ERR("failed to allocate ssl");
		return -1;
	}
	 
    util_un_fcntl(fd);
	int rc = ssl_handshake(cli);
	util_fcntl(fd);
	if(rc){
		LOG_ERR("failed to shake ssl hand");
		SSL_free(cli->ssl_conn.ssl);
		SSL_CTX_free(cli->ssl_conn.ssl_ctx);
		return -2;
	}

	LOG_DBG("http2 ssl connect OK");
	set_nghttp2_session_info(worker, cli);


	return 0;
}

static int do_write_msg_2_http2(void* arg)
{
	ev_ptr_t* ptr = (ev_ptr_t*)arg;
	proto_client_inst_t* cli  = ptr->cli;
	worker_thread_t* worker = (worker_thread_t*)ptr->arg;

	int rc = nghttp2_session_send(cli->ssl_conn.session);
	if(rc == NGHTTP2_ERR_CALLBACK_FAILURE){
		LOG_ERR("failed to execute nghttp2 session send:%d", rc);
		clean_http2_cli(worker, cli);
		return -1;
	}

   	ctl_http2_event(worker, cli);
    return 0;
}

static int do_read_msg_from_http2(void* arg)
{
	ev_ptr_t* ptr = (ev_ptr_t*)arg;
	proto_client_inst_t* cli  = ptr->cli;
	worker_thread_t* worker = (worker_thread_t*)ptr->arg;
	int rc = nghttp2_session_recv(cli->ssl_conn.session);
	if(rc == NGHTTP2_ERR_EOF || rc == NGHTTP2_ERR_CALLBACK_FAILURE){
		LOG_ERR("failed to execute nghttp2 session recv:%d", rc);
		clean_http2_cli(worker, cli);
		return -1;
	}

    LOG_DBG("add_ev_ptr_2_idle_time_wheel do_read_msg_from_http2. worker:%llu, host:%s:%d", (long long unsigned)worker, ptr->ip, ptr->port);
	//add_ev_ptr_2_idle_time_wheel(worker, ptr);
	ctl_http2_event(worker, cli);
	return 0;
}

ssize_t data_prd_read_callback(
		nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
		uint32_t *data_flags, nghttp2_data_source *source, void *user_data) 
{
	http2_payload_t *payload = (http2_payload_t*)source->ptr;
	ssize_t len = payload->len;

	memcpy(buf, payload->data, len);
	*data_flags |= NGHTTP2_DATA_FLAG_EOF;

	char sz_payload[2048];
  	memcpy(sz_payload, payload->data, len);
  	sz_payload[len] = 0;
	LOG_DBG("stream_id: %d, NGHTTP2_DATA: %s", stream_id, sz_payload);
	free(payload->data);
	free(payload);
	return len;
}

int http2_submit_request(worker_thread_t* worker, const char* service, nghttp2_nv* nva, size_t sz, http2_payload_t* payload)
{
	if(NULL == payload){
		LOG_ERR("no payload for submit request");
		return -10;
	}

	proto_client_t* client = get_clients_by_service(worker, service);//TODO
	if(NULL == client || 0 == client->num_clients){
		LOG_ERR("no proto cli 4 service:%s", service);
		return -1;
	}

	proto_client_inst_t* cli = NULL;
	size_t start = client->next_cli;
	size_t i = start %(client->num_clients);
	do{
		client->next_cli = (client->next_cli+1)%(client->num_clients);
		proto_client_inst_t* s = client->cli_inst_s+i;
		if(s->ptr){
			cli = s;
			break;
		}
	}while(i != start);

	if(NULL == cli){
		LOG_ERR("no instances cli for service:%s", service);
		return -2;
	}

	nghttp2_data_provider data_prd;
	data_prd.source.ptr = (void*)payload; 
	data_prd.read_callback = data_prd_read_callback;

	int32_t stream_id = nghttp2_submit_request(cli->ssl_conn.session, NULL, nva, sz, &data_prd, cli);
	//LOG_INFO("stream_id:%d, payload:%s", stream_id, payload);
	ctl_http2_event(worker, cli);
	return stream_id;
}

int async_http2_heartbeat(worker_thread_t* worker, ev_ptr_t* ptr)
{
	proto_client_inst_t* cli = ptr->cli;
	if(NULL == cli || NULL == cli->ssl_conn.session){
		return 0;
	}

	int32_t stream_id = nghttp2_submit_ping(cli->ssl_conn.session, NGHTTP2_FLAG_NONE, NULL);
	LOG_DBG("stream_id:%d", stream_id);
	ctl_http2_event(worker, cli);
	return 0;
}

int http2_ping_mark(ev_ptr_t* ptr)
{
	return 0;
}

