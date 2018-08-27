
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t               *flushes;
    ngx_array_t               *lengths;
    ngx_array_t               *values;
    ngx_hash_t                 hash;
} ngx_http_grpc_headers_t;


typedef struct {
    ngx_http_upstream_conf_t   upstream; 

    ngx_http_grpc_headers_t    headers;
    ngx_array_t               *headers_source;

    ngx_str_t                  host;
    ngx_uint_t                 host_set;

#if (NGX_HTTP_SSL)
    ngx_uint_t                 ssl;
    ngx_uint_t                 ssl_protocols;
    ngx_str_t                  ssl_ciphers;
    ngx_uint_t                 ssl_verify_depth;
    ngx_str_t                  ssl_trusted_certificate;
    ngx_str_t                  ssl_crl;
    ngx_str_t                  ssl_certificate;
    ngx_str_t                  ssl_certificate_key;
    ngx_array_t               *ssl_passwords;
#endif
} ngx_http_grpc_loc_conf_t;


typedef enum {
    ngx_http_grpc_st_start = 0,
    ngx_http_grpc_st_length_2,
    ngx_http_grpc_st_length_3,
    ngx_http_grpc_st_type,
    ngx_http_grpc_st_flags,
    ngx_http_grpc_st_stream_id,
    ngx_http_grpc_st_stream_id_2,
    ngx_http_grpc_st_stream_id_3,
    ngx_http_grpc_st_stream_id_4,
    ngx_http_grpc_st_payload,
    ngx_http_grpc_st_padding
} ngx_http_grpc_state_e;


typedef struct {
    size_t                     init_window; /* 是stream的initial window 会根据settings改的 */
    size_t                     send_window; /* 是connection的发送窗口 window_update来改变 */
    size_t                     recv_window;
    ngx_uint_t                 last_stream_id;
} ngx_http_grpc_conn_t;


typedef struct { /* 用户自定义的数据结构，用于filter的 */
    ngx_http_grpc_state_e      state;
    ngx_uint_t                 frame_state;
    ngx_uint_t                 fragment_state;

    ngx_chain_t               *in;
    ngx_chain_t               *out;
    ngx_chain_t               *free;
    ngx_chain_t               *busy;

    ngx_http_grpc_conn_t      *connection;

    ngx_uint_t                 id; /* 这个是r的stream id */

    ssize_t                    send_window;
    size_t                     recv_window;

    size_t                     rest;
    ngx_uint_t                 stream_id;
    u_char                     type;
    u_char                     flags;
    u_char                     padding;

    ngx_uint_t                 error;
    ngx_uint_t                 window_update; /* 记录window_update帧的increment值 */

    ngx_uint_t                 setting_id;
    ngx_uint_t                 setting_value;

    u_char                     ping_data[8];

    ngx_uint_t                 index;
    ngx_str_t                  name;
    ngx_str_t                  value;

    u_char                    *field_end;
    size_t                     field_length;
    size_t                     field_rest;
    u_char                     field_state;

    unsigned                   literal:1;
    unsigned                   field_huffman:1;

    unsigned                   header_sent:1;
    unsigned                   output_closed:1;
    unsigned                   parsing_headers:1;
    unsigned                   end_stream:1;
    unsigned                   status:1;

    ngx_http_request_t        *request;
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    ngx_http_multi_upstreams_t   *mus;
#endif
} ngx_http_grpc_ctx_t;


typedef struct { /* frame */
    u_char                     length_0; /* 3 * 8 = 24 bits length */
    u_char                     length_1;
    u_char                     length_2;
    u_char                     type;
    u_char                     flags;
    u_char                     stream_id_0; /* 4 * 8 = 32 bits stream ID */
    u_char                     stream_id_1;
    u_char                     stream_id_2;
    u_char                     stream_id_3;
} ngx_http_grpc_frame_t;


static ngx_int_t ngx_http_grpc_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_grpc_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_grpc_body_output_filter(void *data, ngx_chain_t *in); /* 这是向上游发的时候 */
static ngx_int_t ngx_http_grpc_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_grpc_filter_init(void *data); /* 这是向下游转发的时候  */
static ngx_int_t ngx_http_grpc_filter(void *data, ssize_t bytes);

static ngx_int_t ngx_http_grpc_parse_frame(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_grpc_parse_header(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_grpc_parse_fragment(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_grpc_validate_header_name(ngx_http_request_t *r,
    ngx_str_t *s);
static ngx_int_t ngx_http_grpc_validate_header_value(ngx_http_request_t *r,
    ngx_str_t *s);
static ngx_int_t ngx_http_grpc_parse_rst_stream(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_grpc_parse_goaway(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_grpc_parse_window_update(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_grpc_parse_settings(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_grpc_parse_ping(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);

static ngx_int_t ngx_http_grpc_send_settings_ack(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx);
static ngx_int_t ngx_http_grpc_send_ping_ack(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx);
static ngx_int_t ngx_http_grpc_send_window_update(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx);

static ngx_chain_t *ngx_http_grpc_get_buf(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx);
static ngx_http_grpc_ctx_t *ngx_http_grpc_get_ctx(ngx_http_request_t *r);
static ngx_int_t ngx_http_grpc_get_connection_data(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_peer_connection_t *pc);
static void ngx_http_grpc_cleanup(void *data);

static void ngx_http_grpc_abort_request(ngx_http_request_t *r);
static void ngx_http_grpc_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_grpc_internal_trailers_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_grpc_add_variables(ngx_conf_t *cf);
static void *ngx_http_grpc_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_grpc_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_grpc_init_headers(ngx_conf_t *cf,
    ngx_http_grpc_loc_conf_t *conf, ngx_http_grpc_headers_t *headers,
    ngx_keyval_t *default_headers);

static char *ngx_http_grpc_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#if (NGX_HTTP_SSL)
static char *ngx_http_grpc_ssl_password_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_grpc_set_ssl(ngx_conf_t *cf,
    ngx_http_grpc_loc_conf_t *glcf);
#endif


static ngx_conf_bitmask_t  ngx_http_grpc_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    /* { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT }, */
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
    { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    /* { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 }, */
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


#if (NGX_HTTP_SSL)

static ngx_conf_bitmask_t  ngx_http_grpc_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    /* { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 }, */
    { ngx_null_string, 0 }
};

#endif


static ngx_command_t  ngx_http_grpc_commands[] = {

    { ngx_string("grpc_pass"), /* 配置grpc后端 */
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_grpc_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("grpc_bind"), /* 设置发送到server的请求的地址 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("grpc_connect_timeout"), /* 连接server最大值 需 < 75s */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("grpc_send_timeout"), /* 将请求发送到gRPC server的超时 在两个连续写之间 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("grpc_intercept_errors"), /* 确定代码大于或等于300的gRPC server响应 是应该to client 还是被拦截并重定向到nginx以便使用error_page指令进行处理 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.intercept_errors),
      NULL },

    { ngx_string("grpc_buffer_size"), /* 设置从server返回的消息存入buf的大小，这将同步返回给client */
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1, /* 保证复用的所有的buffer_size大小相同 即同一个连接的多个流的初始窗口大小一致 */
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("grpc_read_timeout"), /* 从gRPC server读取响应的超时 在两个连续读之间 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("grpc_next_upstream"), /* 确定什么情况下将被传递给下一个server 如404 超时等 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.next_upstream),
      &ngx_http_grpc_next_upstream_masks },

    { ngx_string("grpc_next_upstream_tries"), /* 限制将请求传递到下一个server的可能尝试次数 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { ngx_string("grpc_next_upstream_timeout"), /* 限制请求可以传递到下一个服务器的时间 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { ngx_string("grpc_set_header"), /* 增加给server的header */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, headers_source),
      NULL },

    { ngx_string("grpc_pass_header"), /* 允许将其他禁用的header从gRPC server传递到client */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.pass_headers),
      NULL },

    { ngx_string("grpc_hide_header"), /* 隐藏从server返回的header (某些如date是默认隐藏的) */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.hide_headers),
      NULL },

    { ngx_string("grpc_ignore_headers"), /* 不解析从server返回的header */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.ignore_headers),
      &ngx_http_upstream_ignore_headers_masks },

#if (NGX_HTTP_SSL)

    { ngx_string("grpc_ssl_session_reuse"), /* 是否可重用与gRPC server SSL session */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { ngx_string("grpc_ssl_protocols"), /* 支持的SSL协议版本 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, ssl_protocols),
      &ngx_http_grpc_ssl_protocols },

    { ngx_string("grpc_ssl_ciphers"), /* 指定对gRPC server 的enabled ciphers */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, ssl_ciphers),
      NULL },

    { ngx_string("grpc_ssl_name"), /* 没懂 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_name),
      NULL },

    { ngx_string("grpc_ssl_server_name"), /* 启用或禁止在TLS中显示server name */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { ngx_string("grpc_ssl_verify"), /* 开启或关闭对server的身份认证 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_verify),
      NULL },

    { ngx_string("grpc_ssl_verify_depth"), /* 设置gRPC SSL server 证书链中的验证深度 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, ssl_verify_depth),
      NULL },

    { ngx_string("grpc_ssl_trusted_certificate"), /* CA 证书 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { ngx_string("grpc_ssl_crl"), /* 指定CRL认证用于sever */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, ssl_crl),
      NULL },

    { ngx_string("grpc_ssl_certificate"), /* 指定与用于验证的gRPC SSL server的证书 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, ssl_certificate),
      NULL },

    { ngx_string("grpc_ssl_certificate_key"), /* 指定对gRPC SSL server进行认证的密钥文件 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_grpc_loc_conf_t, ssl_certificate_key),
      NULL },

    { ngx_string("grpc_ssl_password_file"), /* 指定密钥文件 */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_grpc_ssl_password_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

      ngx_null_command
};


static ngx_http_module_t  ngx_http_grpc_module_ctx = {
    ngx_http_grpc_add_variables,           /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_grpc_create_loc_conf,         /* create location configuration */
    ngx_http_grpc_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_grpc_module = {
    NGX_MODULE_V1,
    &ngx_http_grpc_module_ctx,             /* module context */
    ngx_http_grpc_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char  ngx_http_grpc_connection_start[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"         /* connection preface */

    "\x00\x00\x12\x04\x00\x00\x00\x00\x00"     /* settings frame */
    "\x00\x01\x00\x00\x00\x00"                 /* header table size */
    "\x00\x02\x00\x00\x00\x00"                 /* disable push */
    "\x00\x04\x7f\xff\xff\xff"                 /* initial window */

    "\x00\x00\x04\x08\x00\x00\x00\x00\x00"     /* window update frame */
    "\x7f\xff\x00\x00";


#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
static u_char ngx_http_grpc_conn_preface[] = 
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";        /* connection preface */

# define NGX_HTTP_GRPC_SETTINGS_ITEM       6
# define NGX_HTTP_GRPC_SETTINGS_ID         2
#endif


static ngx_keyval_t  ngx_http_grpc_headers[] = {
    { ngx_string("Content-Length"), ngx_string("$content_length") },
    { ngx_string("TE"), ngx_string("$grpc_internal_trailers") },
    { ngx_string("Host"), ngx_string("") },
    { ngx_string("Connection"), ngx_string("") },
    { ngx_string("Transfer-Encoding"), ngx_string("") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};


static ngx_str_t  ngx_http_grpc_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};


static ngx_http_variable_t  ngx_http_grpc_vars[] = {

    { ngx_string("grpc_internal_trailers"), NULL,
      ngx_http_grpc_internal_trailers_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_grpc_handler(ngx_http_request_t *r) /* 各种handler挂载到new的upstream上 从v2模块解析的r来了*/
{
    ngx_int_t                  rc;
    ngx_http_upstream_t       *u;
    ngx_http_grpc_ctx_t       *ctx;
    ngx_http_grpc_loc_conf_t  *glcf;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    glcf = ngx_http_get_module_loc_conf(r, ngx_http_grpc_module);

    u = r->upstream;

#if (NGX_HTTP_SSL)
    u->ssl = (glcf->upstream.ssl != NULL);

    if (u->ssl) {
        ngx_str_set(&u->schema, "grpcs://");

    } else {
        ngx_str_set(&u->schema, "grpc://");
    }
#else
    ngx_str_set(&u->schema, "grpc://");
#endif

    u->output.tag = (ngx_buf_tag_t) &ngx_http_grpc_module;

    u->conf = &glcf->upstream;

    u->create_request = ngx_http_grpc_create_request;
    u->reinit_request = ngx_http_grpc_reinit_request;
    u->process_header = ngx_http_grpc_process_header;
    u->abort_request = ngx_http_grpc_abort_request;
    u->finalize_request = ngx_http_grpc_finalize_request;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_grpc_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r; /* r挂到ctx上 */

    ngx_http_set_ctx(r, ctx, ngx_http_grpc_module); /* ctx挂到r上 */

    u->input_filter_init = ngx_http_grpc_filter_init; /* prepare to read response body */
    u->input_filter = ngx_http_grpc_filter; /* process body */
    u->input_filter_ctx = ctx; /* 用户数据结构 */

    r->request_body_no_buffering = 1; /* 固定大小内存转发 马上就会设置为0了 */

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init); /* 在层层嵌套中 启动upstream? */

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_grpc_create_request(ngx_http_request_t *r)
{
    u_char                       *p, *tmp, *key_tmp, *val_tmp, *headers_frame;
    size_t                        len, tmp_len, key_len, val_len, uri_len;
    uintptr_t                     escape;
    ngx_buf_t                    *b;
    ngx_uint_t                    i, next;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_upstream_t          *u;
    ngx_http_grpc_frame_t        *f;
    ngx_http_script_code_pt       code;
    ngx_http_grpc_loc_conf_t     *glcf;
    ngx_http_script_engine_t      e, le;
    ngx_http_script_len_code_pt   lcode;

    u = r->upstream;

    glcf = ngx_http_get_module_loc_conf(r, ngx_http_grpc_module);

    len = sizeof(ngx_http_grpc_connection_start) - 1
          + sizeof(ngx_http_grpc_frame_t);             /* headers frame */

    /* :method header */

    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_POST) {
        len += 1;
        tmp_len = 0;

    } else {
        len += 1 + NGX_HTTP_V2_INT_OCTETS + r->method_name.len;
        tmp_len = r->method_name.len;
    }

    /* :scheme header */

    len += 1;

    /* :path header */

    if (r->valid_unparsed_uri) {
        escape = 0;
        uri_len = r->unparsed_uri.len;

    } else {
        escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
                                    NGX_ESCAPE_URI);
        uri_len = r->uri.len + escape + sizeof("?") - 1 + r->args.len;
    }

    len += 1 + NGX_HTTP_V2_INT_OCTETS + uri_len;

    if (tmp_len < uri_len) {
        tmp_len = uri_len;
    }

    /* :authority header */

    if (!glcf->host_set) {
        len += 1 + NGX_HTTP_V2_INT_OCTETS + glcf->host.len;

        if (tmp_len < glcf->host.len) {
            tmp_len = glcf->host.len;
        }
    }

    /* other headers */

    ngx_http_script_flush_no_cacheable_variables(r, glcf->headers.flushes);
    ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

    le.ip = glcf->headers.lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            continue;
        }

        len += 1 + NGX_HTTP_V2_INT_OCTETS + key_len
                 + NGX_HTTP_V2_INT_OCTETS + val_len;

        if (tmp_len < key_len) {
            tmp_len = key_len;
        }

        if (tmp_len < val_len) {
            tmp_len = val_len;
        }
    }

    if (glcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&glcf->headers.hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            len += 1 + NGX_HTTP_V2_INT_OCTETS + header[i].key.len
                     + NGX_HTTP_V2_INT_OCTETS + header[i].value.len;

            if (tmp_len < header[i].key.len) {
                tmp_len = header[i].key.len;
            }

            if (tmp_len < header[i].value.len) {
                tmp_len = header[i].value.len;
            }
        }
    }

    /* continuation frames */

    len += sizeof(ngx_http_grpc_frame_t)
           * (len / NGX_HTTP_V2_DEFAULT_FRAME_SIZE);


    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    tmp = ngx_palloc(r->pool, tmp_len * 3);
    if (tmp == NULL) {
        return NGX_ERROR;
    }

    key_tmp = tmp + tmp_len; /* 前tmp为key的位置 */
    val_tmp = tmp + 2 * tmp_len; /* 后2个tmp为val的位置 */

    /* connection preface */

#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (u->multiple) {
        u_char   *conn_tmp = b->last;
        b->last = ngx_copy(b->last, ngx_http_grpc_connection_start,
                           sizeof(ngx_http_grpc_connection_start) - 1);

        conn_tmp += sizeof(ngx_http_grpc_conn_preface) - 1;
        conn_tmp += NGX_HTTP_V2_FRAME_HEADER_SIZE;
        conn_tmp += NGX_HTTP_GRPC_SETTINGS_ITEM;
        conn_tmp += NGX_HTTP_GRPC_SETTINGS_ITEM;
        conn_tmp += NGX_HTTP_GRPC_SETTINGS_ID;

        /* change initial window size in settings frame to upstream's buffer_size */

        *conn_tmp++ = (u_char) ((u->conf->buffer_size >> 24) & 0xff);
        *conn_tmp++ = (u_char) ((u->conf->buffer_size >> 16) & 0xff);
        *conn_tmp++ = (u_char) ((u->conf->buffer_size >> 8) & 0xff);
        *conn_tmp++ = (u_char) (u->conf->buffer_size & 0xff);

        conn_tmp += NGX_HTTP_V2_FRAME_HEADER_SIZE;

        /* change window_update increment to 0 */
        
        *conn_tmp++ = (u_char) (0x00);
        *conn_tmp++ = (u_char) (0x00);

    } else {
        b->last = ngx_copy(b->last, ngx_http_grpc_connection_start,
                           sizeof(ngx_http_grpc_connection_start) - 1);
    }
#else
        b->last = ngx_copy(b->last, ngx_http_grpc_connection_start,
                           sizeof(ngx_http_grpc_connection_start) - 1);
#endif

    /* headers frame */

    headers_frame = b->last; /* 处理报文头 */

    f = (ngx_http_grpc_frame_t *) b->last;
    b->last += sizeof(ngx_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = NGX_HTTP_V2_HEADERS_FRAME; /* 标记frame为headers */
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 1;

    if (r->method == NGX_HTTP_GET) {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_METHOD_GET_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: GET\"");

    } else if (r->method == NGX_HTTP_POST) {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_METHOD_POST_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: POST\"");

    } else {
        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_METHOD_INDEX);
        b->last = ngx_http_v2_write_value(b->last, r->method_name.data,
                                          r->method_name.len, tmp);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: %V\"", &r->method_name);
    }

#if (NGX_HTTP_SSL)
    if (glcf->ssl) {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTPS_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":scheme: https\"");
    } else
#endif
    {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTP_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":scheme: http\"");
    }

    if (r->valid_unparsed_uri) {

        if (r->unparsed_uri.len == 1 && r->unparsed_uri.data[0] == '/') {
            *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_PATH_ROOT_INDEX);

        } else {
            *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX); /* r->unparsed_uri=/helloworld.Greeter/SayHello */
            b->last = ngx_http_v2_write_value(b->last, r->unparsed_uri.data, /* 给path　huffman编码 */
                                              r->unparsed_uri.len, tmp);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %V\"", &r->unparsed_uri);

    } else if (escape || r->args.len > 0) {
        p = val_tmp;

        if (escape) {
            p = (u_char *) ngx_escape_uri(p, r->uri.data, r->uri.len,
                                          NGX_ESCAPE_URI);

        } else {
            p = ngx_copy(p, r->uri.data, r->uri.len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = ngx_copy(p, r->args.data, r->args.len);
        }

        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
        b->last = ngx_http_v2_write_value(b->last, val_tmp, p - val_tmp, tmp);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %*s\"", p - val_tmp, val_tmp);

    } else {
        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
        b->last = ngx_http_v2_write_value(b->last, r->uri.data,
                                          r->uri.len, tmp);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %V\"", &r->uri);
    }

    if (!glcf->host_set) {
        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_AUTHORITY_INDEX);
        b->last = ngx_http_v2_write_value(b->last, glcf->host.data,
                                          glcf->host.len, tmp);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":authority: %V\"", &glcf->host);
    }

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = glcf->headers.values->elts;
    e.request = r;
    e.flushed = 1;

    le.ip = glcf->headers.lengths->elts;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }

        *b->last++ = 0;

        e.pos = key_tmp;

        code = *(ngx_http_script_code_pt *) e.ip;
        code((ngx_http_script_engine_t *) &e);

        b->last = ngx_http_v2_write_name(b->last, key_tmp, key_len, tmp);

        e.pos = val_tmp;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        b->last = ngx_http_v2_write_value(b->last, val_tmp, val_len, tmp);

#if (NGX_DEBUG)
        if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
            ngx_strlow(key_tmp, key_tmp, key_len);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc header: \"%*s: %*s\"",
                           key_len, key_tmp, val_len, val_tmp);
        }
#endif
    }

    if (glcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&glcf->headers.hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            *b->last++ = 0;

            b->last = ngx_http_v2_write_name(b->last, header[i].key.data, /* 写其他header */
                                             header[i].key.len, tmp);

            b->last = ngx_http_v2_write_value(b->last, header[i].value.data,
                                              header[i].value.len, tmp);

#if (NGX_DEBUG)
            if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
                ngx_strlow(tmp, header[i].key.data, header[i].key.len);

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header: \"%*s: %V\"",
                               header[i].key.len, tmp, &header[i].value);
            }
#endif
        }
    }

    /* update headers frame length */

    len = b->last - headers_frame - sizeof(ngx_http_grpc_frame_t);

    if (len > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
        len = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
        next = 1;

    } else {
        next = 0;
    }

    f = (ngx_http_grpc_frame_t *) headers_frame;

    f->length_0 = (u_char) ((len >> 16) & 0xff);
    f->length_1 = (u_char) ((len >> 8) & 0xff);
    f->length_2 = (u_char) (len & 0xff);

    /* create additional continuation frames */

    p = headers_frame;

    while (next) {
        p += sizeof(ngx_http_grpc_frame_t) + NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
        len = b->last - p;

        ngx_memmove(p + sizeof(ngx_http_grpc_frame_t), p, len);
        b->last += sizeof(ngx_http_grpc_frame_t);

        if (len > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
            len = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
            next = 1;

        } else {
            next = 0;
        }

        f = (ngx_http_grpc_frame_t *) p;

        f->length_0 = (u_char) ((len >> 16) & 0xff);
        f->length_1 = (u_char) ((len >> 8) & 0xff);
        f->length_2 = (u_char) (len & 0xff);
        f->type = NGX_HTTP_V2_CONTINUATION_FRAME;
        f->flags = 0;
        f->stream_id_0 = 0;
        f->stream_id_1 = 0;
        f->stream_id_2 = 0;
        f->stream_id_3 = 1;
    }

    f->flags |= NGX_HTTP_V2_END_HEADERS_FLAG;

#if (NGX_DEBUG)
    if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
        u_char  buf[512];
        size_t  n, m;

        n = ngx_min(b->last - b->pos, 256);
        m = ngx_hex_dump(buf, b->pos, n) - buf;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: %*s%s, len: %uz",
                       m, buf, b->last - b->pos > 256 ? "..." : "",
                       b->last - b->pos);
    }
#endif

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

    } else {

        body = u->request_bufs;
        u->request_bufs = cl;　/* cl->buf是报文的buf 构造的报文挂上去了 */

        if (body == NULL) {
            f = (ngx_http_grpc_frame_t *) headers_frame;
            f->flags |= NGX_HTTP_V2_END_STREAM_FLAG; /* body为空 设置EOS */
        }

        while (body) { /* 把剩下的body内容加到cl->next...里 */
            b = ngx_alloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

            cl->next = ngx_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

        b->last_buf = 1;
    }

    u->output.output_filter = ngx_http_grpc_body_output_filter; /* 设置output的filter函数 */
    u->output.filter_ctx = r; /* 设置它为r */

    b->flush = 1;
    cl->next = NULL;

#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (u->multiple) {
        u->read_state = ngx_http_multi_ups_st_header;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_reinit_request(ngx_http_request_t *r)
{
    ngx_http_grpc_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_grpc_module);

    if (ctx == NULL) {
        return NGX_OK;
    }
                  
    ctx->state = 0;
    ctx->header_sent = 0;
    ctx->output_closed = 0;
    ctx->parsing_headers = 0;
    ctx->end_stream = 0;
    ctx->status = 0;
    ctx->connection = NULL; /* 这里注意了 因为新的connect之后 要设置成新的conn_ctx */

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_body_output_filter(void *data, ngx_chain_t *in) /* 在output_chain里面调用 */
{
    ngx_http_request_t  *r = data;

    off_t                   file_pos;
    u_char                 *p, *pos, *start;
    size_t                  len, limit;
    ngx_buf_t              *b;
    ngx_int_t               rc;
    ngx_uint_t              next, last;
    ngx_chain_t            *cl, *out, **ll;
    ngx_http_grpc_ctx_t    *ctx;
    ngx_http_grpc_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output filter");

    ctx = ngx_http_grpc_get_ctx(r); /* 这里应该是第一次调用的地方 也就是将conn_t放到cleanup里面 */

    if (ctx == NULL) {
        return NGX_ERROR;
    }

#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (u->multiple) {
        u->mus->conn_ctx->connection = u->mus->conn_ctx->connection ?
                                       u->mus->conn_ctx->connection : 
                                       ctx->connection;
    }
#endif

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) { /* 把in copy到grpc的ctx->in里 */
            return NGX_ERROR;
        }
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) { /* 更新stream id */
        /* first buffer contains headers */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output header");

        ctx->header_sent = 1;

        if (ctx->id != 1) {
            /*
             * keepalive connection: skip connection preface,
             * update stream identifiers
             */

            b = ctx->in->buf;
            b->pos += sizeof(ngx_http_grpc_connection_start) - 1;

            p = b->pos;

            while (p < b->last) { /* 循环ok的 */
                f = (ngx_http_grpc_frame_t *) p;
                p += sizeof(ngx_http_grpc_frame_t);

                f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
                f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
                f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
                f->stream_id_3 = (u_char) (ctx->id & 0xff);

                p += (f->length_0 << 16) + (f->length_1 << 8) + f->length_2;
            }
        }

        if (ctx->in->buf->last_buf) {
            ctx->output_closed = 1;
        }

        *ll = ctx->in; /* out = ctx->in ctx->in->buf为header buf*/
        ll = &ctx->in->next;

        ctx->in = ctx->in->next;
    }

    if (ctx->out) { /* 这就是在其他地方写的send settings_ack/send window_update */
        /* queued control frames */

        *ll = ctx->out; /* 这里是为了把ctx->out挂到out上 */

        for (cl = ctx->out, ll = &cl->next; cl; cl = cl->next) {
            ll = &cl->next;
        }

        ctx->out = NULL;
    }

#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    /*
     * Each upstream going to send chain will check
     * if there's control frame of the connection needed
     * to be sent first, and according to the protocol, 
     * control frames are exempt from window limitation.
     */
    if (r->upstream->multiple) {
        ngx_http_grpc_ctx_t    *conn_ctx = r->upstream->mus->conn_ctx;
        if (conn_ctx->out) {
            *ll = conn_ctx->out;
            for (cl = conn_ctx->out, ll = &cl->next; cl; cl = cl->next) {
                ll = &cl->next;
            }
            conn_ctx->out = NULL;/* 清空了bingo! */
        }
    }
#endif

    f = NULL;
    last = 0;

    limit = ngx_max(0, ctx->send_window); /* 从这里也可以看出limit是不管上面的frame control的 */

    if (limit > ctx->connection->send_window) {
        limit = ctx->connection->send_window;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->connection->send_window);

#if (NGX_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
    cl = NULL;
#endif

    in = ctx->in; /* 不包括header frame */

    while (in && limit > 0) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "grpc output in  l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       in->buf->last - in->buf->pos,
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        if (ngx_buf_special(in->buf)) { /* 这个buf的标志满足某些条件时 */
            goto next;
        }

        if (in->buf->in_file) {
            file_pos = in->buf->file_pos;

        } else {
            pos = in->buf->pos; /* 上次没发送完的 */
        }

        next = 0;

        do {

            cl = ngx_http_grpc_get_buf(r, ctx);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            f = (ngx_http_grpc_frame_t *) b->last; /* 第一个buf存头 */
            b->last += sizeof(ngx_http_grpc_frame_t);

            *ll = cl;
            ll = &cl->next;

            cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf; /* 第二个buf存数据 */
            start = b->start;

            ngx_memcpy(b, in->buf, sizeof(ngx_buf_t));

            /*
             * restore b->start to preserve memory allocated in the buffer,
             * to reuse it later for headers and control frames
             */

            b->start = start;

            if (in->buf->in_file) { /* 上次没发完在文件中  */
                b->file_pos = file_pos;
                file_pos += ngx_min(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (file_pos >= in->buf->file_last) {
                    file_pos = in->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (ngx_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += ngx_min(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (pos >= in->buf->last) {
                    pos = in->buf->last;
                    next = 1; /* 存下了 设为1 */
                }

                b->last = pos;
                len = (ngx_uint_t) (pos - b->pos);
            }

            b->tag = (ngx_buf_tag_t) &ngx_http_grpc_body_output_filter;
            b->shadow = in->buf;
            b->last_shadow = next;

            b->last_buf = 0;
            b->last_in_chain = 0;

            *ll = cl;
            ll = &cl->next;

            f->length_0 = (u_char) ((len >> 16) & 0xff);
            f->length_1 = (u_char) ((len >> 8) & 0xff);
            f->length_2 = (u_char) (len & 0xff);
            f->type = NGX_HTTP_V2_DATA_FRAME;
            f->flags = 0;
            f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->id & 0xff);

            limit -= len;
            ctx->send_window -= len;
            ctx->connection->send_window -= len;

        } while (!next && limit > 0); /* 可能会发送几个frame */

        if (!next) { /* 几个frame发了 而limit导致一次不能发太多 于是还剩下没发完的 */
            /*
             * if the buffer wasn't fully sent due to flow control limits,
             * preserve position for future use
             */

            if (in->buf->in_file) { /* 这个存着其实没关系啦 反正是包装好的frame 没发完的就在in里了 */
                in->buf->file_pos = file_pos;

            } else {
                in->buf->pos = pos;
            }

            break;
        }

    next: /* 处理special */

        if (in->buf->last_buf) { /* 满足last_buf */
            last = 1;
        }

        in = in->next;
    }

    ctx->in = in; /* 更新ctx->in是剩下的内容 */

    if (last) { /* 最后一个buf才会发EOS */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output last");

        ctx->output_closed = 1;

        if (f) {
            f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;

        } else {
            cl = ngx_http_grpc_get_buf(r, ctx);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            f = (ngx_http_grpc_frame_t *) b->last;
            b->last += sizeof(ngx_http_grpc_frame_t);

            f->length_0 = 0;
            f->length_1 = 0;
            f->length_2 = 0;
            f->type = NGX_HTTP_V2_DATA_FRAME;
            f->flags = NGX_HTTP_V2_END_STREAM_FLAG;
            f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->id & 0xff);

            *ll = cl;
            ll = &cl->next;
        }

        cl->buf->last_buf = 1;
    }

    *ll = NULL;

#if (NGX_DEBUG)

    for (cl = out; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "grpc output out l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->connection->send_window);

#endif

    rc = ngx_chain_writer(&r->upstream->writer, out); /* 发送数据! */

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_grpc_body_output_filter);

    for (cl = ctx->free; cl; cl = cl->next) {

        /* mark original buffers as sent */

        if (cl->buf->shadow) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last; /* 标志已经发送了 */
            }

            cl->buf->shadow = NULL;
        }
    }

    if (rc == NGX_OK && ctx->in) { /* 没发送完或者blabla */
        rc = NGX_AGAIN;
    }

    return rc;
}

 /* 先调用这个函数再grpc filter(input_filter)
  * 虽然这个看起来返回了很多种错误情况
  * 但是在原来的process_header中其实只处理了三种情况 AGAIN ERROR INVALIDHEADER
  * 而且对于多路复用 AGAIN 有可能 (continuation frame)
  * AGAIN还有的情况是 解析完一个frame发现还有剩余在buf里
  */
static ngx_int_t
ngx_http_grpc_process_header(ngx_http_request_t *r)
{
    ngx_str_t                      *status_line;
    ngx_int_t                       rc, status;
    ngx_buf_t                      *b;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_grpc_ctx_t            *ctx;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    u = r->upstream;
    b = &u->buffer;

#if (NGX_DEBUG)
    if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
        u_char  buf[512];
        size_t  n, m;

        n = ngx_min(b->last - b->pos, 256);
        m = ngx_hex_dump(buf, b->pos, n) - buf;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc response: %*s%s, len: %uz",
                       m, buf, b->last - b->pos > 256 ? "..." : "",
                       b->last - b->pos);
    }
#endif

    ctx = ngx_http_grpc_get_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;; ) { /* 一个接一个的处理frame 可惜我们的upstream多路复用之后是一个frame一个frame传进来的 */

        if (ctx->state < ngx_http_grpc_st_payload) { /* 状态是在处理payload前 */

            rc = ngx_http_grpc_parse_frame(r, ctx, b);

            if (rc == NGX_AGAIN) { /* 多路复用不会 这个只当连stream都不能解析完全时 */

                /*
                 * there can be a lot of window update frames,
                 * so we reset buffer if it is empty and we haven't
                 * started parsing headers yet
                 */
                /* 这里就是为了buffer大小小于一个frame的情况? */
                if (!ctx->parsing_headers) {
                    b->pos = b->start;
                    b->last = b->pos;
                }

                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /*
             * RFC 7540 says that implementations MUST discard frames
             * that have unknown or unsupported types.  However, extension
             * frames that appear in the middle of a header block are
             * not permitted.  Also, for obvious reasons CONTINUATION frames
             * cannot appear before headers, and DATA frames are not expected
             * to appear before all headers are parsed.
             */

            if (ctx->type == NGX_HTTP_V2_DATA_FRAME
                || (ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME
                    && !ctx->parsing_headers)
                || (ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers)) /* parsing_headers 表示正在解析头部的过程中 */
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->stream_id && ctx->stream_id != ctx->id) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        /* frame payload */

        if (ctx->type == NGX_HTTP_V2_RST_STREAM_FRAME) {

            rc = ngx_http_grpc_parse_rst_stream(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          ctx->error);

            return NGX_HTTP_UPSTREAM_INVALID_HEADER; /* 通过返回这个来结束 */
        }

        if (ctx->type == NGX_HTTP_V2_GOAWAY_FRAME) {

            rc = ngx_http_grpc_parse_goaway(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /*
             * If stream_id is lower than one we use, our
             * request won't be processed and needs to be retried.
             * If stream_id is greater or equal to the one we use,
             * we can continue normally (except we can't use this
             * connection for additional requests).  If there is
             * a real error, the connection will be closed.
             */

            if (ctx->stream_id < ctx->id) {

                /* TODO: we can retry non-idempotent requests */

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent goaway with error %ui",
                              ctx->error);

                return NGX_HTTP_UPSTREAM_INVALID_HEADER; /* 返回invalid_header会retry */
            }

            continue; /* 不受影响继续走 */
        }

        if (ctx->type == NGX_HTTP_V2_WINDOW_UPDATE_FRAME) {

            rc = ngx_http_grpc_parse_window_update(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->in) {
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                if (u->multiple) {
                    ngx_queue_insert_tail(&u->mus->wait_write_queue, u);
                }
#endif
                ngx_post_event(u->peer.connection->write, &ngx_posted_events);
            }

            continue;
        }

        if (ctx->type == NGX_HTTP_V2_SETTINGS_FRAME) {

            rc = ngx_http_grpc_parse_settings(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->in) {
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                if (u->multiple) {
                    ngx_queue_insert_tail(&u->mus->wait_write_queue, u);
                }
#endif
                ngx_post_event(u->peer.connection->write, &ngx_posted_events);
            }

            continue;
        }

        if (ctx->type == NGX_HTTP_V2_PING_FRAME) {

            rc = ngx_http_grpc_parse_ping(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                if (u->multiple) {
                    ngx_queue_insert_tail(&u->mus->wait_write_queue, u);
                }
#endif
            ngx_post_event(u->peer.connection->write, &ngx_posted_events);
            continue;
        }

        if (ctx->type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent unexpected push promise frame");
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (ctx->type != NGX_HTTP_V2_HEADERS_FRAME
            && ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME)
        {
            /* priority, unknown frames */

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return NGX_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = ngx_http_grpc_st_start;

            continue;
        }

        /* headers */

        for ( ;; ) {

            rc = ngx_http_grpc_parse_header(r, ctx, b);

            if (rc == NGX_AGAIN) { /* 可能，比如还没收到 continuation frame 会跳到下面的NGX_AGAIN */
                break;
            }

            if (rc == NGX_OK) {

                /* a header line has been parsed successfully */

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header: \"%V: %V\"",
                               &ctx->name, &ctx->value);

                if (ctx->name.len && ctx->name.data[0] == ':') {

                    if (ctx->name.len != sizeof(":status") - 1
                        || ngx_strncmp(ctx->name.data, ":status",
                                       sizeof(":status") - 1)
                           != 0)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid header \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (ctx->status) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent duplicate :status header");
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status_line = &ctx->value;

                    if (status_line->len != 3) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status = ngx_atoi(status_line->data, 3);

                    if (status == NGX_ERROR) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (status < NGX_HTTP_OK) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent unexpected :status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    u->headers_in.status_n = status;

                    if (u->state && u->state->status == 0) {
                        u->state->status = status;
                    }

                    ctx->status = 1;

                    continue;

                } else if (!ctx->status) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent no :status header");
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                h = ngx_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->key = ctx->name;
                h->value = ctx->value;
                h->lowcase_key = h->key.data;
                h->hash = ngx_hash_key(h->key.data, h->key.len);

                hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                                   h->lowcase_key, h->key.len);

                if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                    return NGX_ERROR;
                }

                continue;
            }

            if (rc == NGX_HTTP_PARSE_HEADER_DONE) { /* 解析完成看看是不是EOS */

                /* a whole header has been parsed successfully */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header done");

                if (ctx->end_stream) {
                    u->headers_in.content_length_n = 0;

                    if (ctx->in == NULL
                        && ctx->out == NULL
                        && ctx->output_closed
                        && b->last == b->pos)
                    {
                        u->keepalive = 1; /* 这里意思可能是保证如果是keepalive就ok吧 如果没开启那就没用咯 */
                    }
                }

                return NGX_OK;
            }

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /* rc == NGX_AGAIN */

        /* 如果parse_header返回AGAIN 且这个frame处理完 就会继续走for */
        if (ctx->rest == 0) {
            ctx->state = ngx_http_grpc_st_start;
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
            if (u->multiple) {
                return NGX_DONE;
            }
#endif
            continue;
        }
        /* 否则要继续把这个frame接收完 */
        return NGX_AGAIN;
    }
}


static ngx_int_t
ngx_http_grpc_filter_init(void *data)
{
    ngx_http_grpc_ctx_t  *ctx = data;

    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    r = ctx->request;
    u = r->upstream;

    u->length = 1;

    if (ctx->end_stream) {
        u->length = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_filter(void *data, ssize_t bytes) /* 向下游转发 这个函数在send_response里只被关心是不是返回ERROR */
{
    ngx_http_grpc_ctx_t  *ctx = data;

    ngx_int_t             rc;
    ngx_buf_t            *b, *buf;
    ngx_chain_t          *cl, **ll;
    ngx_table_elt_t      *h;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    r = ctx->request;
    u = r->upstream;
    b = &u->buffer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc filter bytes:%z", bytes);

    b->pos = b->last;
    b->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    } /* 找到out_bufs最后端 */

    for ( ;; ) { /* 专注于处理DATA frame */

        if (ctx->state < ngx_http_grpc_st_payload) { /* 处理payload之前 */

            rc = ngx_http_grpc_parse_frame(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if ((ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME
                 && !ctx->parsing_headers)
                || (ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers))
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return NGX_ERROR;
            }

            if (ctx->type == NGX_HTTP_V2_DATA_FRAME) {

                if (ctx->stream_id != ctx->id) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent data frame "
                                  "for unknown stream %ui",
                                  ctx->stream_id);
                    return NGX_ERROR;
                }

                if (ctx->rest > ctx->recv_window) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream violated stream flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->recv_window);
                    return NGX_ERROR;
                }

                if (ctx->rest > ctx->connection->recv_window) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream violated connection flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->connection->recv_window);
                    return NGX_ERROR;
                }

                ctx->recv_window -= ctx->rest; /* 一起减分开加的 一起减 */
                ctx->connection->recv_window -= ctx->rest;

#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                if (u->multiple) {
                    if (ctx->connection->recv_window < mus->buffer_size / 4
                        || ctx->recv_window < u->conf->buffer_size / 4))
                    {
                        if (ngx_http_grpc_send_window_update(r, ctx) != NGX_OK) {
                            return NGX_ERROR;
                        }
                    
                        ngx_queue_insert_tail(&u->mus->wait_write_queue, u);
                        ngx_post_event(u->peer.connection->write,
                                       &ngx_posted_events);
                    }

                } else {
#endif
                if (ctx->connection->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4
                    || ctx->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4)
                {
                    if (ngx_http_grpc_send_window_update(r, ctx) != NGX_OK) {
                        return NGX_ERROR;
                    }
                    
                    ngx_post_event(u->peer.connection->write, /* 这里应该就是为了写window_update */
                                   &ngx_posted_events);
                }
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                }
#endif
            }
            
            if (ctx->stream_id && ctx->stream_id != ctx->id) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return NGX_ERROR;
            }

            ctx->padding = 0;
        }
        /* 开始处理padding */
        if (ctx->state == ngx_http_grpc_st_padding) {

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return NGX_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = ngx_http_grpc_st_start;

            if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                u->length = 0;

                if (ctx->in == NULL
                    && ctx->out == NULL
                    && ctx->output_closed
                    && b->last == b->pos)
                {
                    u->keepalive = 1;
                }

                break;
            }

            continue;
        }

        /* frame payload */

        if (ctx->type == NGX_HTTP_V2_RST_STREAM_FRAME) {

            rc = ngx_http_grpc_parse_rst_stream(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          ctx->error);

            return NGX_ERROR;
        }

        if (ctx->type == NGX_HTTP_V2_GOAWAY_FRAME) {

            rc = ngx_http_grpc_parse_goaway(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            /*
             * If stream_id is lower than one we use, our
             * request won't be processed and needs to be retried.
             * If stream_id is greater or equal to the one we use,
             * we can continue normally (except we can't use this
             * connection for additional requests).  If there is
             * a real error, the connection will be closed.
             */

            if (ctx->stream_id < ctx->id) {

                /* TODO: we can retry non-idempotent requests */

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent goaway with error %ui",
                              ctx->error);

                return NGX_ERROR;
            }

            continue;
        }

        if (ctx->type == NGX_HTTP_V2_WINDOW_UPDATE_FRAME) {

            rc = ngx_http_grpc_parse_window_update(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (ctx->in) {
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                if (u->multiple) {
                    ngx_queue_insert_tail(&u->mus->wait_write_queue, u);
                }
#endif
                ngx_post_event(u->peer.connection->write, &ngx_posted_events);
            }

            continue;
        }

        if (ctx->type == NGX_HTTP_V2_SETTINGS_FRAME) {

            rc = ngx_http_grpc_parse_settings(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (ctx->in) {
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                if (u->multiple) {
                    ngx_queue_insert_tail(&u->mus->wait_write_queue, u);
                }
#endif
                ngx_post_event(u->peer.connection->write, &ngx_posted_events);
            }

            continue;
        }

        if (ctx->type == NGX_HTTP_V2_PING_FRAME) {

            rc = ngx_http_grpc_parse_ping(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                if (u->multiple) {
                    ngx_queue_insert_tail(&u->mus->wait_write_queue, u);
                }
#endif
            ngx_post_event(u->peer.connection->write, &ngx_posted_events);
            continue;
        }

        if (ctx->type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent unexpected push promise frame");
            return NGX_ERROR;
        }

        if (ctx->type == NGX_HTTP_V2_HEADERS_FRAME
            || ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME) /* 处理 trailer */
        {
            for ( ;; ) {

                rc = ngx_http_grpc_parse_header(r, ctx, b);

                if (rc == NGX_AGAIN) {
                    break;
                }

                if (rc == NGX_OK) {

                    /* a header line has been parsed successfully */

                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "grpc trailer: \"%V: %V\"",
                                   &ctx->name, &ctx->value);

                    if (ctx->name.len && ctx->name.data[0] == ':') {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid "
                                      "trailer \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return NGX_ERROR;
                    }

                    h = ngx_list_push(&u->headers_in.trailers);
                    if (h == NULL) {
                        return NGX_ERROR;
                    }

                    h->key = ctx->name;
                    h->value = ctx->value;
                    h->lowcase_key = h->key.data;
                    h->hash = ngx_hash_key(h->key.data, h->key.len);

                    continue;
                }

                if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

                    /* a whole header has been parsed successfully */

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "grpc trailer done");

                    if (ctx->end_stream) {
                        u->length = 0;

                        if (ctx->in == NULL
                            && ctx->out == NULL
                            && ctx->output_closed
                            && b->last == b->pos)
                        {
                            u->keepalive = 1;
                        }

                        return NGX_OK;
                    }

                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent trailer without "
                                  "end stream flag");
                    return NGX_ERROR;
                }

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid trailer");

                return NGX_ERROR;
            }

            /* rc == NGX_AGAIN */

            if (ctx->rest == 0) {
                ctx->state = ngx_http_grpc_st_start;
                continue;
            }

            return NGX_AGAIN;
        }

        if (ctx->type != NGX_HTTP_V2_DATA_FRAME) {

            /* priority, unknown frames */

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return NGX_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = ngx_http_grpc_st_start;

            continue;
        }

        /*
         * data frame:
         *
         * +---------------+
         * |Pad Length? (8)|
         * +---------------+-----------------------------------------------+
         * |                            Data (*)                         ...
         * +---------------------------------------------------------------+
         * |                           Padding (*)                       ...
         * +---------------------------------------------------------------+
         */

        if (ctx->flags & NGX_HTTP_V2_PADDED_FLAG) {

            if (ctx->rest == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too short http2 frame");
                return NGX_ERROR;
            }

            if (b->pos == b->last) {
                return NGX_AGAIN;
            }

            ctx->flags &= ~NGX_HTTP_V2_PADDED_FLAG;
            ctx->padding = *b->pos++;
            ctx->rest -= 1;

            if (ctx->padding > ctx->rest) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 frame with too long "
                              "padding: %d in frame %uz",
                              ctx->padding, ctx->rest);
                return NGX_ERROR;
            }

            continue;
        }

        if (ctx->rest == ctx->padding) {
            goto done;
        }

        if (b->pos == b->last) {
            return NGX_AGAIN;
        }

        cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        buf = cl->buf;

        buf->flush = 1;
        buf->memory = 1;

        buf->pos = b->pos;
        buf->tag = u->output.tag;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output buf %p", buf->pos);

        if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;
            buf->last = b->pos;

            return NGX_AGAIN;
        }

        b->pos += ctx->rest - ctx->padding;
        buf->last = b->pos;
        ctx->rest = ctx->padding;

    done:

        if (ctx->padding) {
            ctx->state = ngx_http_grpc_st_padding;
            continue;
        }

        ctx->state = ngx_http_grpc_st_start;

        if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
            u->length = 0;

            if (ctx->in == NULL
                && ctx->out == NULL
                && ctx->output_closed
                && b->last == b->pos)
            {
                u->keepalive = 1;
            }

            break;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_parse_frame(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx, /* 这里把frame里的length stream_id都解析出来了 */
    ngx_buf_t *b)
{
    u_char                 ch, *p;
    ngx_http_grpc_state_e  state;

    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case ngx_http_grpc_st_start:
            ctx->rest = ch << 16;
            state = ngx_http_grpc_st_length_2;
            break;

        case ngx_http_grpc_st_length_2:
            ctx->rest |= ch << 8;
            state = ngx_http_grpc_st_length_3;
            break;

        case ngx_http_grpc_st_length_3:
            ctx->rest |= ch;

            if (ctx->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 frame: %uz",
                              ctx->rest);
                return NGX_ERROR;
            }

            state = ngx_http_grpc_st_type;
            break;

        case ngx_http_grpc_st_type:
            ctx->type = ch;
            state = ngx_http_grpc_st_flags;
            break;

        case ngx_http_grpc_st_flags:
            ctx->flags = ch;
            state = ngx_http_grpc_st_stream_id;
            break;

        case ngx_http_grpc_st_stream_id:
            ctx->stream_id = (ch & 0x7f) << 24;
            state = ngx_http_grpc_st_stream_id_2;
            break;

        case ngx_http_grpc_st_stream_id_2:
            ctx->stream_id |= ch << 16;
            state = ngx_http_grpc_st_stream_id_3;
            break;

        case ngx_http_grpc_st_stream_id_3:
            ctx->stream_id |= ch << 8;
            state = ngx_http_grpc_st_stream_id_4;
            break;

        case ngx_http_grpc_st_stream_id_4:
            ctx->stream_id |= ch;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc frame: %d, len: %uz, f:%d, i:%ui",
                           ctx->type, ctx->rest, ctx->flags, ctx->stream_id);

            b->pos = p + 1; /* 向前进一个字节 */

            ctx->state = ngx_http_grpc_st_payload;
            ctx->frame_state = 0;

            return NGX_OK; /* 后面的是data要单独处理 */

        /* suppress warning */
        case ngx_http_grpc_st_payload:
        case ngx_http_grpc_st_padding:
            break;
        }
    }

    b->pos = p; /* 更新b->pos表示在此之前的都处理了 */
    ctx->state = state;

    return NGX_AGAIN; /* 没有在case stream_id_3退出 说明没完 但是多路复用不会有这个问题 */
}


static ngx_int_t
ngx_http_grpc_parse_header(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
    ngx_buf_t *b)
{
    u_char     ch, *p, *last;
    size_t     min;
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_padding_length,
        sw_dependency,
        sw_dependency_2,
        sw_dependency_3,
        sw_dependency_4,
        sw_weight,
        sw_fragment,
        sw_padding
    } state;

    state = ctx->frame_state;

    if (state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc parse header: start");

        if (ctx->type == NGX_HTTP_V2_HEADERS_FRAME) {
            ctx->parsing_headers = 1; /* 表示正在解析header */
            ctx->fragment_state = 0; /* 处理头部压缩的 有点复杂 没看 */

            min = (ctx->flags & NGX_HTTP_V2_PADDED_FLAG ? 1 : 0)
                  + (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

            if (ctx->rest < min) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent headers frame "
                              "with invalid length: %uz",
                              ctx->rest);
                return NGX_ERROR;
            }

            if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                ctx->end_stream = 1;
            }

            if (ctx->flags & NGX_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
            state = sw_fragment;
        }

        ctx->padding = 0;
        ctx->frame_state = state;
    }

    if (state < sw_fragment) { /* 这一步是在过滤 如果现在<fragment 什么情况下可以接下去走fragment了 */

        if (b->last - b->pos < (ssize_t) ctx->rest) {
            last = b->last;

        } else {
            last = b->pos + ctx->rest;
        }

        for (p = b->pos; p < last; p++) {
            ch = *p;

#if 0
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc header byte: %02Xd s:%d", ch, state);
#endif

            /*
             * headers frame:
             *
             * +---------------+
             * |Pad Length? (8)|
             * +-+-------------+----------------------------------------------+
             * |E|                 Stream Dependency? (31)                    |
             * +-+-------------+----------------------------------------------+
             * |  Weight? (8)  |
             * +-+-------------+----------------------------------------------+
             * |                   Header Block Fragment (*)                ...
             * +--------------------------------------------------------------+
             * |                           Padding (*)                      ...
             * +--------------------------------------------------------------+
             */

            switch (state) {

            case sw_padding_length:

                ctx->padding = ch;

                if (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                    state = sw_dependency;
                    break;
                }

                goto fragment;

            case sw_dependency:
                state = sw_dependency_2;
                break;

            case sw_dependency_2:
                state = sw_dependency_3;
                break;

            case sw_dependency_3:
                state = sw_dependency_4;
                break;

            case sw_dependency_4:
                state = sw_weight;
                break;

            case sw_weight:
                goto fragment;

            /* suppress warning */
            case sw_start:
            case sw_fragment:
            case sw_padding:
                break;
            }
        }

        ctx->rest -= p - b->pos;
        b->pos = p;
        /* 当state = start/fragment/padding 就会返回这个 感觉不可能阿 除非是其他类型的frame */
        ctx->frame_state = state;
        return NGX_AGAIN;

    fragment: /* 真正解压头部字段 */

        p++;
        ctx->rest -= p - b->pos;
        b->pos = p;

        if (ctx->padding > ctx->rest) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent http2 frame with too long "
                          "padding: %d in frame %uz",
                          ctx->padding, ctx->rest);
            return NGX_ERROR;
        }

        state = sw_fragment;
        ctx->frame_state = state;
    }

    if (state == sw_fragment) {

        rc = ngx_http_grpc_parse_fragment(r, ctx, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN; /* 多路复用不可能 */
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {
            return NGX_OK;
        }

        /* rc == NGX_DONE */

        state = sw_padding;
        ctx->frame_state = state;
    }

    if (state == sw_padding) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;

            return NGX_AGAIN; /* 这个应该也是不可能的吧 */
        }

        b->pos += ctx->rest;
        ctx->rest = 0;

        ctx->state = ngx_http_grpc_st_start;

        if (ctx->flags & NGX_HTTP_V2_END_HEADERS_FLAG) {

            if (ctx->fragment_state) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent truncated http2 header");
                return NGX_ERROR;
            }

            ctx->parsing_headers = 0;

            return NGX_HTTP_PARSE_HEADER_DONE; /* 会返回DONE */
        }
        /* 这个是有可能的 所以上面没有把parsing_headers设为0 */
        return NGX_AGAIN;
    }

    /* unreachable */

    return NGX_ERROR;
}


/* 调用一次只会解析一个header 最后一次(针对一个frame) 会返回DONE */
/* 如果一个frame不够 则会返回AGAIN */
static ngx_int_t
ngx_http_grpc_parse_fragment(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
    ngx_buf_t *b)
{
    u_char      ch, *p, *last;
    size_t      size;
    ngx_uint_t  index, size_update;
    enum {
        sw_start = 0,
        sw_index,
        sw_name_length,
        sw_name_length_2,
        sw_name_length_3,
        sw_name_length_4,
        sw_name,
        sw_name_bytes,
        sw_value_length,
        sw_value_length_2,
        sw_value_length_3,
        sw_value_length_4,
        sw_value,
        sw_value_bytes
    } state;

    /* header block fragment */

#if 0
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc header fragment %p:%p rest:%uz",
                   b->pos, b->last, ctx->rest);
#endif

    if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest - ctx->padding;
    }

    state = ctx->fragment_state;

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->index = 0;

            if ((ch & 0x80) == 0x80) {
                /*
                 * indexed header:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 1 |        Index (7+)         |
                 * +---+---------------------------+
                 */

                index = ch & ~0x80;

                if (index == 0 || index > 61) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc indexed header: %ui", index);

                ctx->index = index;
                ctx->literal = 0;

                goto done;

            } else if ((ch & 0xc0) == 0x40) {
                /*
                 * literal header with incremental indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |      Index (6+)       |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |           0           |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xc0;

                if (index > 61) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header: %ui", index);

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xe0) == 0x20) {
                /*
                 * dynamic table size update:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 1 |   Max size (5+)   |
                 * +---+---------------------------+
                 */

                size_update = ch & ~0xe0;

                if (size_update > 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "dynamic table size update: %ui",
                                  size_update);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc table size update: %ui", size_update);

                break;

            } else if ((ch & 0xf0) == 0x10) {
                /*
                 *  literal header field never indexed:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header never indexed: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xf0) == 0x00) {
                /*
                 * literal header field without indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header without indexing: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;
            }

            /* not reached */

            return NGX_ERROR;

        case sw_index:
            ctx->index = ctx->index + (ch & ~0x80);

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 table index "
                              "with continuation flag");
                return NGX_ERROR;
            }

            if (ctx->index > 61) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid http2 "
                              "table index: %ui", ctx->index);
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc header index: %ui", ctx->index);

            state = sw_value_length;
            break;

        case sw_name_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_name_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent zero http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_name_length_3;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_name_length_4;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name:
            ctx->name.len = ctx->field_huffman ?
                            ctx->field_length * 8 / 5 : ctx->field_length;

            ctx->name.data = ngx_pnalloc(r->pool, ctx->name.len + 1);
            if (ctx->name.data == NULL) {
                return NGX_ERROR;
            }

            ctx->field_end = ctx->name.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_name_bytes;

            /* fall through */

        case sw_name_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc name: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (ngx_http_v2_huff_decode(&ctx->field_state, p, size,
                                            &ctx->field_end,
                                            ctx->field_rest == 0,
                                            r->connection->log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                ctx->name.len = ctx->field_end - ctx->name.data;
                ctx->name.data[ctx->name.len] = '\0';

            } else {
                ctx->field_end = ngx_cpymem(ctx->field_end, p, size);
                ctx->name.data[ctx->name.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                state = sw_value_length;
            }

            break;

        case sw_value_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_value_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                ngx_str_set(&ctx->value, "");
                goto done;
            }

            state = sw_value;
            break;

        case sw_value_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_value_length_3;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_value_length_4;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length");
                return NGX_ERROR;
            }

            state = sw_value;
            break;

        case sw_value:
            ctx->value.len = ctx->field_huffman ?
                             ctx->field_length * 8 / 5 : ctx->field_length;

            ctx->value.data = ngx_pnalloc(r->pool, ctx->value.len + 1);
            if (ctx->value.data == NULL) {
                return NGX_ERROR;
            }

            ctx->field_end = ctx->value.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_value_bytes;

            /* fall through */

        case sw_value_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc value: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (ngx_http_v2_huff_decode(&ctx->field_state, p, size,
                                            &ctx->field_end,
                                            ctx->field_rest == 0,
                                            r->connection->log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                ctx->value.len = ctx->field_end - ctx->value.data;
                ctx->value.data[ctx->value.len] = '\0';

            } else {
                ctx->field_end = ngx_cpymem(ctx->field_end, p, size);
                ctx->value.data[ctx->value.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                goto done;
            }

            break;
        }

        continue; /* 如果上面switch case里没有 goto done，就会continue for */

    done: /* 意味着一个头解析完成 会返回 */

        p++;
        ctx->rest -= p - b->pos;
        ctx->fragment_state = sw_start;
        b->pos = p;

        if (ctx->index) {
            ctx->name = *ngx_http_v2_get_static_name(ctx->index);
        }

        if (ctx->index && !ctx->literal) {
            ctx->value = *ngx_http_v2_get_static_value(ctx->index);
        }

        if (!ctx->index) {
            if (ngx_http_grpc_validate_header_name(r, &ctx->name) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return NGX_ERROR;
            }
        }

        if (!ctx->index || ctx->literal) {
            if (ngx_http_grpc_validate_header_value(r, &ctx->value) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return NGX_ERROR;
            }
        }

        return NGX_OK;
    }

    ctx->rest -= p - b->pos;
    ctx->fragment_state = state;
    b->pos = p;

    if (ctx->rest > ctx->padding) {
        return NGX_AGAIN;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_grpc_validate_header_name(ngx_http_request_t *r, ngx_str_t *s)
{
    u_char      ch;
    ngx_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == ':' && i > 0) {
            return NGX_ERROR;
        }

        if (ch >= 'A' && ch <= 'Z') {
            return NGX_ERROR;
        }

        if (ch == '\0' || ch == CR || ch == LF) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_validate_header_value(ngx_http_request_t *r, ngx_str_t *s)
{
    u_char      ch;
    ngx_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == '\0' || ch == CR || ch == LF) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_parse_rst_stream(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
    ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_error_2,
        sw_error_3,
        sw_error_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->error |= ch;
            state = sw_start;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc error: %ui", ctx->error);

            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_parse_goaway(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
    ngx_buf_t *b)
{
    u_char              ch, *p, *last;
    ngx_log_t          *log;
    enum {
        sw_start = 0,
        sw_last_stream_id_2,
        sw_last_stream_id_3,
        sw_last_stream_id_4,
        sw_error,
        sw_error_2,
        sw_error_3,
        sw_error_4,
        sw_debug
    } state;

    if (r) {
        log = r->connection->log;
    }
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (r == NULL) {
        log = ctx->mus->c->log;
    }
#endif

    /* 处理frame剩下的部分 */
    if (b->last - b->pos < (ssize_t) ctx->rest) { /* frame不全 */
        last = b->last;

    } else {
        last = b->pos + ctx->rest; /* frame全，buffer后面是其他frame的 */
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        /* ctx->stream_id有时候表示收到的这个frame的stream_id，有时候表示goaway的last_stream_id */
        if (ctx->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return NGX_ERROR;
        }

        if (ctx->rest < 8) { /* last_stream_id + error_code = 8bytes */
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc goaway byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->stream_id = (ch & 0x7f) << 24;
            state = sw_last_stream_id_2;
            break;

        case sw_last_stream_id_2:
            ctx->stream_id |= ch << 16;
            state = sw_last_stream_id_3;
            break;

        case sw_last_stream_id_3:
            ctx->stream_id |= ch << 8;
            state = sw_last_stream_id_4;
            break;

        case sw_last_stream_id_4:
            ctx->stream_id |= ch;
            state = sw_error;
            break;

        case sw_error:
            ctx->error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->error |= ch;
            state = sw_debug;
            break;

        case sw_debug:
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "grpc goaway: %ui, stream %ui",
                   ctx->error, ctx->stream_id);

    ctx->state = ngx_http_grpc_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_parse_window_update(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b)
{
    u_char           ch, *p, *last;
    ngx_log_t       *log;
    enum {
        sw_start = 0,
        sw_size_2,
        sw_size_3,
        sw_size_4
    } state;

    if (r) {
        log = r->connection->log;
    }
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (r == NULL) {
        log = ctx->mus->c->log;
    }
#endif

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->rest != 4) { /* 只能是四个字节的window_increment */
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc window update byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->window_update = (ch & 0x7f) << 24;
            state = sw_size_2;
            break;

        case sw_size_2:
            ctx->window_update |= ch << 16;
            state = sw_size_3;
            break;

        case sw_size_3:
            ctx->window_update |= ch << 8;
            state = sw_size_4;
            break;

        case sw_size_4:
            ctx->window_update |= ch;
            state = sw_start;
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->state = ngx_http_grpc_st_start;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "grpc window update: %ui", ctx->window_update);

    if (ctx->stream_id) {

        if (ctx->window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
                                 - ctx->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too large window update");
            return NGX_ERROR;
        }

        ctx->send_window += ctx->window_update;

    } else {

        if (ctx->window_update > NGX_HTTP_V2_MAX_WINDOW
                                 - ctx->connection->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too large window update");
            return NGX_ERROR;
        }

        ctx->connection->send_window += ctx->window_update;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_parse_settings(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
    ngx_buf_t *b)
{
    u_char   ch, *p, *last;
    ssize_t  window_update;
    ngx_log_t *log;
    enum {
        sw_start = 0,
        sw_id,
        sw_id_2,
        sw_value,
        sw_value_2,
        sw_value_3,
        sw_value_4
    } state;

    if (r) {
        log = r->connection->log;
    }
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    ngx_http_upstream_t  *u;
    if (r == NULL) {
        log = ctx->mus->c->log;
    }
#endif

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return NGX_ERROR;
        }

        if (ctx->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                           "grpc settings ack");

            if (ctx->rest != 0) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              ctx->rest);
                return NGX_ERROR;
            }

            ctx->state = ngx_http_grpc_st_start;

            return NGX_OK;
        }

        if (ctx->rest % 6 != 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc settings byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
        case sw_id:
            ctx->setting_id = ch << 8;
            state = sw_id_2;
            break;

        case sw_id_2:
            ctx->setting_id |= ch;
            state = sw_value;
            break;

        case sw_value:
            ctx->setting_value = (ngx_uint_t) ch << 24;
            state = sw_value_2;
            break;

        case sw_value_2:
            ctx->setting_value |= ch << 16;
            state = sw_value_3;
            break;

        case sw_value_3:
            ctx->setting_value |= ch << 8;
            state = sw_value_4;
            break;

        case sw_value_4:
            ctx->setting_value |= ch;
            state = sw_id;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "grpc setting: %ui %ui",
                           ctx->setting_id, ctx->setting_value);

            /*
             * The following settings are defined by the protocol:
             *
             * SETTINGS_HEADER_TABLE_SIZE, SETTINGS_ENABLE_PUSH,
             * SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_INITIAL_WINDOW_SIZE,
             * SETTINGS_MAX_FRAME_SIZE, SETTINGS_MAX_HEADER_LIST_SIZE
             *
             * Only SETTINGS_INITIAL_WINDOW_SIZE seems to be needed in
             * a simple client.
             */

            if (ctx->setting_id == 0x04) {
                /* SETTINGS_INITIAL_WINDOW_SIZE */

                if (ctx->setting_value > NGX_HTTP_V2_MAX_WINDOW) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent settings frame "
                                  "with too large initial window size: %ui",
                                  ctx->setting_value);
                    return NGX_ERROR;
                }

                window_update = ctx->setting_value
                                - ctx->connection->init_window;
                ctx->connection->init_window = ctx->setting_value;
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                if (r == NULL) {
                    for (u = ctx->mus->upstream->elts;
                         u != NULL;
                         u = u->next)
                    {
                        ngx_http_grpc_ctx_t   *stream_ctx;
                        stream_ctx = ngx_http_get_module_ctx(u->data, ngx_http_grpc_module);
                        if (stream_ctx != NULL) {
                            if (stream_ctx->send_window > 0
                                && window_update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
                                                   - stream_ctx->send_window)
                            {
                                ngx_log_error(NGX_LOG_ERR, log, 0,
                                              "upstream sent settings frame "
                                              "with too large initial window size: %ui "
                                              "for stream: %ui",
                                              ctx->setting_value, stream_ctx->id);
                                u->stream_error = 1;
                                continue;
                            }

                            stream_ctx->send_window += window_update;
                        }
                    }
                
                } else {
#endif
                if (ctx->send_window > 0
                    && window_update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
                                       - ctx->send_window)
                {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent settings frame "
                                  "with too large initial window size: %ui",
                                  ctx->setting_value);
                    return NGX_ERROR;
                }

                ctx->send_window += window_update;
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
                }
#endif

            }
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->state = ngx_http_grpc_st_start;

    return ngx_http_grpc_send_settings_ack(r, ctx);
}


static ngx_int_t
ngx_http_grpc_parse_ping(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    ngx_log_t *log;
    enum {
        sw_start = 0,
        sw_data_2,
        sw_data_3,
        sw_data_4,
        sw_data_5,
        sw_data_6,
        sw_data_7,
        sw_data_8
    } state;

if (r) {
        log = r->connection->log;
    }
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    ngx_http_upstream_t  *u;
    if (r == NULL) {
        log = ctx->mus->c->log;
    }
#endif

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return NGX_ERROR;
        }

        if (ctx->rest != 8) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }

        if (ctx->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent ping frame with ack flag");
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc ping byte: %02Xd s:%d", ch, state);
#endif

        if (state < sw_data_8) {
            ctx->ping_data[state] = ch;
            state++;

        } else {
            ctx->ping_data[7] = ch;
            state = sw_start;

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                           "grpc ping");
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->state = ngx_http_grpc_st_start;

    return ngx_http_grpc_send_ping_ack(r, ctx);
}


static ngx_int_t
ngx_http_grpc_send_settings_ack(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx)
{
    ngx_chain_t            *cl, **ll;
    ngx_http_grpc_frame_t  *f;
    ngx_log_t              *log;

    if (r) {
        log = r->connection->log;
    }
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (r == NULL) {
        log = ctx->mus->c->log;
    }
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "grpc send settings ack");

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = NGX_HTTP_V2_SETTINGS_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    *ll = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_send_ping_ack(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx)
{
    ngx_chain_t            *cl, **ll;
    ngx_http_grpc_frame_t  *f;
    ngx_log_t              *log;

if (r) {
        log = r->connection->log;
    }
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (r == NULL) {
        log = ctx->mus->c->log;
    }
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "grpc send ping ack");

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 8;
    f->type = NGX_HTTP_V2_PING_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    cl->buf->last = ngx_copy(cl->buf->last, ctx->ping_data, 8);

    *ll = cl;

    return NGX_OK;
}


static ngx_int_t  /* 俩window_update一起 */
ngx_http_grpc_send_window_update(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx)
{
    size_t                  n;
    ngx_chain_t            *cl, **ll;
    ngx_http_grpc_frame_t  *f;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send window update: %uz %uz",
                   ctx->connection->recv_window, ctx->recv_window);

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    n = NGX_HTTP_V2_MAX_WINDOW - ctx->connection->recv_window;
    ctx->connection->recv_window = NGX_HTTP_V2_MAX_WINDOW;
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (r->upstream->multiple) {
        n = r->upstream->mus->buffer_size - ctx->connection->recv_window;
        ctx->connection->recv_window = r->upstream->mus->buffer_size;
    }
#endif

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    f = (ngx_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (ctx->id & 0xff);

    n = NGX_HTTP_V2_MAX_WINDOW - ctx->recv_window;
    ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (r->upstream->multiple) {
        n = r->upstream->conf->buffer_size - ctx->recv_window;
        ctx->recv_window = r->upstream->conf->buffer_size;
    }
#endif

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    *ll = cl;

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_grpc_get_buf(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx)
{
    u_char       *start;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;
    ngx_pool_t   *pool;

    if (r) {
        pool = r->pool;
    }
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
    if (r == NULL) {
        pool = ctx->mus->c->pool;
    }
#endif

    cl = ngx_chain_get_free_buf(pool, &ctx->free);

    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;
    start = b->start;

    if (start == NULL) {

        /*
         * each buffer is large enough to hold two window update
         * frames in a row
         */

        start = ngx_palloc(pool, 2 * sizeof(ngx_http_grpc_frame_t) + 8);
        if (start == NULL) {
            return NULL;
        }

    }

    ngx_memzero(b, sizeof(ngx_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + 2 * sizeof(ngx_http_grpc_frame_t) + 8;

    b->tag = (ngx_buf_tag_t) &ngx_http_grpc_body_output_filter;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static ngx_http_grpc_ctx_t *
ngx_http_grpc_get_ctx(ngx_http_request_t *r)
{
    ngx_http_grpc_ctx_t  *ctx;
    ngx_http_upstream_t  *u;

    ctx = ngx_http_get_module_ctx(r, ngx_http_grpc_module);

    if (ctx->connection == NULL) {
        u = r->upstream;

        if (ngx_http_grpc_get_connection_data(r, ctx, &u->peer) != NGX_OK) {
            return NULL;
        }
    }

    return ctx;
}


static ngx_int_t
ngx_http_grpc_get_connection_data(ngx_http_request_t *r,
    ngx_http_grpc_ctx_t *ctx, ngx_peer_connection_t *pc)
{
    ngx_connection_t    *c;
    ngx_pool_cleanup_t  *cln;

    c = pc->connection;

    if (pc->cached) {

        /*
         * for cached connections, connection data can be found
         * in the cleanup handler
         */

        for (cln = c->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_grpc_cleanup) {
                ctx->connection = cln->data;
                break;
            }
        }

        if (ctx->connection == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no connection data found for "
                          "keepalive http2 connection");
            return NGX_ERROR;
        }

        ctx->send_window = ctx->connection->init_window; /* initial window的作用就是 新的stream将这个作为自己给对方发的窗口大小 */
        ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
        if (c->multiple) {
            ctx->recv_window = r->upstream->conf->buffer_size;
        }
#endif

        ctx->connection->last_stream_id += 2;
        ctx->id = ctx->connection->last_stream_id;

        return NGX_OK;
    }

    cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_http_grpc_conn_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_grpc_cleanup;
    ctx->connection = cln->data; /* 将ctx->connection(即grpc_conn_t)挂在cleanup里 */

    ctx->connection->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    ctx->connection->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    ctx->connection->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    ctx->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;
#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)
        if (c->multiple) {
            ctx->connectoin->recv_window = r->upstream->mus->buffer_size;
            ctx->recv_window = r->upstream->conf->buffer_size;

        }
#endif

    ctx->id = 1;
    ctx->connection->last_stream_id = 1;

    return NGX_OK;
}


static void
ngx_http_grpc_cleanup(void *data)
{
#if 0
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "grpc cleanup");
#endif
    return;
}


static void
ngx_http_grpc_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort grpc request");
    return;
}


static void
ngx_http_grpc_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize grpc request");
    return;
}


static ngx_int_t
ngx_http_grpc_internal_trailers_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_table_elt_t  *te;

    te = r->headers_in.te;

    if (te == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_strlcasestrn(te->value.data, te->value.data + te->value.len,
                         (u_char *) "trailers", 8 - 1)
        == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = (u_char *) "trailers";
    v->len = sizeof("trailers") - 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_grpc_add_variables(ngx_conf_t *cf) /* pre 函数 */
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_grpc_vars; v->name.len; v++) {  /* 设置te头的参数为trailers */
        var = ngx_http_add_variable(cf, &v->name, v->flags); /* 应该是与r无关的 */
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_grpc_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_grpc_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_grpc_loc_conf_t)); /* 对.conf中的upstream进行设置初始化 upstream指令的各种设置blabla */
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.ssl_name = NULL;
     *
     *     conf->headers_source = NULL;
     *     conf->headers.lengths = NULL;
     *     conf->headers.values = NULL;
     *     conf->headers.hash = { NULL, 0 };
     *     conf->host = { 0, NULL };
     *     conf->host_set = 0;
     *     conf->ssl = 0;
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *     conf->ssl_certificate = { 0, NULL };
     *     conf->ssl_certificate_key = { 0, NULL };
     */

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

#if (NGX_HTTP_SSL)
    conf->upstream.ssl_session_reuse = NGX_CONF_UNSET;
    conf->upstream.ssl_server_name = NGX_CONF_UNSET;
    conf->upstream.ssl_verify = NGX_CONF_UNSET;
    conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
    conf->ssl_passwords = NGX_CONF_UNSET_PTR;
#endif

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.pass_request_headers = 1;
    conf->upstream.pass_request_body = 1;
    conf->upstream.force_ranges = 0;
    conf->upstream.pass_trailers = 1;
    /* conf->upstream.preserve_output = 1; */ /* tengine does not have this member */

    ngx_str_set(&conf->upstream.module, "grpc");

    return conf;
}


static char *
ngx_http_grpc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_grpc_loc_conf_t *prev = parent;
    ngx_http_grpc_loc_conf_t *conf = child;

    ngx_int_t                  rc;
    ngx_hash_init_t            hash;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              NGX_CONF_BITMASK_SET);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    ngx_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

#if (NGX_HTTP_SSL)

    ngx_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);

    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                                 (NGX_CONF_BITMASK_SET|NGX_SSL_TLSv1
                                  |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2));

    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    if (conf->upstream.ssl_name == NULL) {
        conf->upstream.ssl_name = prev->upstream.ssl_name;
    }

    ngx_conf_merge_value(conf->upstream.ssl_server_name,
                              prev->upstream.ssl_server_name, 0);
    ngx_conf_merge_value(conf->upstream.ssl_verify,
                              prev->upstream.ssl_verify, 0);
    ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");
    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    ngx_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");
    ngx_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");
    ngx_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl && ngx_http_grpc_set_ssl(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#endif

    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "grpc_headers_hash";

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, ngx_http_grpc_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->noname && conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->host = prev->host;
#if (NGX_HTTP_SSL)
        conf->upstream.ssl = prev->upstream.ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL && conf->upstream.upstream) {
        clcf->handler = ngx_http_grpc_handler;
    }

    if (conf->headers_source == NULL) {
        conf->headers = prev->headers;
        conf->headers_source = prev->headers_source;
        conf->host_set = prev->host_set;
    }

    rc = ngx_http_grpc_init_headers(cf, conf, &conf->headers,
                                    ngx_http_grpc_headers);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * special handling to preserve conf->headers in the "http" section
     * to inherit it to all servers
     */

    if (prev->headers.hash.buckets == NULL
        && conf->headers_source == prev->headers_source)
    {
        prev->headers = conf->headers;
        prev->host_set = conf->host_set;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_grpc_init_headers(ngx_conf_t *cf, ngx_http_grpc_loc_conf_t *conf,
    ngx_http_grpc_headers_t *headers, ngx_keyval_t *default_headers)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    ngx_uint_t                    i;
    ngx_array_t                   headers_names, headers_merged;
    ngx_keyval_t                 *src, *s, *h;
    ngx_hash_key_t               *hk;
    ngx_hash_init_t               hash;
    ngx_http_script_compile_t     sc;
    ngx_http_script_copy_code_t  *copy;

    if (headers->hash.buckets) {
        return NGX_OK;
    }

    if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&headers_merged, cf->temp_pool, 4, sizeof(ngx_keyval_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    headers->lengths = ngx_array_create(cf->pool, 64, 1);
    if (headers->lengths == NULL) {
        return NGX_ERROR;
    }

    headers->values = ngx_array_create(cf->pool, 512, 1);
    if (headers->values == NULL) {
        return NGX_ERROR;
    }

    if (conf->headers_source) {

        src = conf->headers_source->elts;
        for (i = 0; i < conf->headers_source->nelts; i++) {

            if (src[i].key.len == 4
                && ngx_strncasecmp(src[i].key.data, (u_char *) "Host", 4) == 0)
            {
                conf->host_set = 1;
            }

            s = ngx_array_push(&headers_merged);
            if (s == NULL) {
                return NGX_ERROR;
            }

            *s = src[i];
        }
    }

    h = default_headers;

    while (h->key.len) {

        src = headers_merged.elts;
        for (i = 0; i < headers_merged.nelts; i++) {
            if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
                goto next;
            }
        }

        s = ngx_array_push(&headers_merged);
        if (s == NULL) {
            return NGX_ERROR;
        }

        *s = *h;

    next:

        h++;
    }


    src = headers_merged.elts;
    for (i = 0; i < headers_merged.nelts; i++) {

        hk = ngx_array_push(&headers_names);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = src[i].key;
        hk->key_hash = ngx_hash_key_lc(src[i].key.data, src[i].key.len);
        hk->value = (void *) 1;

        if (src[i].value.len == 0) {
            continue;
        }

        copy = ngx_array_push_n(headers->lengths,
                                sizeof(ngx_http_script_copy_code_t));
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = (ngx_http_script_code_pt) (void *)
                                                 ngx_http_script_copy_len_code;
        copy->len = src[i].key.len;

        size = (sizeof(ngx_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = ngx_array_push_n(headers->values, size);
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = ngx_http_script_copy_code;
        copy->len = src[i].key.len;

        p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
        ngx_memcpy(p, src[i].key.data, src[i].key.len);

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &src[i].value;
        sc.flushes = &headers->flushes;
        sc.lengths = &headers->lengths;
        sc.values = &headers->values;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_ERROR;
        }

        code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;

        code = ngx_array_push_n(headers->values, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;


    hash.hash = &headers->hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "grpc_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
ngx_http_grpc_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_grpc_loc_conf_t *glcf = conf;

    size_t                     add;
    ngx_str_t                 *value, *url;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (glcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;
    url = &value[1];

    if (ngx_strncasecmp(url->data, (u_char *) "grpc://", 7) == 0) {
        add = 7;

    } else if (ngx_strncasecmp(url->data, (u_char *) "grpcs://", 8) == 0) {

#if (NGX_HTTP_SSL)
        glcf->ssl = 1;

        add = 8;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "grpcs protocol requires SSL support");
        return NGX_CONF_ERROR;
#endif

    } else {
        add = 0;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.no_resolve = 1;

    glcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (glcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    if (u.family != AF_UNIX) {

        if (u.no_port) {
            glcf->host = u.host;

        } else {
            glcf->host.len = u.host.len + 1 + u.port_text.len;
            glcf->host.data = u.host.data;
        }

    } else {
        ngx_str_set(&glcf->host, "localhost");
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_grpc_handler; /* 设置grpc handler */

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}


#if (NGX_HTTP_SSL)

static char *
ngx_http_grpc_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_grpc_loc_conf_t *glcf = conf;

    ngx_str_t  *value;

    if (glcf->ssl_passwords != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    glcf->ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (glcf->ssl_passwords == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_grpc_set_ssl(ngx_conf_t *cf, ngx_http_grpc_loc_conf_t *glcf)
{
    ngx_pool_cleanup_t  *cln;

    glcf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (glcf->upstream.ssl == NULL) {
        return NGX_ERROR;
    }

    glcf->upstream.ssl->log = cf->log;

    if (ngx_ssl_create(glcf->upstream.ssl, glcf->ssl_protocols, NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = glcf->upstream.ssl;

    if (glcf->ssl_certificate.len) {

        if (glcf->ssl_certificate_key.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"grpc_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &glcf->ssl_certificate);
            return NGX_ERROR;
        }

#if (T_SSL)

        ngx_http_ssl_pphrase_dialog_conf_t  dialog;

        dialog.ssl = glcf->upstream.ssl;

        dialog.type = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if (dialog.type == NULL) {
            return NGX_ERROR;
        }

        ngx_str_set(dialog.type, "builtin");

        dialog.server_name = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
        if (dialog.server_name == NULL) {
            return NGX_ERROR;
        }

        ngx_str_set(dialog.server_name, "unknown");

        if (ngx_ssl_certificate(cf, glcf->upstream.ssl, &glcf->ssl_certificate,
                                &glcf->ssl_certificate_key, &dialog, NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
#else
        if (ngx_ssl_certificate(cf, glcf->upstream.ssl, &glcf->ssl_certificate,
                                &glcf->ssl_certificate_key, glcf->ssl_passwords)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
#endif
    }

    if (SSL_CTX_set_cipher_list(glcf->upstream.ssl->ctx,
                                (const char *) glcf->ssl_ciphers.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      &glcf->ssl_ciphers);
        return NGX_ERROR;
    }

    if (glcf->upstream.ssl_verify) {
        if (glcf->ssl_trusted_certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no grpc_ssl_trusted_certificate for grpc_ssl_verify");
            return NGX_ERROR;
        }

        if (ngx_ssl_trusted_certificate(cf, glcf->upstream.ssl,
                                        &glcf->ssl_trusted_certificate,
                                        glcf->ssl_verify_depth)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_ssl_crl(cf, glcf->upstream.ssl, &glcf->ssl_crl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    if (SSL_CTX_set_alpn_protos(glcf->upstream.ssl->ctx,
                                (u_char *) "\x02h2", 3)
        != 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_alpn_protos() failed");
        return NGX_ERROR;
    }

#endif

    return NGX_OK;
}

#endif


#if (NGX_HTTP_MULTIPLEXING_UPS && NGX_HTTP_GRPC_MULTIPLEXING)

ngx_uint_t 
ngx_http_multi_upstreams_get_stream_id(ngx_http_request_t *r)
{

    ngx_http_grpc_ctx_t           *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_grpc_module);

    if (ctx == NULL) {
        return NGX_HTTP_MULTI_UPS_STREAMID_NOT_FOUND;
    }

    return ctx->id;

}


ngx_int_t
ngx_http_multi_upstreams_parse_goaway(ngx_http_multi_upstreams_t *mus)
{
    mus->conn_ctx->frame_state = 0;

    return ngx_http_grpc_parse_goaway(NULL, mus->conn_ctx, &mus->frame);
}


ngx_int_t
ngx_http_multi_upstreams_parse_window_update(ngx_http_multi_upstreams_t *mus)
{
    mus->conn_ctx->frame_state = 0;

    return ngx_http_grpc_parse_window_update(NULL, mus->conn_ctx, &mus->frame);
}


ngx_int_t
ngx_http_multi_upstreams_parse_settings(ngx_http_multi_upstreams_t *mus)
{
    mus->conn_ctx->frame_state = 0;

    return ngx_http_grpc_parse_settings(NULL, mus->conn_ctx, &mus->frame);
}


ngx_int_t
ngx_http_multi_upstreams_parse_ping(ngx_http_multi_upstreams_t *mus)
{
    mus->conn_ctx->frame_state = 0;

    return ngx_http_grpc_parse_ping(NULL, mus->conn_ctx, &mus->frame);
}

#endif
