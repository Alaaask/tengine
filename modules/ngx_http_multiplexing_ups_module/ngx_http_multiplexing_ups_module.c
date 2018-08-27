
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_multiplexing_ups_module.h>


typedef struct {
    ngx_uint_t                         max_cached;
    size_t                             buffer_size;

    ngx_queue_t                        cache;
    //ngx_queue_t                        free;

    ngx_http_upstream_init_pt          original_init_upstream;
    ngx_http_upstream_init_peer_pt     original_init_peer;

} ngx_http_multiplexing_ups_srv_conf_t;


typedef struct {
    ngx_http_multiplexing_ups_srv_conf_t  *conf;

    ngx_queue_t                        queue;
    void                               *connection;
    void                               *request;

    socklen_t                          socklen;
    u_char                             sockaddr[NGX_SOCKADDRLEN];
    unsigned int                       id;
    unsigned int                       used;
} ngx_http_multiplexing_ups_cache_t;


typedef struct {
    ngx_http_multiplexing_ups_srv_conf_t  *conf;

    ngx_http_upstream_t               *upstream;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

} ngx_http_multiplexing_ups_peer_data_t;


static ngx_int_t ngx_http_multiplexing_ups_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_multiplexing_ups_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_free_multiple_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static ngx_int_t ngx_http_multiplexing_ups_get_peer_null(ngx_peer_connection_t *pc,
    void *data);

static void ngx_http_multiplexing_ups_close(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_multiplexing_ups_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_multiplexing_ups_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif
static ngx_int_t
ngx_http_multiplexing_ups_cache(ngx_connection_t *c,
    ngx_peer_connection_t *pc, void *data);

static void *ngx_http_multiplexing_ups_create_conf(ngx_conf_t *cf);
static char *ngx_http_multiplexing_ups(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_command_t  ngx_http_multiplexing_ups_commands[] = {

    { ngx_string("multiplexing"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_multiplexing_ups, /* Step 1 */
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
    
    { ngx_string("multiplexing_buffer_size"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_multiplexing_ups_srv_conf_t, buffer_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_multiplexing_ups_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_multiplexing_ups_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_multiplexing_ups_module = {
    NGX_MODULE_V1,
    &ngx_http_multiplexing_ups_module_ctx, /* module context */
    ngx_http_multiplexing_ups_commands,    /* module directives */
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


static ngx_int_t
ngx_http_multiplexing_ups_init(ngx_conf_t *cf, /* Step 3 */
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_multiplexing_ups_srv_conf_t  *mcf;
    ngx_http_multiplexing_ups_cache_t     *cached;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init multiple");

    mcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_multiplexing_ups_module);

    if (mcf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    mcf->original_init_peer = us->peer.init;

    us->peer.init = ngx_http_multiplexing_ups_init_peer;

    /* allocate cache items and add to free queue */

    cached = ngx_pcalloc(cf->pool,
                sizeof(ngx_http_multiplexing_ups_cache_t) * mcf->max_cached);
    
    if (cached == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&mcf->cache);
    //ngx_queue_init(&mcf->free);
#if 0
    for (i = 0; i < mcf->max_cached; i++) {
        ngx_queue_insert_head(&mcf->free, &cached[i].queue);
        cached[i].conf = mcf;
    }
#endif
    return NGX_OK;
}


static ngx_int_t
ngx_http_multiplexing_ups_init_peer(ngx_http_request_t *r, /* 在这里设置multiple */
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_multiplexing_ups_peer_data_t  *mp;
    ngx_http_multiplexing_ups_srv_conf_t   *mcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init multiple peer");

    mcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_multiplexing_ups_module);

    mp = ngx_palloc(r->pool, sizeof(ngx_http_multiplexing_ups_peer_data_t));
    if (mp == NULL) {
        return NGX_ERROR;
    }

    if (mcf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    mp->conf = mcf;
    mp->upstream = r->upstream;
    mp->data = r->upstream->peer.data;
    mp->original_get_peer  = r->upstream->peer.get;
    mp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = mp;
    r->upstream->peer.get  = ngx_http_multiplexing_ups_get_peer;
    r->upstream->peer.free = ngx_http_upstream_free_multiple_peer;

    r->upstream->multiple = 1;

#if (NGX_HTTP_SSL)
    mp->original_set_session  = r->upstream->peer.set_session;
    mp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_multiplexing_ups_set_session;
    r->upstream->peer.save_session = ngx_http_multiplexing_ups_save_session;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_multiplexing_ups_get_peer_null(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_multiplexing_ups_get_peer(ngx_peer_connection_t *pc, void *data) /* Step 4 */
{
    ngx_int_t                               rc, cnt;
    ngx_queue_t                            *q, *cache;
    ngx_connection_t                       *c;
    ngx_http_upstream_t                    *u, *upstream;
    ngx_event_get_peer_pt                   save_handler;
    ngx_http_multiplexing_ups_cache_t      *item, *best;
    ngx_http_multiplexing_ups_peer_data_t  *mp = data;
    ngx_http_multiplexing_ups_srv_conf_t   *mcf;
#if (NGX_HTTP_GRPC_MULTIPLEXING)
    ngx_log_t                       *log;
    ngx_http_multi_upstreams_t      *mus;
    ngx_http_grpc_ctx_t             *grpc_ctx;
#endif

    mcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_multiplexing_ups_module);

    u = mp->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get multiple peer");

    /* ask balancer */

    rc = mp->original_get_peer(pc, mp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */
    cache = &mp->conf->cache;

    best = NULL;
    cnt  = 0;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_multiplexing_ups_cache_t, queue);

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {

            /* 改：增加ssl判断 */
            if (item->connection->goaway) {
                continue;
            }
            
            if (best == NULL) {
                best = item;

            } else {

                if (best->used > item->used) {
                    best = item;
                }
            }
            cnt++;
        }
    }

    if (cnt > 0) {
        c = best->connection;
        best->used++;
        goto found;
    }

    /* not found */
    save_handler = pc->get;
    pc->get = ngx_http_multiplexing_ups_get_peer_null; /* 啥也不做 等着分配新的 */
    rc = ngx_event_connect_peer(pc); /* 得到新的 不调rr get peer*/
    pc->get = save_handler;

    if (pc->connection == NULL) { /* rc == NGX_ERROR || rc == NGX_DECLINE */
        ngx_log_error(NGX_LOG_ERR, pc->log,
                    0, "multiplexing get new connection error");
        return rc; /* 它会报错(ERROR)或者请求下一个server(DECLINE) */
    }
    /* 否则 成功了 但有可能是返回NGX_AGAIN */
    c = pc->connection;
    if (ngx_http_multiplexing_ups_cache(c, pc, data) != NGX_OK) { /* 缓存新的c */
        return NGX_ERROR; /* 没有缓存好新的 只会有没内存的时候才不是OK 所以直接返回ERROR */
    }
    
#if (NGX_HTTP_GRPC_MULTIPLEXING)
    /* allocate new multi_upstreams for connection c */
    if (c->pool == NULL) {

        /* we need separate pool here to be able to cache SSL connections */
        c->pool = ngx_create_pool(128, pc->log); /* pc->log is r->connection->log in fact */
        if (c->pool == NULL) {
            return NGX_ERROR;
        }
    }
    
    c->log = ngx_palloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        return NGX_ERROR;
    }
    *c->log = *r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    if (c->mus == NULL) {
        mus = ngx_palloc(c->pool, sizeof(ngx_http_multi_upstreams_t));
        if (mus == NULL) {
            return NGX_ERROR;
        }
        c->mus = mus;
        mus->c = c;
    }

    mus->write_event_handler = ngx_http_multi_upstreams_send_request_handler;
    mus->read_event_handler = ngx_http_multi_upstreams_read_event_handler;

    if (mus->grpc_ctx == NULL) {
        grpc_ctx = ngx_palloc(c->pool, sizeof(ngx_http_grpc_ctx_t));
        if (grpc_ctx == NULL) {
            return NGX_ERROR;
        }
        mus->grpc_ctx = grpc_ctx;
        grpc_ctx->mus = mus;
    }

    upstream = ngx_array_push(mus->upstreams);
    if (upstream == NULL) {
        return NGX_ERROR;
    }
    upstream = u;

    u->mus = c->mus;
    u->multiple = 1;

    mus->input_filter_init = u->input_filter_init;
    mus->input_filter = u->input_filter;

    mus->tries = u->conf->next_upstream_tries;
    mus->read_timeout = u->conf->read_timeout;
    mus->send_timeout = u->conf->send_timeout;
    mus->send_lowat = u->conf->send_lowat;

    mus->buffer_size = (mcf->buffer_size == NGX_CONF_UNSET_SIZE ? (size_t)16384 : mcf->buffer_size);

    ngx_queue_init(&mus->wait_write_queue); /* 初始化写队列 注意重试 */

#endif

    if (rc == NGX_AGAIN) { /* NGX_AGAIN情况下也会缓存 但是会返回AGAIN */
        return rc;
    }

    return NGX_DONE;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get multiple peer: using connection %p", c);

#if (NGX_HTTP_GRPC_MULTIPLEXING)
    /* 改：旧的connection的问题 若现在没有一个peer 其他的upstream走的时候清理干净没 */
    upstream = ngx_array_push(c->mus->upstreams);
    if (upstream == NULL) {
        return NGX_ERROR;
    }
    upstream = u;
    u->mus = c->mus;
    u->multiple = 1;
#endif

    pc->connection = c;
    pc->cached = 1; /* mark */

    return NGX_DONE;
}

ngx_int_t
ngx_http_multiplexing_ups_cache(ngx_connection_t *c, /* 肯定是一个也没找着才会重新申请一个再cache */
    ngx_peer_connection_t *pc, void *data)
{
    ngx_http_multiplexing_ups_peer_data_t  *mp = data;
    ngx_http_multiplexing_ups_cache_t      *item;

    if (c->multiple_cached) {
        return NGX_OK;
    }

    item = ngx_calloc(sizeof(ngx_http_multiplexing_ups_cache_t), ngx_cycle->log);
    if (item == NULL) {
        return NGX_ERROR;
    }

    item->connection = c;
    item->socklen    = pc->socklen;
    item->used       = 1;
    item->conf       = mp->conf;

    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    ngx_queue_insert_head(&mp->conf->cache, &item->queue);
    c->multiple = 1;
    c->multiple_cached = 1;
    c->multiple_item = item;

    return NGX_OK;
}

static void
ngx_http_upstream_free_multiple_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_multiplexing_ups_peer_data_t  *mp = data;

    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free multiple peer");

    /* cache valid connections */

    u = mp->upstream;
    c = pc->connection;

    if (c->multiple) {
        pc->connection = NULL;
    }
    /* 改：解耦mus 队列什么的 */

    mp->original_free_peer(pc, mp->data, state);

}


void
ngx_http_multiplexing_ups_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "multiple dummy handler");
}


void
ngx_http_multiplexing_ups_close_handler(ngx_event_t *ev)
{
    ngx_http_multiplexing_ups_cache_t     *item;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "multiple close handler");

    c = ev->data;

    if (c->close) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->multiple_item;
    //conf = item->conf;

    ngx_http_multiplexing_ups_close(c);

    ngx_queue_remove(&item->queue);
}


static void
ngx_http_multiplexing_ups_close(ngx_connection_t *c)
{

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_multiplexing_ups_close;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_multiplexing_ups_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_multiplexing_ups_peer_data_t  *mp = data;

    return mp->original_set_session(pc, mp->data);
}


static void
ngx_http_multiplexing_ups_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_multiplexing_ups_peer_data_t  *mp = data;

    mp->original_save_session(pc, mp->data);
    return;
}

#endif


static void *
ngx_http_multiplexing_ups_create_conf(ngx_conf_t *cf)
{
    ngx_http_multiplexing_ups_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_multiplexing_ups_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     *     conf->max_cached = 0;
     */

    conf->buffer_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_multiplexing_ups(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) /* Step 2 */
{
    ngx_http_upstream_srv_conf_t            *uscf;
    ngx_http_multiplexing_ups_srv_conf_t    *mcf = conf;

    ngx_int_t    n;
    ngx_str_t   *value;

    if (mcf->max_cached) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR || n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    mcf->max_cached = n;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    mcf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : ngx_http_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_http_multiplexing_ups_init;

    return NGX_CONF_OK;
}

#define HASH_BUCKET_SIZE    256
#define HASH_BUCKET_MASK    (HASH_BUCKET_SIZE - 1)

ngx_int_t
ngx_http_multiplexing_ups_bind_connection(ngx_http_request_t *r, ngx_connection_t *upstream)
{
    ngx_uint_t i;
    ngx_http_multiplexing_ups_cache_t      *item;

    if (upstream->multiple_hash_tb == NULL) {
        upstream->multiple_hash_tb = ngx_palloc(upstream->pool, sizeof(ngx_queue_t) * HASH_BUCKET_SIZE);
        if (upstream->multiple_hash_tb == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log,
                          0, "multiplexing multiple_hash_tb error");
            return NGX_ERROR;
        }

        for (i = 0; i < HASH_BUCKET_SIZE; i++) {
            ngx_queue_init(&upstream->multiple_hash_tb[i]);
        }
    }

    item = ngx_palloc(r->pool, sizeof(ngx_http_multiplexing_ups_cache_t));
    if (item == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 
                      0, "multiplexing item error");
        return NGX_ERROR;
    }

    item->request    = r;
    item->id         = r->connection_id;
    r->queue         = &item->queue;

    i = item->id&HASH_BUCKET_MASK;

    ngx_queue_insert_head(&upstream->multiple_hash_tb[i], &item->queue);

    return NGX_OK;
}

ngx_http_request_t *
ngx_http_multiplexing_ups_find_connection(ngx_connection_t *upstream, unsigned int id)
{
    ngx_uint_t i;
    ngx_queue_t *q, *cache;
    ngx_http_multiplexing_ups_cache_t      *item;

    if (upstream->multiple_hash_tb == NULL) {
        ngx_log_error(NGX_LOG_ERR, upstream->log, 
                      0, "multiplexing find table error");
        return NULL;
    }


    i = id&HASH_BUCKET_MASK;
    cache = &upstream->multiple_hash_tb[i];

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_multiplexing_ups_cache_t, queue);

        if (id == item->id) {
            return item->request;
        }
    }

    return NULL;
}


void
ngx_http_multiplexing_ups_finalize(ngx_connection_t *upstream,
    ngx_int_t rc)
{
    ngx_uint_t i;
    ngx_queue_t *q, *cache;
    ngx_http_multiplexing_ups_cache_t      *item;
    ngx_http_request_t *r;
    ngx_pool_t *pool;

    if (upstream->multiple_hash_tb == NULL) {
        ngx_log_error(NGX_LOG_ERR, upstream->log, 0, 
                      "upstream close without client hash_tb");
        goto end;
    }

    /* The upstream will be close, so close all downstream related to this upstream */
    for (i = 0; i < HASH_BUCKET_SIZE; i++) {

        cache = &upstream->multiple_hash_tb[i];

        for(;;) {

            if (ngx_queue_empty(cache)) {
                break;
            }

            q = ngx_queue_head(cache);
            ngx_queue_remove(q);

            item = ngx_queue_data(q, ngx_http_multiplexing_ups_cache_t, queue);

            r = item->request;
            ngx_pfree(r->pool, item);
            r->queue = NULL;
            
            r->connection->log->action = "removed by upstream";

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                          "upstream close and remove client");

            ngx_http_upstream_finalize(r, r->upstream, rc);

        }
    }

end:
    pool = upstream->pool;
    ngx_close_connection(upstream);

    if (pool)
        ngx_destroy_pool(pool); /* 释放c的pool */
    //ngx_http_close_connection(upstream);
}

void
ngx_http_multiplexing_ups_free(ngx_connection_t *c)
{
    ngx_http_multiplexing_ups_cache_t      *item;

    item = c->multiple_item;

    ngx_queue_remove(&item->queue);
    c->multiple_item = NULL;
    ngx_free(item);
}
