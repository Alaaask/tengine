#ifndef _NGX_UPSTREAM_MULTIPLEXING_H_INCLUDED_
#define _NGX_UPSTREAM_MULTIPLEXING_H_INCLUDED_


ngx_int_t
ngx_http_multiplexing_ups_bind_connection(ngx_http_request_t *r, ngx_connection_t *upstream);
ngx_http_request_t *
ngx_http_multiplexing_ups_find_connection(ngx_connection_t *upstream, unsigned int id);
void
ngx_http_multiplexing_ups_free(ngx_connection_t *c);
void
ngx_http_multiplexing_ups_finalize(ngx_connection_t *upstream,
    ngx_int_t rc);
void
ngx_http_upstream_finalize(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_int_t rc);

#endif
