#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stddef.h>
#include <stdio.h>

#define FIELD(T,F) printf(",\"" #T "." #F "\":%zu", offsetof(T,F))
#define BIT(F,V) do { \
    ngx_http_request_t r; memset(&r,0,sizeof(r)); r.F=(V); \
    unsigned char *p=(unsigned char *)&r; size_t at=0; \
    while(at<sizeof(r) && !p[at]) ++at; \
    unsigned mask=0; for(unsigned j=0;j<4 && at+j<sizeof(r);++j) mask|=(unsigned)p[at+j]<<(8*j); \
    printf(",\"bit." #F "\":{\"offset\":%zu,\"mask\":%u}",at,mask); \
} while(0)
int main(void) {
    printf("{\"pointer_size\":%zu",sizeof(void *));
    FIELD(ngx_http_request_t,main); FIELD(ngx_http_request_t,loc_conf);
    FIELD(ngx_http_request_t,ncaptures); FIELD(ngx_http_request_t,captures);
    FIELD(ngx_http_request_t,uri); FIELD(ngx_http_core_loc_conf_t,alias);
    FIELD(ngx_http_regex_t,ncaptures); FIELD(ngx_str_t,len); FIELD(ngx_str_t,data);
    FIELD(ngx_module_t,ctx_index);
    FIELD(ngx_http_script_engine_t,ip); FIELD(ngx_http_script_engine_t,pos);
    FIELD(ngx_http_script_engine_t,status);
    BIT(uri_changed,1); BIT(realloc_captures,1); BIT(blocked,255);
    puts("}");
    return 0;
}
