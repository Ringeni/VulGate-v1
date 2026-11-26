#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define APR_INLINE inline
#define HUGE_STRING_LEN 64
#define HTTP_REQUEST_URI_TOO_LARGE 414
#define OK 0
#define DECLINED (-1)
#define ap_log_rerror(mark, level, status, r, message) (++(r)->errors)
#define ap_get_module_config(config, module) (config)
#define apr_snprintf snprintf
#define apr_tolower tolower

typedef struct {
    char strings[8][128];
    unsigned int used;
} fixture_pool;

typedef struct { void *module_config; } server_rec;
typedef struct { const char *local_ip; } connection_rec;

typedef struct request_rec {
    fixture_pool *pool;
    server_rec *server;
    connection_rec *connection;
    struct request_rec *notes;
    const char *hostname;
    const char *uri;
    const char *filename;
    const char *canonical_filename;
    const char *document_root;
    const char *handler;
    unsigned int errors;
    unsigned int notes_writes;
    unsigned int context_updates;
} request_rec;

static const char *ap_get_server_name(request_rec *r) { return r->hostname; }
static int ap_get_server_port(request_rec *r) { (void)r; return 8080; }
static void ap_set_document_root(request_rec *r, const char *root) { r->document_root = root; }

static void ap_set_context_info(request_rec *r, const char *prefix, const char *root)
{
    (void)prefix;
    (void)root;
    ++r->context_updates;
}

static void apr_table_setn(request_rec *r, const char *key, const char *value)
{
    assert(strcmp(key, "alias-forced-type") == 0);
    assert(strcmp(value, "cgi-script") == 0);
    ++r->notes_writes;
}

static char *apr_pstrdup(fixture_pool *pool, const char *text)
{
    assert(pool->used < 8 && strlen(text) < sizeof(pool->strings[0]));
    return strcpy(pool->strings[pool->used++], text);
}

static char *apr_pstrcat(fixture_pool *pool, const char *first, ...)
{
    char text[128] = "";
    va_list args;
    va_start(args, first);
    for (const char *part = first; part; part = va_arg(args, const char *)) {
        assert(strlen(text) + strlen(part) < sizeof(text));
        strcat(text, part);
    }
    va_end(args);
    return apr_pstrdup(pool, text);
}

static int checked_fixture_capacity(request_rec *r, char *buf, char **dest, int size);
#include "patched_vhost_alias.inc"
#undef vhost_alias_checkspace

static int report_capacity_error;

static int checked_fixture_capacity(request_rec *r, char *buf, char **dest, int size)
{
    return vhost_alias_checkspace(r, buf, dest, report_capacity_error ? HUGE_STRING_LEN : size);
}

int main(void)
{
    char buffer[HUGE_STRING_LEN] = "marker";
    char *cursor = buffer;
    request_rec request = {0};

    /* Synthetic lengths exercise the guard directly before any copying. */
    assert(vhost_alias_checkspace(&request, buffer, &cursor, HUGE_STRING_LEN - 1) == OK);
    assert(vhost_alias_checkspace(&request, buffer, &cursor, HUGE_STRING_LEN) == 414);
    assert(request.errors == 1 && cursor == buffer && strcmp(buffer, "marker") == 0);

    fixture_pool pool = {0};
    mva_sconf_t conf = {
        .doc_root = "/srv/%1/%%/%p", .cgi_root = "/srv/cgi/%1",
        .doc_root_mode = VHOST_ALIAS_NAME, .cgi_root_mode = VHOST_ALIAS_NAME,
    };
    server_rec server = {&conf};
    request = (request_rec){
        .pool = &pool, .server = &server, .notes = &request,
        .hostname = "Sample.example", .uri = "/index.html",
    };
    assert(mva_translate(&request) == OK);
    assert(strcmp(request.filename, "/srv/sample/%/8080/index.html") == 0);
    assert(strcmp(request.document_root, "/srv/sample/%/8080") == 0);
    assert(request.context_updates == 1 && request.notes_writes == 0);

    request.uri = "/cgi-bin/status";
    assert(mva_translate(&request) == OK);
    assert(strcmp(request.filename, "/srv/cgi/sample/status") == 0);
    assert(strcmp(request.handler, "cgi-script") == 0);
    assert(request.context_updates == 3 && request.notes_writes == 1);

    /* Inject a capacity failure while the request itself stays ordinary. */
    report_capacity_error = 1;
    request.handler = "unchanged";
    assert(mva_translate(&request) == 414);
    assert(strcmp(request.handler, "unchanged") == 0);
    assert(request.context_updates == 3 && request.notes_writes == 1);
    assert(request.errors == 1 && request.filename == NULL);
    puts("Patched C module functions passed capacity, document-root, CGI and 414 tests.");
    return 0;
}
