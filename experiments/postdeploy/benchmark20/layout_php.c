#include "php.h"
#include "SAPI.h"
#include <stddef.h>
#include <stdio.h>
int main(void) {
    printf("{\"modules_activated\":%zu,\"uploads\":%zu,\"throws\":%zu}\n",
        offsetof(php_core_globals,modules_activated),
        offsetof(sapi_globals_struct,rfc1867_uploaded_files),
        offsetof(sapi_globals_struct,request_parse_body_context)+offsetof(sapi_request_parse_body_context,throw_exceptions));
    return 0;
}
