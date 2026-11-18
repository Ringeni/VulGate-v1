#include "httpd.h"
#include "http_config.h"
#include <stddef.h>
#include <stdio.h>
int main(void) {
    printf("{\"request_rec.prev\":%zu,\"request_rec.server\":%zu,\"request_rec.hostname\":%zu,"
           "\"server_rec.module_config\":%zu,\"module.module_index\":%zu}\n",
           offsetof(request_rec,prev),offsetof(request_rec,server),offsetof(request_rec,hostname),
           offsetof(server_rec,module_config),offsetof(module,module_index));
    return 0;
}
