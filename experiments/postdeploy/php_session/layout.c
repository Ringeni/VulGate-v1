#include "php.h"
#include "ext/session/php_session.h"
#include <stddef.h>
#include <stdio.h>
int main(void) {
#ifdef ZTS
    const int zts = 1;
#else
    const int zts = 0;
#endif
    printf("{\"zts\":%d,\"progress_offset\":%zu,\"enabled_offset\":%zu,\"success\":%d}\n",
        zts, offsetof(zend_ps_globals, rfc1867_progress), offsetof(zend_ps_globals, rfc1867_enabled), SUCCESS);
    return 0;
}
