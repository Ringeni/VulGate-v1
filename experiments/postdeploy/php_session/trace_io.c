#include <stdio.h>
#include "trace.h"

/* Host experiment control; this is not executed by patch bytecode. */
int vg_trace_finish_file(const char *path) {
    FILE *out = fopen(path, "w");
    if (!out) return -1;
    fputc('{', out);
    vg_trace_finish_json(out);
    fputs("}\n", out);
    return fclose(out);
}
