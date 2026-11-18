#ifndef VG_EXPERIMENT_TRACE_H
#define VG_EXPERIMENT_TRACE_H
#include <stdio.h>
void vg_trace_begin(const void *module_symbol);
void vg_trace_finish_json(FILE *output);
#endif
