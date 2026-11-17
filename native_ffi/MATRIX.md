# FFI behavior matrix

This matrix records the current real-application evidence for the FFI backend.
`FFI` means the mount was installed through `libvg_ffi.so`; `fallback` means
the original DSL uses Frida Interceptor because funchook is not reliable for
that target.

| # | CVE | App | FFI mount | Trigger | Result |
|---:|---|---|---|---|---|
| 1 | CVE-2026-15176 | nginx | `coarse: ngx_http_static_handler` | `/files/file.txt` | 200 → 500 |
| 2 | CVE-2026-27654 | nginx | `ngx_http_dav_copy_move_handler` | DAV COPY | 204 → 405 |
| 3 | CVE-2026-42055 | nginx | `proxy_v2_create_request` + `grpc_create_request` | `/h2proxy`, `/grpc` | 502 → 500 |
| 4 | CVE-2026-42533 | nginx | `ngx_http_map_variable` | `/map/ordinary` | BLOCK run=1, HTTP 200 |
| 5 | CVE-2026-42945 | nginx | `ngx_http_rewrite_handler` | `/rewrite/ordinary` | 302 → 500 |
| 6 | CVE-2026-47360 | httpd | `proxy_handler` | internal redirect | run=1, HTTP 404 |
| 7 | CVE-2026-56153 | httpd | `xlate_out_filter` | charset request | 200 → 500 |
| 8 | CVE-2026-56154 | httpd | `lookup_variable` | `/rewritehost` | Location `x=` |
| 9 | CVE-2026-56449 | httpd | `pcomment` | proxy-html comment | comment removed |
| 10 | CVE-2026-57941 | httpd | `h2_c1_setup` | HTTP/2 | connection failure |
| 11 | CVE-2026-60005 | nginx | `ngx_http_regex_exec` | SSI include with `set` | run=1, HTTP 200 |
| 12 | CVE-2026-63292 | httpd | `mva_translate` | vhost request | 200 → 414 |
| 13 | CVE-2026-63686 | httpd | `xml2enc_ffunc` | `/xml/x.html` | 200 → 500 |
| 14 | CVE-2026-9256 | nginx | `ngx_http_rewrite_handler` | `/rewrite/ordinary` | 302 → 500 |
| 15 | CVE-2026-93479 | nginx | `coarse: ngx_http_rewrite_handler` | `/rewrite/ordinary` | 500; original fine version hangs |
| 16 | CVE-2026-93546 | httpd | `dav_method_proppatch` | PROPPATCH | 207 → 503 |
| 17 | CVE-2026-97205 | nginx | `coarse: ngx_http_output_filter` | SSI + proxy_store + aio_write | 000; guard run=1 |
| 18 | CVE-2026-109618 | PHP | `rfc1867_post_handler` | multipart upload | files empty |
| 19 | CVE-2026-109619 | PHP | `php_session_rfc1867_callback` | fresh PHPSESSID progress upload | files normal, progress=false |
| 20 | CVE-2026-111497 | brotli | callsite `WriteRingBuffer` | real worker | error=-9, produced=0 |

## Notes

- 15176 and 97205 coarse patches are pure funchook mounts and are listed in
  `native_ffi/patches/`.
- The original 15176 and 97205 DSLs use a controlled Frida fallback because
  funchook does not reliably relocate those entries.
- 42533 / 60005 / 97205 execute BLOCK but the target function does not map that
  return value to a standard HTTP 500/503.
- 47360's final HTTP 404 is produced by httpd's ErrorDocument internal
  redirect; the guard itself ran (`run=1`).
- 93479's official fine-grained version still hangs; only the coarse alternative
  is usable.
