# FFI behavior matrix

This matrix records the current real-application evidence for the FFI backend.
All mounts use the independent INT3 engine; there is no Frida hook fallback.

| # | CVE | App | FFI mount | Trigger | Result |
|---:|---|---|---|---|---|
| 1 | CVE-2026-15176 | nginx | `ngx_http_map_uri_to_path` (INT3) | `/files/file.txt` | 200 -> 500 |
| 2 | CVE-2026-27654 | nginx | `ngx_http_dav_copy_move_handler` | DAV COPY | 204 -> 405 |
| 3 | CVE-2026-42055 | nginx | `proxy_v2_create_request` + `grpc_create_request` | `/h2proxy`, `/grpc` | 502 -> 500 |
| 4 | CVE-2026-42533 | nginx | `ngx_http_map_variable` | `/map/ordinary` | BLOCK run=1, HTTP 200 |
| 5 | CVE-2026-42945 | nginx | `ngx_http_rewrite_handler` | `/rewrite/ordinary` | 302 -> 500 |
| 6 | CVE-2026-47360 | httpd | `proxy_handler` | internal redirect / proxy | run=1; HTTP 404 or 503 by path |
| 7 | CVE-2026-56153 | httpd | `xlate_out_filter` | charset request | 200 -> 500 |
| 8 | CVE-2026-56154 | httpd | `lookup_variable` | `/rewritehost` | 302, Location `x=` |
| 9 | CVE-2026-56449 | httpd | `pcomment` | proxy-html comment | comment removed |
| 10 | CVE-2026-57941 | httpd | `h2_c1_setup` | HTTP/2 | connection failure (000) |
| 11 | CVE-2026-60005 | nginx | `ngx_http_regex_exec` | SSI include with `set` | run=1, HTTP 200 |
| 12 | CVE-2026-63292 | httpd | `mva_translate` | vhost request | 200 -> 414 |
| 13 | CVE-2026-63686 | httpd | `xml2enc_ffunc` | `/xml/x.html` | 200 -> 500 |
| 14 | CVE-2026-9256 | nginx | `ngx_http_rewrite_handler` | `/rewrite/ordinary` | 302 -> 500 |
| 15 | CVE-2026-93479 | nginx | `coarse: ngx_http_rewrite_handler` | `/rewrite/ordinary` | 500; original fine version hangs |
| 16 | CVE-2026-93546 | httpd | `dav_method_proppatch` | PROPPATCH | 207 -> 503 |
| 17 | CVE-2026-97205 | nginx | `ngx_http_copy_filter` (INT3) | SSI + proxy_store + aio_write | 000; guard run=1 |
| 18 | CVE-2026-109618 | PHP | `rfc1867_post_handler` | multipart upload | files empty |
| 19 | CVE-2026-109619 | PHP | `php_session_rfc1867_callback` | fresh PHPSESSID progress upload | files normal, progress=false |
| 20 | CVE-2026-111497 | brotli | observer + guard on `WriteRingBuffer` | real worker | error=-9, produced=0 |

## INT3 install coverage

All 20 patches install through the INT3 bridge:

```text
nginx 9:  15176 27654 42055 42533 42945 60005 9256 93479 97205
httpd 8:  47360 56153 56154 56449 57941 63292 63686 93546
php 2:    109618 109619
brotli 1: 111497
```

`ffi_run.py` maps 93479 to the coarse rewrite patch; the rest use the original
DSLs. 111497 installs its observer and guard on the same entry.

## Extreme-condition checks

| Check | Result |
|---|---|
| 10 x install/uninstall, nginx 15176 | all rc=0, nginx alive 200 |
| 32-thread load, INT3 42945 | 875 RPS, all 500, 0 errors |
| 2-worker nginx, install on both pids | all COPY 405 |
| uninstall after load | 302 |
| target exits during patch | `target_gone`, no crash |
| loop fixture | 4 iterations, body_calls=0 |
| bounded loop bound > 256 | compile error |

## INT3 engine checks

| Check | Result |
|---|---|
| real nginx, preload driver, `ngx_http_map_uri_to_path` | `/files/file.txt` 500, `/plain` 200 |
| real brotli worker, `WriteRingBuffer` unconditional | error=-9, produced=0 |
| real brotli worker, `local("available_in") != 0` | error=-9 |
| local nginx 1000 requests, 16 curl workers | baseline 1.24 s, INT3 1.28 s |

The nginx and brotli checks use `LD_PRELOAD` drivers, not Frida.

## Notes

- 42533 / 60005 / 97205 execute BLOCK but the target function does not map that
  return value to a standard HTTP 500/503.
- 47360's final status depends on the request path; the guard itself runs.
- 93479's official fine-grained version still hangs; only the coarse alternative
  is usable.
