# Apache httpd 2.4.68 模块回移

`httpd-2.4.68-CVE-2026-63292.patch` 将 Apache 2.4.69 的 `mod_vhost_alias` 修复回移到上游 2.4.68。它在写入前检查每个实际展开片段的容量，并在触发上限时由翻译钩子返回 414，早于 CGI 后续处理。应用补丁后，该模块源文件与 Apache 2.4.69 对应文件一致。[Apache 公告](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2026-63292) · [Apache 2.4.69 模块源码](https://github.com/apache/httpd/blob/2.4.69/modules/mappers/mod_vhost_alias.c)

在干净的上游 2.4.68 源码树运行以下命令。将路径替换为本仓库和 Apache 源码树的绝对路径。

```sh
git -C "$httpd_src" apply --check "$vulgate_repo/deploy/backports/httpd-2.4.68-CVE-2026-63292.patch"
git -C "$httpd_src" apply "$vulgate_repo/deploy/backports/httpd-2.4.68-CVE-2026-63292.patch"
```

沿用目标 2.4.68 构建的配置重编 `mod_vhost_alias`，在隔离的目标环境做配置检查和正常的虚拟主机、CGI 请求回归。若使用发行版源码，先核对其维护者是否已回移同一个修复。此补丁是模块源码变更，应用到源码并重新构建后生效。

## 验证

在 VulGate 仓库根目录运行，`$httpd_ref` 指向包含 `2.4.68`、`2.4.69` 标签的 Apache Git checkout。

```sh
python deploy/backports/verify_cve_2026_63292.py "$httpd_ref"
```

检验脚本使用临时目录，核对补丁可应用且产物与 2.4.69 发布文件逐字节一致。随后以 C 夹具编译补丁后的实际函数，覆盖容量边界、正常站点和 CGI 路径，以及 414 在 CGI 后续处理前的传播。目标 Linux DSO 的构建、加载和请求回归单独验收。

上游模块补丁受 [Apache License 2.0](LICENSE.Apache-2.0) 约束。模块由 Demon Internet Ltd. 原始贡献，Apache 版本由 Apache Software Foundation 发布维护。
