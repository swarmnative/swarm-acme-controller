swarm-acme-controller（Go 版）
================================

Languages: 中文 | English (see English Summary below)

[![Publish](https://github.com/swarmnative/swarm-acme-controller/actions/workflows/publish.yml/badge.svg)](https://github.com/swarmnative/swarm-acme-controller/actions/workflows/publish.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Docker Pulls](https://img.shields.io/docker/pulls/swarmnative/swarm-acme-controller?logo=docker)](https://hub.docker.com/r/swarmnative/swarm-acme-controller)

镜像：`ghcr.io/swarmnative/swarm-acme-controller` | `docker.io/swarmnative/swarm-acme-controller`

简介
----
纯 Go、distroless 运行的 ACME 证书控制器：在 Swarm 中为带标签的服务（Traefik 可选）自动签发/续签证书，创建版本化 Secrets/Configs，并以 start-first 滚动更新。

特性
----
- 发现带指定标签的服务（默认 `edge.cert.enabled=true`，可用 `EDGE_SERVICE_LABELS` 自定义）。
- 域名来源优先级：`edge.cert.domains`（每服务标签）→ Traefik 原生 `traefik.http.routers.*.rule` 的 Host(...)（默认启用解析）→ 全局 `DOMAINS`（可为空）。
- 可从服务标签覆盖参数：`edge.cert.key_set`、`edge.cert.renew_days`、`edge.cert.mode`、`edge.cert.tls_config_enable`、`edge.cert.tls_config_target`、`edge.cert.tls_config_name_prefix`。
- 证书输出到容器：`/run/secrets/<domain>.<ext>`（默认 `.crt` 与 `.key`）。可选合并 PEM：`/run/secrets/<domain>.pem`。
- Secret 命名（RFC 1123）：`tls-crt-<safe-domain>-<YYYYMMDDHHMM>` / `tls-key-<safe-domain>-<YYYYMMDDHHMM>` / `tls-pem-<safe-domain>-<YYYYMMDDHHMM>`。
- Config 命名（RFC 1123）：`<prefix>-<service>-<YYYYMMDDHHMM>`；按服务仅保留最新 N 代（建议 1）。
- 证书模式：SAN（单证书多域）与 split（每域一证）。
- 支持 ZeroSSL EAB；Distroless 最小镜像，多架构自动构建（lego tag + CA 指纹判重）。

快速开始（Swarm）
-----------------
1) 给你的服务打标签（任意服务）：
```
deploy.labels:
  - edge.cert.enabled=true
  - edge.cert.domains=example.com,*.example.com
```
2) 运行控制器（示例）：
```
services:
  swarm-acme-controller:
    image: ghcr.io/swarmnative/swarm-traefik-acme-controller:latest
    environment:
      - DOCKER_HOST=tcp://docker-socket-proxy:2375
      - LEGO_EMAIL=admin@example.com
      - DNS_PROVIDER=cloudflare
      # DOMAINS 可选（建议每服务通过标签声明）
      # - DOMAINS=example.com,*.example.com
      - LOOP_INTERVAL=12h
      - PERSIST_DIR=/data/.lego
      - PROVIDER_ENV_FILES=CF_API_TOKEN=/run/secrets/DNS_API_TOKEN
      - EDGE_SERVICE_LABELS=edge.cert.enabled=true
      - EDGE_TRAEFIK_USE_NATIVE_LABELS=true
      # 可选：证书文件扩展名与 PEM 合并输出
      - CERT_FILE_EXT=.crt
      - KEY_FILE_EXT=.key
      - COMBINED_PEM_ENABLE=false
      - PEM_FILE_EXT=.pem
      - PEM_ORDER=key-first
      # 可选：动态配置（主要给 Traefik）
      - TLS_CONFIG_ENABLE=false
      - TLS_CONFIG_NAME_PREFIX=prod-edge-traefik-certs
      - TLS_CONFIG_TARGET=/etc/traefik/dynamic/certs.yml
```

环境变量
--------
- `DOCKER_HOST`：指向 socket-proxy，如 `tcp://docker-socket-proxy:2375`
- `LEGO_EMAIL`：ACME 账户邮箱
- `DNS_PROVIDER`：DNS-01 提供商（如 cloudflare、alidns、route53）
- `DOMAINS`：逗号分隔域名列表；可被服务标签/Traefik 原生标签覆盖（未设置也可，仅按标签工作）。
- `EDGE_SERVICE_LABEL`：用于定位目标服务（默认 `edge.cert.enabled=true`）。
- `EDGE_SERVICE_LABELS`：逗号分隔的多个 key=value 过滤（覆盖 `EDGE_SERVICE_LABEL`），例如：`edge.cert.enabled=true,team=web`。
- `EDGE_TRAEFIK_USE_NATIVE_LABELS`：解析 `traefik.http.routers.*.rule` 的 Host(...) 作为域名（默认 `true`）。
- `KEY_SET`：证书类型（默认 ec256；可选 both 以同时签发 EC 与 RSA）
- `ACME_SERVER`：可选，自定义 ACME 端点
- `RENEW_DAYS`：续签阈值（默认 30）
- `PERSIST_DIR`：本地持久化目录（默认 `/data/.lego`）
- `LOOP_INTERVAL`：巡检间隔（默认 `12h`）
- `PROVIDER_ENV_FILES`：从文件注入 Provider 变量映射，如 `CF_API_TOKEN=/run/secrets/DNS_API_TOKEN`
- `TLS_CONFIG_ENABLE`：是否生成/更新证书动态配置（Docker config），主要用于 Traefik（默认 false）
- `TLS_CONFIG_NAME_PREFIX`：动态配置的 config 名称前缀（默认 `prod-edge-traefik-certs`）
- `TLS_CONFIG_TARGET`：在容器内挂载的目标路径（默认 `/etc/traefik/dynamic/certs.yml`）
- `CERT_MODE`：`san|split`（默认 `san`）。`san` 为单张证书覆盖全部 DOMAINS；`split` 为每个域名单独签发并写入多条 `tls.certificates`。
- `EAB_KID`：可选，ACME 外部账户绑定 KID（ZeroSSL 必需）
- `EAB_HMAC`：可选，ACME 外部账户绑定 HMAC（ZeroSSL 必需，Base64 编码）
- 提示：EAB_KID/EAB_HMAC 建议通过 `PROVIDER_ENV_FILES` 从 Secret 文件注入，例如 `EAB_KID=/run/secrets/zerossl_kid,EAB_HMAC=/run/secrets/zerossl_hmac`。
- `RETAIN_GENERATIONS`：保留多少代历史（默认 2，即“最新版+上一版”），老的 Secrets/Configs 将被清理。
- `CERT_FILE_EXT`：证书文件扩展名（默认 `.crt`）
- `KEY_FILE_EXT`：私钥文件扩展名（默认 `.key`）
- `COMBINED_PEM_ENABLE`：是否额外输出合并 PEM（默认 `false`）
- `PEM_FILE_EXT`：合并 PEM 扩展名（默认 `.pem`，也可设为 `.crt`）
- `PEM_ORDER`：合并顺序（`key-first` 或 `cert-first`，默认 `key-first`）

构建与发布
----------
GitHub Actions 自动构建并推送到 GHCR：
- 推送到 main/master 分支，或每日定时触发
- 多架构：linux/amd64, linux/arm64

CA 证书与 Traefik 配置
----------------------
- 镜像在构建期内置系统 CA（/etc/ssl/certs/ca-certificates.crt），用于 HTTPS 与 DNS Provider API 的 TLS 校验，无需额外挂载。
- Traefik 使用建议：
  - 启用 file provider 并 watch：
    ```
    --providers.file.directory=/etc/traefik/dynamic
    --providers.file.watch=true
    ```
  - 若启用 `TLS_CONFIG_ENABLE=true`：控制器会生成 certs.yml 并以 Docker config 注入到 `TLS_CONFIG_TARGET`（默认 `/etc/traefik/dynamic/certs.yml`），Traefik 自动生效；按服务仅保留最新版（由 `RETAIN_GENERATIONS` 决定）。
  - 若不启用动态配置，也可让路由直接引用 `/run/secrets/<domain>.<ext>`。

socket-proxy 权限建议
--------------------
- 最小权限只需 Swarm 读取与 Service 更新：
  - 允许：`/services`（list/inspect/update）、`/secrets`（list/create/remove）、`/configs`（list/create/remove）
  - 可选：`/nodes`（只读）、`/events`（只读）
- 禁止：`/containers`、`/images` 等与本控制器无关的写操作。

示例 Swarm Stack（通用）
----------------------
```yaml
networks:
  app-net:
    external: true

secrets:
  dns_api_token:
    external: true

volumes:
  certlego: {}

services:
  swarm-acme-controller:
    image: ghcr.io/swarmnative/swarm-acme-controller:latest
    environment:
      - DOCKER_HOST=tcp://docker-socket-proxy:2375
      - LOOP_INTERVAL=12h
      - PERSIST_DIR=/data/.lego
      - PROVIDER_ENV_FILES=CF_API_TOKEN=/run/secrets/DNS_API_TOKEN
      - LEGO_EMAIL=admin@example.com
      - DNS_PROVIDER=cloudflare
      # 每服务用标签声明域名
      - EDGE_SERVICE_LABELS=edge.cert.enabled=true
      - RENEW_DAYS=30
      - TLS_CONFIG_ENABLE=false
      - CERT_FILE_EXT=.crt
      - KEY_FILE_EXT=.key
      - COMBINED_PEM_ENABLE=false
      - PEM_FILE_EXT=.pem
      - PEM_ORDER=key-first
    secrets:
      - source: dns_api_token
        target: /run/secrets/DNS_API_TOKEN
        mode: 0400
    networks:
      - app-net
    volumes:
      - certlego:/data/.lego
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
```
  
注意：
- 将 `docker-socket-proxy` 改为你的 socket-proxy 服务名；或直接挂载 `/var/run/docker.sock`（不推荐）。
- `dns_api_token` 请在 Swarm 预先创建，并在容器内由 DNS Provider 官方变量读取（如 Cloudflare 为 `CF_API_TOKEN`，通过 `PROVIDER_ENV_FILES` 注入）。
- 若无需 socket-proxy，可不设 `DOCKER_HOST`，并在服务中挂载本地 `/var/run/docker.sock:/var/run/docker.sock:ro`。

多域名与 Traefik 配置
--------------------
- SAN（单证书多域）：不必修改路由引用，建议启用动态 certs.yml，由控制器写入多条 `tls.certificates`。
- split（每域一证）：控制器按域生成多条条目。也可在路由里直接引用 `/run/secrets/<domain>.<ext>`。

socket-proxy 权限建议
--------------------
- 最小权限只需 Swarm 读取与 Service 更新：
  - 允许：`/services`（list/inspect/update）、`/secrets`（list/create/remove）、`/configs`（list/create/remove）
  - 可选：`/nodes`（只读）、`/events`（只读）
- 禁止：`/containers`、`/images` 等与本控制器无关的写操作。

附录：最小 Traefik Stack 片段（file provider）
-------------------------------------------
```yaml
networks:
  app-net:
    external: true

services:
  traefik:
    image: traefik:latest
    command:
      - --providers.docker=true
      - --providers.docker.swarmMode=true
      - --providers.docker.network=app-net
      - --providers.file.directory=/etc/traefik/dynamic
      - --providers.file.watch=true
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --api.dashboard=false
    ports:
      - target: 80
        published: 80
        protocol: tcp
        mode: host
      - target: 443
        published: 443
        protocol: tcp
        mode: host
    networks:
      - app-net
    configs:
      - source: traefik_dynamic_base
        target: /etc/traefik/dynamic/base.yml
        mode: 0444
    deploy:
      replicas: 1
      labels:
        - edge.cert.enabled=true
        # 可直接使用 Traefik 原生标签声明域名（默认启用解析），例如：
        # traefik.http.routers.websecure.rule=Host(`a.example.com`,`b.example.com`)
      update_config:
        order: start-first
        parallelism: 1
      placement:
        constraints:
          - node.labels.edge.traefik == true

configs:
  traefik_dynamic_base:
    external: true
```
说明：
- `traefik_dynamic_base` 可为空的基础动态配置（如中间件链），证书条目由控制器按需生成 `certs.yml` 注入（启用 TLS_CONFIG_ENABLE）。

通用服务示例（非 Traefik）
------------------------
```yaml
services:
  myapp:
    image: nginx:alpine
    deploy:
      labels:
        - edge.cert.domains=example.com,*.a.example.com
    # 控制器将自动注入：/run/secrets/example.com.crt 与 /run/secrets/example.com.key
    # 若启用合并 PEM：/run/secrets/example.com.pem
```

证书与命名说明
--------------
- Secret 命名（RFC 1123）：`tls-crt-<safe-domain>-<ts>`、`tls-key-<safe-domain>-<ts>`；`<safe-domain>` 会把 `*`→`star`、`.`→`-` 并转小写。
- Config 命名（RFC 1123）：`<prefix>-<service>-<ts>`；仅启用动态配置时创建；前缀便于区分与批量清理。
- 文件扩展名可调：`CERT_FILE_EXT`、`KEY_FILE_EXT`、`PEM_FILE_EXT`；合并 PEM 可由 `COMBINED_PEM_ENABLE` 与 `PEM_ORDER` 控制。

证书模式说明
------------
- SAN（默认）：
  - 一张证书覆盖 DOMAINS 列表；配额少、管理简单；注意 SAN 会在证书中并列可见域名。
- split：
  - 每个域名单独证书，隔离更好；增加签发/续签次数，需关注 ACME 速率限制。

ZeroSSL（EAB）示例（split + 通配符，Secret 注入）
----------------------------------------------
```yaml
services:
  swarm-acme-controller:
    image: ghcr.io/swarmnative/swarm-acme-controller:latest
    environment:
      - DOCKER_HOST=tcp://docker-socket-proxy:2375
      - EDGE_SERVICE_LABELS=edge.traefik.service=true
      - DNS_PROVIDER=cloudflare
      - LEGO_EMAIL=admin@example.com
      - ACME_SERVER=https://acme.zerossl.com/v2/DV90
      - PROVIDER_ENV_FILES=EAB_KID=/run/secrets/zerossl_kid,EAB_HMAC=/run/secrets/zerossl_hmac,CF_API_TOKEN=/run/secrets/DNS_API_TOKEN
      - CERT_MODE=split
      - DOMAINS=*.a.example.com,*.b.example.com
      - TLS_CONFIG_ENABLE=true
    secrets:
      - source: zerossl_kid
        target: /run/secrets/zerossl_kid
        mode: 0400
      - source: zerossl_hmac
        target: /run/secrets/zerossl_hmac
        mode: 0400
      - source: dns_api_token
        target: /run/secrets/DNS_API_TOKEN
        mode: 0400
secrets:
  zerossl_kid:
    external: true
  zerossl_hmac:
    external: true
  dns_api_token:
    external: true
```

许可证
----
MIT

免责声明
------
本项目为社区维护，与 Docker, Inc.、Mirantis、Traefik 或任何相关公司无关、无隶属或背书关系。

English Summary
---------------
Go-based ACME controller for Docker Swarm and Traefik. It issues/renews certificates (Let’s Encrypt / ZeroSSL EAB), injects versioned Secrets/Configs, and rolls out with start-first updates.

- Modes: SAN (one cert for multiple domains) and split (one cert per domain)
- ACME: DNS-01; supports ZeroSSL EAB (EAB_KID/EAB_HMAC + ACME_SERVER)
- TLS config: optional certs.yml (enable via TLS_CONFIG_ENABLE=true)
- Retention: RETAIN_GENERATIONS for GC of old Secrets/Configs (default 2)
- Docker access: DOCKER_HOST (socket-proxy) or fallback to /var/run/docker.sock

Quick usage
```
services:
  swarm-acme-controller:
    image: ghcr.io/swarmnative/swarm-acme-controller:latest
    environment:
      - DOCKER_HOST=tcp://docker-socket-proxy:2375
      - EDGE_SERVICE_LABELS=edge.traefik.service=true
      - LEGO_EMAIL=admin@example.com
      - DNS_PROVIDER=cloudflare
      - DOMAINS=example.com,*.example.com
      - TLS_CONFIG_ENABLE=false
```
See the Chinese sections above for full environment variables, Traefik snippet, ZeroSSL secret injection, and socket-proxy permissions.


