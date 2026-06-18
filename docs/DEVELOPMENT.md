# 开发与部署文档

## 1. 本地开发依赖

在 Debian/Ubuntu 环境可直接安装：

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake pkg-config \
  libmicrohttpd-dev libjansson-dev libsodium-dev libsqlite3-dev
```

## 2. 本地构建

```bash
cmake -S . -B build
cmake --build build -j
```

生成产物：`./build/jinxiaocun-server`

## 3. 本地运行

```bash
PORT=8080 \
DB_PATH=./data/app.db \
USER_DATA_KEY_FILE=./data/user_key.b64 \
SESSION_TTL_HOURS=12 \
./build/jinxiaocun-server
```

## 4. Docker 部署

### 4.1 启动

```bash
docker compose up -d --build

# 如 8080 端口被占用
APP_PORT=18080 docker compose up -d --build
```

### 4.2 查看日志

```bash
docker logs -f jinxiaocun-backend
```

### 4.3 Swagger 验证

```bash
# OpenAPI JSON
curl http://localhost:8080/api/v1/openapi.json

# Swagger UI
open http://localhost:8080/docs
```

### 4.4 停止

```bash
docker compose down
```

## 5. 数据持久化

`docker-compose.yml` 已将本地 `./data` 挂载到容器 `/app/data`：

- 数据库：`./data/app.db`
- 自动生成密钥：`./data/user_key.b64`

请备份 `user_key.b64`，否则旧数据无法解密。

## 6. 安全建议（生产环境）

- 通过 HTTPS 反向代理对外暴露服务（Nginx/Traefik）
- 将 `USER_DATA_KEY_B64` 注入到安全的密钥管理系统，不落盘
- 缩短 `SESSION_TTL_HOURS` 并结合网关限流
- 对登录接口增加 IP 级限流与失败次数锁定策略
- 定期备份 SQLite 数据并验证恢复流程

## 7. 可扩展建议

- 接入 PostgreSQL（多实例高并发时更合适）
- 增加 RBAC 权限模型（仓库员/审计员/运营）
- 增加审计日志与导出报表
- 增加自动补货阈值提醒
