# 园区矿泉水自助零售管理系统（纯后端 / C 语言）

本项目是一个基于 C 语言实现的园区矿泉水自助零售后端系统，聚焦“进、销、存”主流程，具备鉴权、安全加密、数据库持久化与容器化部署能力。

## 项目亮点

- 纯后端 REST API（C11）
- 进销存全流程：入库、销售、库存汇总、流水查询
- SQLite 数据库持久化
- 密码哈希（libsodium）
- 用户敏感字段加密存储（姓名/邮箱/手机号）
- Bearer Token 鉴权（服务端仅存储 token 哈希）
- Swagger UI + OpenAPI 自动映射最新接口
- Docker / Docker Compose 一键部署

## 🚀 快速启动

### 方式一：Docker 一键启动（推荐）

```bash
docker compose up -d --build
```

如果本机 `8080` 端口被占用：

```bash
APP_PORT=18080 docker compose up -d --build
```

启动后访问：

- 服务健康检查：`http://localhost:8080/api/v1/health`
- Swagger UI：`http://localhost:8080/docs`
- OpenAPI JSON：`http://localhost:8080/api/v1/openapi.json`

停止服务：

```bash
docker compose down
```

### 方式二：本地编译运行

```bash
cmake -S . -B build
cmake --build build -j
./build/jinxiaocun-server
```

默认配置：

- 端口：`8080`
- 数据库：`./data/app.db`
- 用户加密密钥文件：`./data/user_key.b64`

## 初始化账号

系统首次启动会自动创建默认管理员账号：

- 用户名：`admin`
- 密码：`Admin@123456`

可通过环境变量覆盖：

- `DEFAULT_ADMIN_USERNAME`
- `DEFAULT_ADMIN_PASSWORD`

登录后可使用管理员权限创建其他用户：

1. 调用 `POST /api/v1/auth/login` 获取 `Bearer Token`
2. 使用管理员 Token 调用 `POST /api/v1/auth/register` 创建新用户
3. 使用管理员令牌创建商品并执行进销存操作

## 核心接口

- 认证：注册、登录、登出、当前用户信息
- 商品：新增商品、商品列表
- 进销存：入库、销售、库存查询、流水查询
- 文档：OpenAPI JSON、Swagger UI

接口详情见：

- API 文档：[`docs/API.md`](docs/API.md)
- 开发文档：[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)

## 安全设计

- 密码：`crypto_pwhash_str` / `crypto_pwhash_str_verify`
- 用户敏感信息：`crypto_secretbox` 加密后入库
- 会话鉴权：Bearer Token + 服务端 token 哈希存储
- 数据访问：SQL 预编译绑定参数
- 库存一致性：入库/销售事务化处理

## 环境变量

| 变量名 | 默认值 | 说明 |
|---|---|---|
| `PORT` | `8080` | 服务监听端口 |
| `DB_PATH` | `./data/app.db` | SQLite 数据文件 |
| `USER_DATA_KEY_FILE` | `./data/user_key.b64` | 用户字段加密密钥文件 |
| `USER_DATA_KEY_B64` | 空 | 直接注入 base64 密钥（优先于文件） |
| `SESSION_TTL_HOURS` | `12` | 登录会话有效期（小时） |

## 目录结构

```text
.
├── src/
│   ├── main.c
│   ├── http/
│   │   ├── response.c
│   │   ├── response.h
│   │   └── routes_meta.h
│   └── docs/
│       ├── docs_ui.c
│       └── docs_ui.h
├── docs/
│   ├── API.md
│   └── DEVELOPMENT.md
├── .env.example
├── CMakeLists.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

