# API 文档（v1）

Base URL: `http://localhost:8080/api/v1`

## 0. Swagger 文档

- Swagger UI：`http://localhost:8080/docs`
- OpenAPI JSON：`http://localhost:8080/api/v1/openapi.json`

说明：OpenAPI 由后端路由注册表自动生成，代码中的 API 路由变化后会自动映射到最新文档。

统一响应格式：

- 成功：
```json
{"success":true,"data":{}}
```

- 失败：
```json
{"success":false,"error":{"code":"ERROR_CODE","message":"错误描述"}}
```

## 1. 健康检查

### GET `/health`

返回服务状态。

## 2. 认证

### POST `/auth/register`

创建用户。

- 当系统中没有任何用户时：允许匿名调用，首个用户强制为 `admin`
- 当系统已有用户时：必须由 `admin` 调用

请求体：

```json
{
  "username": "admin",
  "password": "Admin@123456",
  "role": "admin",
  "full_name": "张三",
  "email": "admin@example.com",
  "phone": "13800000000"
}
```

### POST `/auth/login`

登录并获取 Token。

请求体：

```json
{
  "username": "admin",
  "password": "Admin@123456"
}
```

返回示例：

```json
{
  "success": true,
  "data": {
    "access_token": "xxxxx",
    "token_type": "Bearer",
    "expires_at": 1730000000,
    "user_id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

### POST `/auth/logout`

退出登录，需 Header：

```http
Authorization: Bearer <token>
```

### GET `/auth/me`

获取当前登录用户信息（包含解密后的用户字段）。

## 3. 商品管理

### POST `/products`

新增商品（仅 admin）。

请求体：

```json
{
  "sku": "WATER-550ML",
  "name": "矿泉水 550ml",
  "unit": "瓶"
}
```

### GET `/products`

获取商品列表。

## 4. 进销存

### POST `/inbound`

入库（采购补货）。

请求体：

```json
{
  "sku": "WATER-550ML",
  "quantity": 100,
  "unit_cost_cents": 120,
  "note": "周一补货"
}
```

### POST `/sales`

销售出库。

请求体：

```json
{
  "sku": "WATER-550ML",
  "quantity": 5,
  "unit_price_cents": 200,
  "note": "扫码售卖"
}
```

当库存不足时返回 `409 CONFLICT`，错误码 `INSUFFICIENT_STOCK`。

### GET `/inventory`

获取库存汇总与明细。

### GET `/movements?type=IN&limit=50`

获取库存流水。

- `type`: 可选，`IN` 或 `OUT`
- `limit`: 可选，范围 `1~200`，默认 `50`

## 5. cURL 示例

```bash
# 1) 管理员注册
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@123456","full_name":"管理员","email":"admin@park.com","phone":"13800000000"}'

# 2) 登录
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@123456"}' | jq -r '.data.access_token')

# 3) 新增商品
curl -X POST http://localhost:8080/api/v1/products \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sku":"WATER-550ML","name":"矿泉水550ml","unit":"瓶"}'

# 4) 入库
curl -X POST http://localhost:8080/api/v1/inbound \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sku":"WATER-550ML","quantity":200,"unit_cost_cents":100}'

# 5) 销售
curl -X POST http://localhost:8080/api/v1/sales \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sku":"WATER-550ML","quantity":8,"unit_price_cents":200}'

# 6) 查看库存
curl http://localhost:8080/api/v1/inventory
```
