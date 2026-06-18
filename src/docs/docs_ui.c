#include "docs_ui.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <jansson.h>
#include <microhttpd.h>

#include "../http/response.h"

static const char *method_to_openapi_key(const char *method) {
    if (strcmp(method, MHD_HTTP_METHOD_GET) == 0) {
        return "get";
    }
    if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
        return "post";
    }
    if (strcmp(method, MHD_HTTP_METHOD_PUT) == 0) {
        return "put";
    }
    if (strcmp(method, MHD_HTTP_METHOD_PATCH) == 0) {
        return "patch";
    }
    if (strcmp(method, MHD_HTTP_METHOD_DELETE) == 0) {
        return "delete";
    }
    return NULL;
}

static void build_operation_id(const ApiRoute *route, char *out, size_t out_size) {
    snprintf(out, out_size, "%s_%s", route->method, route->path);
    for (size_t i = 0; out[i] != '\0'; ++i) {
        const unsigned char c = (unsigned char)out[i];
        if (isalnum(c)) {
            out[i] = (char)tolower(c);
        } else {
            out[i] = '_';
        }
    }
}

static json_t *build_generic_success_schema(void) {
    json_t *schema = json_object();
    json_object_set_new(schema, "type", json_string("object"));

    json_t *props = json_object();
    json_t *success_schema = json_object();
    json_object_set_new(success_schema, "type", json_string("boolean"));
    json_object_set_new(props, "success", success_schema);

    json_t *data_schema = json_object();
    json_object_set_new(data_schema, "description",
                        json_string("业务返回数据，结构随接口而变化"));
    json_object_set_new(props, "data", data_schema);

    json_object_set_new(schema, "properties", props);
    return schema;
}

static json_t *schema_ref(const char *name) {
    json_t *ref = json_object();
    char buf[256];
    snprintf(buf, sizeof(buf), "#/components/schemas/%s", name);
    json_object_set_new(ref, "$ref", json_string(buf));
    return ref;
}

static const char *request_schema_name_for_route(const ApiRoute *route) {
    if (strcmp(route->method, MHD_HTTP_METHOD_POST) != 0) {
        return NULL;
    }
    if (strcmp(route->path, "/api/v1/auth/register") == 0) {
        return "RegisterRequest";
    }
    if (strcmp(route->path, "/api/v1/auth/login") == 0) {
        return "LoginRequest";
    }
    if (strcmp(route->path, "/api/v1/products") == 0) {
        return "CreateProductRequest";
    }
    if (strcmp(route->path, "/api/v1/inbound") == 0) {
        return "InboundRequest";
    }
    if (strcmp(route->path, "/api/v1/sales") == 0) {
        return "SalesRequest";
    }
    return NULL;
}

static json_t *request_example_for_route(const ApiRoute *route) {
    if (strcmp(route->path, "/api/v1/auth/register") == 0) {
        json_t *obj = json_object();
        json_object_set_new(obj, "username", json_string("admin"));
        json_object_set_new(obj, "password", json_string("Admin@123456"));
        json_object_set_new(obj, "full_name", json_string("管理员"));
        json_object_set_new(obj, "email", json_string("admin@park.com"));
        json_object_set_new(obj, "phone", json_string("13800000000"));
        return obj;
    }
    if (strcmp(route->path, "/api/v1/auth/login") == 0) {
        json_t *obj = json_object();
        json_object_set_new(obj, "username", json_string("admin"));
        json_object_set_new(obj, "password", json_string("Admin@123456"));
        return obj;
    }
    if (strcmp(route->path, "/api/v1/products") == 0) {
        json_t *obj = json_object();
        json_object_set_new(obj, "sku", json_string("WATER-550ML"));
        json_object_set_new(obj, "name", json_string("矿泉水 550ml"));
        json_object_set_new(obj, "unit", json_string("瓶"));
        return obj;
    }
    if (strcmp(route->path, "/api/v1/inbound") == 0) {
        json_t *obj = json_object();
        json_object_set_new(obj, "sku", json_string("WATER-550ML"));
        json_object_set_new(obj, "quantity", json_integer(100));
        json_object_set_new(obj, "unit_cost_cents", json_integer(120));
        json_object_set_new(obj, "note", json_string("周一补货"));
        return obj;
    }
    if (strcmp(route->path, "/api/v1/sales") == 0) {
        json_t *obj = json_object();
        json_object_set_new(obj, "sku", json_string("WATER-550ML"));
        json_object_set_new(obj, "quantity", json_integer(5));
        json_object_set_new(obj, "unit_price_cents", json_integer(200));
        json_object_set_new(obj, "note", json_string("扫码售卖"));
        return obj;
    }
    return NULL;
}

static json_t *make_string_schema(size_t min_len, size_t max_len) {
    json_t *schema = json_object();
    json_object_set_new(schema, "type", json_string("string"));
    if (min_len > 0) {
        json_object_set_new(schema, "minLength", json_integer((json_int_t)min_len));
    }
    if (max_len > 0) {
        json_object_set_new(schema, "maxLength", json_integer((json_int_t)max_len));
    }
    return schema;
}

static json_t *make_integer_schema(int min, int max) {
    json_t *schema = json_object();
    json_object_set_new(schema, "type", json_string("integer"));
    json_object_set_new(schema, "minimum", json_integer(min));
    json_object_set_new(schema, "maximum", json_integer(max));
    return schema;
}

static json_t *build_request_schemas(void) {
    json_t *schemas = json_object();

    json_t *register_schema = json_object();
    json_object_set_new(register_schema, "type", json_string("object"));
    json_t *register_props = json_object();
    json_object_set_new(register_props, "username", make_string_schema(1, 64));
    json_object_set_new(register_props, "password", make_string_schema(1, 128));
    json_object_set_new(register_props, "role", make_string_schema(0, 16));
    json_object_set_new(register_props, "full_name", make_string_schema(0, 128));
    json_object_set_new(register_props, "email", make_string_schema(0, 128));
    json_object_set_new(register_props, "phone", make_string_schema(0, 64));
    json_object_set_new(register_schema, "properties", register_props);
    json_t *register_required = json_array();
    json_array_append_new(register_required, json_string("username"));
    json_array_append_new(register_required, json_string("password"));
    json_object_set_new(register_schema, "required", register_required);
    json_object_set_new(schemas, "RegisterRequest", register_schema);

    json_t *login_schema = json_object();
    json_object_set_new(login_schema, "type", json_string("object"));
    json_t *login_props = json_object();
    json_object_set_new(login_props, "username", make_string_schema(1, 64));
    json_object_set_new(login_props, "password", make_string_schema(1, 128));
    json_object_set_new(login_schema, "properties", login_props);
    json_t *login_required = json_array();
    json_array_append_new(login_required, json_string("username"));
    json_array_append_new(login_required, json_string("password"));
    json_object_set_new(login_schema, "required", login_required);
    json_object_set_new(schemas, "LoginRequest", login_schema);

    json_t *product_schema = json_object();
    json_object_set_new(product_schema, "type", json_string("object"));
    json_t *product_props = json_object();
    json_object_set_new(product_props, "sku", make_string_schema(1, 64));
    json_object_set_new(product_props, "name", make_string_schema(1, 128));
    json_object_set_new(product_props, "unit", make_string_schema(0, 16));
    json_object_set_new(product_schema, "properties", product_props);
    json_t *product_required = json_array();
    json_array_append_new(product_required, json_string("sku"));
    json_array_append_new(product_required, json_string("name"));
    json_object_set_new(product_schema, "required", product_required);
    json_object_set_new(schemas, "CreateProductRequest", product_schema);

    json_t *inbound_schema = json_object();
    json_object_set_new(inbound_schema, "type", json_string("object"));
    json_t *inbound_props = json_object();
    json_object_set_new(inbound_props, "sku", make_string_schema(1, 64));
    json_object_set_new(inbound_props, "quantity", make_integer_schema(1, 1000000));
    json_object_set_new(inbound_props, "unit_cost_cents",
                        make_integer_schema(0, 100000000));
    json_object_set_new(inbound_props, "note", make_string_schema(0, 256));
    json_object_set_new(inbound_schema, "properties", inbound_props);
    json_t *inbound_required = json_array();
    json_array_append_new(inbound_required, json_string("sku"));
    json_array_append_new(inbound_required, json_string("quantity"));
    json_array_append_new(inbound_required, json_string("unit_cost_cents"));
    json_object_set_new(inbound_schema, "required", inbound_required);
    json_object_set_new(schemas, "InboundRequest", inbound_schema);

    json_t *sales_schema = json_object();
    json_object_set_new(sales_schema, "type", json_string("object"));
    json_t *sales_props = json_object();
    json_object_set_new(sales_props, "sku", make_string_schema(1, 64));
    json_object_set_new(sales_props, "quantity", make_integer_schema(1, 1000000));
    json_object_set_new(sales_props, "unit_price_cents",
                        make_integer_schema(0, 100000000));
    json_object_set_new(sales_props, "note", make_string_schema(0, 256));
    json_object_set_new(sales_schema, "properties", sales_props);
    json_t *sales_required = json_array();
    json_array_append_new(sales_required, json_string("sku"));
    json_array_append_new(sales_required, json_string("quantity"));
    json_array_append_new(sales_required, json_string("unit_price_cents"));
    json_object_set_new(sales_schema, "required", sales_required);
    json_object_set_new(schemas, "SalesRequest", sales_schema);

    return schemas;
}

static void add_route_specific_parameters(const ApiRoute *route, json_t *operation) {
    if (strcmp(route->method, MHD_HTTP_METHOD_GET) != 0 ||
        strcmp(route->path, "/api/v1/movements") != 0) {
        return;
    }

    json_t *parameters = json_array();

    json_t *type_param = json_object();
    json_object_set_new(type_param, "name", json_string("type"));
    json_object_set_new(type_param, "in", json_string("query"));
    json_object_set_new(type_param, "description",
                        json_string("流水类型过滤，可选 IN/OUT"));
    json_t *type_schema = json_object();
    json_object_set_new(type_schema, "type", json_string("string"));
    json_t *type_enum = json_array();
    json_array_append_new(type_enum, json_string("IN"));
    json_array_append_new(type_enum, json_string("OUT"));
    json_object_set_new(type_schema, "enum", type_enum);
    json_object_set_new(type_param, "schema", type_schema);
    json_array_append_new(parameters, type_param);

    json_t *limit_param = json_object();
    json_object_set_new(limit_param, "name", json_string("limit"));
    json_object_set_new(limit_param, "in", json_string("query"));
    json_object_set_new(limit_param, "description",
                        json_string("返回条数，默认50，范围1-200"));
    json_t *limit_schema = json_object();
    json_object_set_new(limit_schema, "type", json_string("integer"));
    json_object_set_new(limit_schema, "minimum", json_integer(1));
    json_object_set_new(limit_schema, "maximum", json_integer(200));
    json_object_set_new(limit_schema, "default", json_integer(50));
    json_object_set_new(limit_param, "schema", limit_schema);
    json_array_append_new(parameters, limit_param);

    json_object_set_new(operation, "parameters", parameters);
}

static void add_openapi_operation(json_t *paths, const ApiRoute *route) {
    const char *openapi_method = method_to_openapi_key(route->method);
    if (openapi_method == NULL) {
        return;
    }

    json_t *path_item = json_object_get(paths, route->path);
    if (path_item == NULL) {
        path_item = json_object();
        json_object_set_new(paths, route->path, path_item);
    }

    json_t *operation = json_object();
    char operation_id[256];
    build_operation_id(route, operation_id, sizeof(operation_id));
    json_object_set_new(operation, "operationId", json_string(operation_id));
    json_object_set_new(operation, "summary", json_string(route->summary));
    json_object_set_new(operation, "description", json_string(route->description));

    json_t *tags = json_array();
    json_array_append_new(tags, json_string(route->tag));
    json_object_set_new(operation, "tags", tags);

    if (route->requires_auth) {
        json_t *security = json_array();
        json_t *bearer_req = json_object();
        json_object_set_new(bearer_req, "bearerAuth", json_array());
        json_array_append_new(security, bearer_req);
        json_object_set_new(operation, "security", security);
    }

    if (route->has_request_body) {
        json_t *request_body = json_object();
        json_object_set_new(request_body, "required", json_true());
        json_t *content = json_object();
        json_t *app_json = json_object();
        const char *schema_name = request_schema_name_for_route(route);
        json_t *schema = schema_name == NULL ? build_generic_success_schema()
                                             : schema_ref(schema_name);
        json_object_set_new(app_json, "schema", schema);
        json_t *example = request_example_for_route(route);
        if (example != NULL) {
            json_object_set_new(app_json, "example", example);
        }
        json_object_set_new(content, "application/json", app_json);
        json_object_set_new(request_body, "content", content);
        json_object_set_new(operation, "requestBody", request_body);
    }

    add_route_specific_parameters(route, operation);

    json_t *responses = json_object();
    json_t *ok = json_object();
    json_object_set_new(ok, "description", json_string("成功"));

    if (strcmp(route->path, "/docs") == 0 || strcmp(route->path, "/") == 0) {
        json_t *content = json_object();
        json_t *html = json_object();
        json_t *schema = json_object();
        json_object_set_new(schema, "type", json_string("string"));
        json_object_set_new(html, "schema", schema);
        json_object_set_new(content, "text/html", html);
        json_object_set_new(ok, "content", content);
    } else {
        json_t *content = json_object();
        json_t *app_json = json_object();
        json_object_set_new(app_json, "schema", build_generic_success_schema());
        json_object_set_new(content, "application/json", app_json);
        json_object_set_new(ok, "content", content);
    }
    json_object_set_new(responses, "200", ok);

    if (route->has_request_body) {
        json_t *bad = json_object();
        json_object_set_new(bad, "description", json_string("请求参数错误"));
        json_object_set_new(responses, "400", bad);
    }
    if (route->requires_auth) {
        json_t *unauth = json_object();
        json_object_set_new(unauth, "description", json_string("未认证或令牌无效"));
        json_object_set_new(responses, "401", unauth);
    }
    json_object_set_new(operation, "responses", responses);

    json_object_set_new(path_item, openapi_method, operation);
}

static json_t *build_openapi_document(const ApiRoute *routes, size_t route_count) {
    json_t *root = json_object();
    json_object_set_new(root, "openapi", json_string("3.1.0"));

    json_t *info = json_object();
    json_object_set_new(info, "title",
                        json_string("园区矿泉水自助零售管理系统 API"));
    json_object_set_new(info, "version", json_string("1.0.0"));
    json_object_set_new(
        info, "description",
        json_string("代码驱动自动生成：路由变化后 OpenAPI 与 Swagger UI 同步更新。"));
    json_object_set_new(root, "info", info);

    json_t *servers = json_array();
    json_t *server = json_object();
    json_object_set_new(server, "url", json_string("/"));
    json_object_set_new(server, "description", json_string("Current server"));
    json_array_append_new(servers, server);
    json_object_set_new(root, "servers", servers);

    json_t *tags = json_array();
    const char *tag_names[] = {"System", "Auth", "Product", "Inventory"};
    for (size_t i = 0; i < sizeof(tag_names) / sizeof(tag_names[0]); ++i) {
        json_t *tag = json_object();
        json_object_set_new(tag, "name", json_string(tag_names[i]));
        json_array_append_new(tags, tag);
    }
    json_object_set_new(root, "tags", tags);

    json_t *paths = json_object();
    for (size_t i = 0; i < route_count; ++i) {
        if (routes[i].include_in_openapi) {
            add_openapi_operation(paths, &routes[i]);
        }
    }
    json_object_set_new(root, "paths", paths);

    json_t *components = json_object();
    json_t *security_schemes = json_object();
    json_t *bearer_auth = json_object();
    json_object_set_new(bearer_auth, "type", json_string("http"));
    json_object_set_new(bearer_auth, "scheme", json_string("bearer"));
    json_object_set_new(bearer_auth, "bearerFormat", json_string("token"));
    json_object_set_new(security_schemes, "bearerAuth", bearer_auth);
    json_object_set_new(components, "securitySchemes", security_schemes);
    json_object_set_new(components, "schemas", build_request_schemas());
    json_object_set_new(root, "components", components);

    return root;
}

enum MHD_Result docs_send_openapi(struct MHD_Connection *connection,
                                  const ApiRoute *routes,
                                  size_t route_count) {
    json_t *doc = build_openapi_document(routes, route_count);
    return send_json_response(connection, MHD_HTTP_OK, doc);
}

enum MHD_Result docs_send_swagger_ui(struct MHD_Connection *connection) {
    static const char *html =
        "<!doctype html>"
        "<html><head><meta charset=\"utf-8\"/>"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
        "<title>Swagger UI</title>"
        "<link rel=\"stylesheet\" "
        "href=\"https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css\"/>"
        "<style>body{margin:0;background:#fafafa;}#swagger-ui{max-width:1200px;"
        "margin:0 auto;}</style>"
        "</head><body><div id=\"swagger-ui\"></div>"
        "<script "
        "src=\"https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js\">"
        "</script>"
        "<script>window.onload=function(){SwaggerUIBundle({url:'/api/v1/openapi.json',"
        "dom_id:'#swagger-ui',deepLinking:true,presets:[SwaggerUIBundle.presets.apis],"
        "layout:'BaseLayout'});};</script>"
        "</body></html>";

    return send_text_response(connection, MHD_HTTP_OK, "text/html; charset=utf-8",
                              html);
}

enum MHD_Result docs_send_home(struct MHD_Connection *connection) {
    static const char *html =
        "<!doctype html>"
        "<html><head><meta charset=\"utf-8\"/>"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
        "<title>jinxiaocun backend</title>"
        "<style>body{font-family:Arial,sans-serif;padding:32px;line-height:1.6;"
        "max-width:760px;margin:0 auto;}a{color:#0b57d0;text-decoration:none;}a:hover{"
        "text-decoration:underline;}code{background:#f3f3f3;padding:2px 6px;border-radius:"
        "4px;}</style></head><body>"
        "<h1>园区矿泉水自助零售管理系统后端</h1>"
        "<p>服务已启动。可访问以下入口：</p>"
        "<ul>"
        "<li>Swagger UI: <a href=\"/docs\">/docs</a></li>"
        "<li>OpenAPI: <a href=\"/api/v1/openapi.json\">/api/v1/openapi.json</a></li>"
        "<li>健康检查: <a href=\"/api/v1/health\">/api/v1/health</a></li>"
        "</ul>"
        "<p>业务接口前缀：<code>/api/v1</code></p>"
        "</body></html>";
    return send_text_response(connection, MHD_HTTP_OK, "text/html; charset=utf-8",
                              html);
}
