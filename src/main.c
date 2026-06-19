#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <microhttpd.h>

#include "docs/docs_ui.h"
#include "http/response.h"
#include "http/routes_meta.h"

#define DEFAULT_PORT 8080
#define DEFAULT_DB_PATH "./data/app.db"
#define DEFAULT_KEY_FILE "./data/user_key.b64"
#define DEFAULT_SESSION_TTL_HOURS 12
#define DEFAULT_ADMIN_USERNAME "admin"
#define DEFAULT_ADMIN_PASSWORD "Admin@123456"

#define MAX_BODY_SIZE (1024 * 1024)
#define RAW_TOKEN_BYTES 32
#define TOKEN_HASH_HEX_LEN (crypto_generichash_BYTES * 2)

typedef struct {
    int port;
    int session_ttl_hours;
    const char *db_path;
    const char *key_file;
} ServerConfig;

typedef struct {
    int user_id;
    char username[128];
    char role[32];
} AuthUser;

static ServerConfig g_cfg;
static sqlite3 *g_db = NULL;
static pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned char g_user_key[crypto_secretbox_KEYBYTES];
static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static char *dup_cstr(const char *src) {
    if (src == NULL) {
        return NULL;
    }
    const size_t len = strlen(src);
    char *dst = (char *)malloc(len + 1);
    if (dst == NULL) {
        return NULL;
    }
    memcpy(dst, src, len + 1);
    return dst;
}

static int env_to_int(const char *name, int fallback) {
    const char *v = getenv(name);
    if (v == NULL || *v == '\0') {
        return fallback;
    }

    char *end = NULL;
    errno = 0;
    long n = strtol(v, &end, 10);
    if (errno != 0 || end == v || *end != '\0' || n <= 0 || n > INT_MAX) {
        return fallback;
    }
    return (int)n;
}

static void bytes_to_hex(const unsigned char *in, size_t in_len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; ++i) {
        out[i * 2] = hex[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
}

static int hash_token(const char *token, char out_hex[TOKEN_HASH_HEX_LEN + 1]) {
    unsigned char hash[crypto_generichash_BYTES];
    if (crypto_generichash(hash, sizeof(hash), (const unsigned char *)token,
                           strlen(token), NULL, 0) != 0) {
        return -1;
    }
    bytes_to_hex(hash, sizeof(hash), out_hex);
    return 0;
}

static int generate_access_token(char *out, size_t out_size) {
    const size_t needed =
        sodium_base64_encoded_len(RAW_TOKEN_BYTES,
                                  sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (out_size < needed) {
        return -1;
    }

    unsigned char raw[RAW_TOKEN_BYTES];
    randombytes_buf(raw, sizeof(raw));
    sodium_bin2base64(out, out_size, raw, sizeof(raw),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return 0;
}

static time_t now_epoch(void) { return time(NULL); }

static int ensure_parent_dir(const char *path) {
    if (path == NULL) {
        return -1;
    }

    char *copy = dup_cstr(path);
    if (copy == NULL) {
        return -1;
    }

    for (char *p = copy + 1; *p != '\0'; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
                free(copy);
                return -1;
            }
            *p = '/';
        }
    }

    free(copy);
    return 0;
}

static int load_or_create_key(void) {
    const char *env_key = getenv("USER_DATA_KEY_B64");
    if (env_key != NULL && *env_key != '\0') {
        size_t bin_len = 0;
        if (sodium_base642bin(g_user_key, sizeof(g_user_key), env_key,
                              strlen(env_key), NULL, &bin_len, NULL,
                              sodium_base64_VARIANT_ORIGINAL) == 0 &&
            bin_len == sizeof(g_user_key)) {
            return 0;
        }
        fprintf(stderr,
                "[WARN] USER_DATA_KEY_B64 无效，将尝试从密钥文件加载。\n");
    }

    FILE *f = fopen(g_cfg.key_file, "rb");
    if (f != NULL) {
        char line[256];
        if (fgets(line, sizeof(line), f) != NULL) {
            line[strcspn(line, "\r\n")] = '\0';
            size_t bin_len = 0;
            if (sodium_base642bin(g_user_key, sizeof(g_user_key), line,
                                  strlen(line), NULL, &bin_len, NULL,
                                  sodium_base64_VARIANT_ORIGINAL) == 0 &&
                bin_len == sizeof(g_user_key)) {
                fclose(f);
                return 0;
            }
        }
        fclose(f);
    }

    randombytes_buf(g_user_key, sizeof(g_user_key));
    const size_t enc_len = sodium_base64_encoded_len(
        sizeof(g_user_key), sodium_base64_VARIANT_ORIGINAL);
    char *b64 = (char *)malloc(enc_len + 2);
    if (b64 == NULL) {
        return -1;
    }

    sodium_bin2base64(b64, enc_len + 2, g_user_key, sizeof(g_user_key),
                      sodium_base64_VARIANT_ORIGINAL);

    if (ensure_parent_dir(g_cfg.key_file) != 0) {
        free(b64);
        return -1;
    }

    f = fopen(g_cfg.key_file, "wb");
    if (f == NULL) {
        free(b64);
        return -1;
    }

    fprintf(f, "%s\n", b64);
    fclose(f);
    chmod(g_cfg.key_file, 0600);
    free(b64);

    fprintf(stdout,
            "[INFO] 已自动生成新的用户字段加密密钥: %s\n"
            "[INFO] 请妥善备份该文件，丢失后将无法解密已有用户信息。\n",
            g_cfg.key_file);

    return 0;
}

static int encrypt_text(const char *plain, char **out_b64) {
    if (plain == NULL) {
        plain = "";
    }

    const size_t plain_len = strlen(plain);
    const size_t boxed_len = crypto_secretbox_NONCEBYTES +
                             crypto_secretbox_MACBYTES + plain_len;

    unsigned char *boxed = (unsigned char *)malloc(boxed_len);
    if (boxed == NULL) {
        return -1;
    }

    unsigned char *nonce = boxed;
    unsigned char *cipher = boxed + crypto_secretbox_NONCEBYTES;
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_easy(cipher, (const unsigned char *)plain, plain_len,
                              nonce, g_user_key) != 0) {
        free(boxed);
        return -1;
    }

    const size_t enc_len =
        sodium_base64_encoded_len(boxed_len, sodium_base64_VARIANT_ORIGINAL);
    char *b64 = (char *)malloc(enc_len + 1);
    if (b64 == NULL) {
        free(boxed);
        return -1;
    }

    sodium_bin2base64(b64, enc_len + 1, boxed, boxed_len,
                      sodium_base64_VARIANT_ORIGINAL);

    free(boxed);
    *out_b64 = b64;
    return 0;
}

static int decrypt_text(const char *b64, char **out_plain) {
    if (b64 == NULL || *b64 == '\0') {
        *out_plain = dup_cstr("");
        return *out_plain == NULL ? -1 : 0;
    }

    const size_t max_len = strlen(b64) * 3 / 4 + 4;
    unsigned char *boxed = (unsigned char *)malloc(max_len);
    if (boxed == NULL) {
        return -1;
    }

    size_t boxed_len = 0;
    if (sodium_base642bin(boxed, max_len, b64, strlen(b64), NULL, &boxed_len,
                          NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
        free(boxed);
        return -1;
    }

    if (boxed_len <
        crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        free(boxed);
        return -1;
    }

    const unsigned char *nonce = boxed;
    const unsigned char *cipher = boxed + crypto_secretbox_NONCEBYTES;
    const size_t cipher_len = boxed_len - crypto_secretbox_NONCEBYTES;
    const size_t plain_len = cipher_len - crypto_secretbox_MACBYTES;

    unsigned char *plain = (unsigned char *)malloc(plain_len + 1);
    if (plain == NULL) {
        free(boxed);
        return -1;
    }

    if (crypto_secretbox_open_easy(plain, cipher, cipher_len, nonce,
                                   g_user_key) != 0) {
        free(boxed);
        free(plain);
        return -1;
    }

    plain[plain_len] = '\0';
    free(boxed);
    *out_plain = (char *)plain;
    return 0;
}

static int db_exec(const char *sql) {
    char *err = NULL;
    const int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        if (err != NULL) {
            fprintf(stderr, "[DB] SQL执行失败: %s\n", err);
            sqlite3_free(err);
        }
        return -1;
    }
    return 0;
}

static int db_init(void) {
    if (ensure_parent_dir(g_cfg.db_path) != 0) {
        fprintf(stderr, "[DB] 无法创建数据库目录: %s\n", g_cfg.db_path);
        return -1;
    }

    if (sqlite3_open_v2(g_cfg.db_path, &g_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        fprintf(stderr, "[DB] 打开数据库失败: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_busy_timeout(g_db, 5000);

    const char *schema_sql =
        "PRAGMA foreign_keys = ON;"
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = NORMAL;"

        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT NOT NULL UNIQUE,"
        "  password_hash TEXT NOT NULL,"
        "  role TEXT NOT NULL CHECK(role IN ('admin','staff')),"
        "  full_name_enc TEXT,"
        "  email_enc TEXT,"
        "  phone_enc TEXT,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"

        "CREATE TABLE IF NOT EXISTS sessions ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  user_id INTEGER NOT NULL,"
        "  token_hash TEXT NOT NULL UNIQUE,"
        "  expires_at INTEGER NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE"
        ");"

        "CREATE TABLE IF NOT EXISTS products ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  sku TEXT NOT NULL UNIQUE,"
        "  name TEXT NOT NULL,"
        "  unit TEXT NOT NULL DEFAULT '瓶',"
        "  stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK(stock_quantity >= 0),"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"

        "CREATE TABLE IF NOT EXISTS stock_movements ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  product_id INTEGER NOT NULL,"
        "  movement_type TEXT NOT NULL CHECK(movement_type IN ('IN','OUT')),"
        "  quantity INTEGER NOT NULL CHECK(quantity > 0),"
        "  unit_price_cents INTEGER NOT NULL CHECK(unit_price_cents >= 0),"
        "  note TEXT,"
        "  operator_user_id INTEGER NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(product_id) REFERENCES products(id),"
        "  FOREIGN KEY(operator_user_id) REFERENCES users(id)"
        ");"

        "CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);"
        "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);"
        "CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);"
        "CREATE INDEX IF NOT EXISTS idx_movements_product_id ON "
        "stock_movements(product_id);"
        "CREATE INDEX IF NOT EXISTS idx_movements_created_at ON "
        "stock_movements(created_at);"

        "CREATE TABLE IF NOT EXISTS orders ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  order_no TEXT NOT NULL UNIQUE,"
        "  total_amount_cents INTEGER NOT NULL CHECK(total_amount_cents >= 0),"
        "  paid_amount_cents INTEGER NOT NULL DEFAULT 0 CHECK(paid_amount_cents >= 0),"
        "  change_amount_cents INTEGER NOT NULL DEFAULT 0 CHECK(change_amount_cents >= 0),"
        "  status TEXT NOT NULL DEFAULT 'PENDING' "
        "    CHECK(status IN ('PENDING','PAID','CHANGE_PENDING','COMPLETED','CHANGE_FAILED','CANCELLED')),"
        "  payment_method TEXT CHECK(payment_method IN ('COIN','BILL','QR_CODE','MIXED')),"
        "  change_failure_reason TEXT "
        "    CHECK(change_failure_reason IN ('INSUFFICIENT_CHANGE','COIN_JAM','USER_CANCELLED','MANUAL_REFUND',NULL)),"
        "  operator_user_id INTEGER,"
        "  note TEXT,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(operator_user_id) REFERENCES users(id)"
        ");"

        "CREATE TABLE IF NOT EXISTS order_items ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  order_id INTEGER NOT NULL,"
        "  product_id INTEGER NOT NULL,"
        "  product_name TEXT NOT NULL,"
        "  quantity INTEGER NOT NULL CHECK(quantity > 0),"
        "  unit_price_cents INTEGER NOT NULL CHECK(unit_price_cents >= 0),"
        "  subtotal_cents INTEGER NOT NULL CHECK(subtotal_cents >= 0),"
        "  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,"
        "  FOREIGN KEY(product_id) REFERENCES products(id)"
        ");"

        "CREATE TABLE IF NOT EXISTS payment_transactions ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  order_id INTEGER,"
        "  txn_no TEXT NOT NULL UNIQUE,"
        "  payment_method TEXT NOT NULL "
        "    CHECK(payment_method IN ('COIN','BILL','QR_CODE')),"
        "  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),"
        "  denomination TEXT,"
        "  status TEXT NOT NULL DEFAULT 'SUCCESS' "
        "    CHECK(status IN ('PENDING','SUCCESS','FAILED','REJECTED')),"
        "  failure_reason TEXT,"
        "  external_ref TEXT,"
        "  operator_user_id INTEGER,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(order_id) REFERENCES orders(id),"
        "  FOREIGN KEY(operator_user_id) REFERENCES users(id)"
        ");"

        "CREATE TABLE IF NOT EXISTS change_transactions ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  order_id INTEGER NOT NULL,"
        "  txn_no TEXT NOT NULL UNIQUE,"
        "  request_amount_cents INTEGER NOT NULL CHECK(request_amount_cents >= 0),"
        "  actual_amount_cents INTEGER NOT NULL DEFAULT 0 CHECK(actual_amount_cents >= 0),"
        "  status TEXT NOT NULL DEFAULT 'PENDING' "
        "    CHECK(status IN ('PENDING','SUCCESS','FAILED','PARTIAL','CANCELLED','MANUAL_REFUND')),"
        "  failure_reason TEXT "
        "    CHECK(failure_reason IN ('INSUFFICIENT_CHANGE','COIN_JAM','USER_CANCELLED','MANUAL_REFUND',NULL)),"
        "  denomination_breakdown TEXT,"
        "  operator_user_id INTEGER,"
        "  note TEXT,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(order_id) REFERENCES orders(id),"
        "  FOREIGN KEY(operator_user_id) REFERENCES users(id)"
        ");"

        "CREATE TABLE IF NOT EXISTS cash_drawer ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  denomination TEXT NOT NULL UNIQUE,"
        "  denomination_value_cents INTEGER NOT NULL CHECK(denomination_value_cents > 0),"
        "  quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity >= 0),"
        "  total_value_cents INTEGER NOT NULL DEFAULT 0 CHECK(total_value_cents >= 0),"
        "  coin_type TEXT NOT NULL CHECK(coin_type IN ('COIN','BILL')),"
        "  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"

        "CREATE TABLE IF NOT EXISTS cash_drawer_movements ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  denomination TEXT NOT NULL,"
        "  movement_type TEXT NOT NULL "
        "    CHECK(movement_type IN ('REFILL','DISPENSE','RECOUNT_ADJUST','MANUAL_ADD','MANUAL_REMOVE')),"
        "  quantity_before INTEGER NOT NULL,"
        "  quantity_change INTEGER NOT NULL,"
        "  quantity_after INTEGER NOT NULL,"
        "  value_change_cents INTEGER NOT NULL,"
        "  order_id INTEGER,"
        "  change_txn_id INTEGER,"
        "  operator_user_id INTEGER,"
        "  note TEXT,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(order_id) REFERENCES orders(id),"
        "  FOREIGN KEY(change_txn_id) REFERENCES change_transactions(id),"
        "  FOREIGN KEY(operator_user_id) REFERENCES users(id)"
        ");"

        "CREATE TABLE IF NOT EXISTS shift_settlements ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  shift_no TEXT NOT NULL UNIQUE,"
        "  operator_user_id INTEGER NOT NULL,"
        "  start_time TEXT NOT NULL,"
        "  end_time TEXT NOT NULL,"
        "  expected_cash_cents INTEGER NOT NULL DEFAULT 0,"
        "  actual_cash_cents INTEGER NOT NULL DEFAULT 0,"
        "  difference_cents INTEGER NOT NULL DEFAULT 0,"
        "  total_sales_cents INTEGER NOT NULL DEFAULT 0,"
        "  total_change_cents INTEGER NOT NULL DEFAULT 0,"
        "  total_qr_sales_cents INTEGER NOT NULL DEFAULT 0,"
        "  order_count INTEGER NOT NULL DEFAULT 0,"
        "  change_failure_count INTEGER NOT NULL DEFAULT 0,"
        "  status TEXT NOT NULL DEFAULT 'COMPLETED' "
        "    CHECK(status IN ('IN_PROGRESS','COMPLETED','REVIEWED')),"
        "  note TEXT,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(operator_user_id) REFERENCES users(id)"
        ");"

        "CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);"
        "CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at);"
        "CREATE INDEX IF NOT EXISTS idx_orders_operator ON orders(operator_user_id);"
        "CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);"
        "CREATE INDEX IF NOT EXISTS idx_payment_txn_order_id ON payment_transactions(order_id);"
        "CREATE INDEX IF NOT EXISTS idx_payment_txn_method ON payment_transactions(payment_method);"
        "CREATE INDEX IF NOT EXISTS idx_payment_txn_created_at ON payment_transactions(created_at);"
        "CREATE INDEX IF NOT EXISTS idx_change_txn_order_id ON change_transactions(order_id);"
        "CREATE INDEX IF NOT EXISTS idx_change_txn_status ON change_transactions(status);"
        "CREATE INDEX IF NOT EXISTS idx_change_txn_created_at ON change_transactions(created_at);"
        "CREATE INDEX IF NOT EXISTS idx_cash_drawer_movements_denom ON cash_drawer_movements(denomination);"
        "CREATE INDEX IF NOT EXISTS idx_cash_drawer_movements_created_at ON cash_drawer_movements(created_at);"
        "CREATE INDEX IF NOT EXISTS idx_shift_settlements_operator ON shift_settlements(operator_user_id);"
        "CREATE INDEX IF NOT EXISTS idx_shift_settlements_created_at ON shift_settlements(created_at);"

        "INSERT OR IGNORE INTO products (sku, name, unit, stock_quantity) VALUES "
        "('SEED-WATER-550', '系统示例矿泉水550ml', '瓶', 50);"

        "INSERT OR IGNORE INTO cash_drawer (denomination, denomination_value_cents, quantity, total_value_cents, coin_type) VALUES "
        "('0.01', 1, 100, 100, 'COIN'),"
        "('0.05', 5, 100, 500, 'COIN'),"
        "('0.10', 10, 100, 1000, 'COIN'),"
        "('0.50', 50, 100, 5000, 'COIN'),"
        "('1.00', 100, 100, 10000, 'COIN'),"
        "('5.00', 500, 20, 10000, 'BILL'),"
        "('10.00', 1000, 20, 20000, 'BILL'),"
        "('20.00', 2000, 10, 20000, 'BILL'),"
        "('50.00', 5000, 5, 25000, 'BILL'),"
        "('100.00', 10000, 5, 50000, 'BILL');";

    if (db_exec(schema_sql) != 0) {
        return -1;
    }

    return 0;
}

static int append_body(ConnectionInfo *ci, const char *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    if (ci->body_size + size > MAX_BODY_SIZE) {
        return -1;
    }

    char *new_buf = (char *)realloc(ci->body, ci->body_size + size + 1);
    if (new_buf == NULL) {
        return -1;
    }

    ci->body = new_buf;
    memcpy(ci->body + ci->body_size, data, size);
    ci->body_size += size;
    ci->body[ci->body_size] = '\0';
    return 0;
}

static int is_method_with_body(const char *method) {
    return strcmp(method, MHD_HTTP_METHOD_POST) == 0 ||
           strcmp(method, MHD_HTTP_METHOD_PUT) == 0 ||
           strcmp(method, MHD_HTTP_METHOD_PATCH) == 0;
}

static int parse_json_body(ConnectionInfo *ci, json_t **out,
                           char err_msg[256]) {
    if (ci->body_size == 0) {
        snprintf(err_msg, 256, "请求体不能为空");
        return -1;
    }

    json_error_t jerr;
    json_t *obj = json_loadb(ci->body, ci->body_size, 0, &jerr);
    if (obj == NULL || !json_is_object(obj)) {
        if (obj != NULL) {
            json_decref(obj);
        }
        snprintf(err_msg, 256, "JSON 格式错误: %s", jerr.text);
        return -1;
    }

    *out = obj;
    return 0;
}

static const char *safe_col_text(sqlite3_stmt *stmt, int col) {
    const unsigned char *text = sqlite3_column_text(stmt, col);
    return text == NULL ? "" : (const char *)text;
}

static int db_user_count(int *count_out) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM users;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    *count_out = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return 0;
}

static int ensure_default_admin_user(void) {
    int user_count = 0;
    if (db_user_count(&user_count) != 0) {
        fprintf(stderr, "[DB] 查询用户数量失败，无法初始化默认管理员\n");
        return -1;
    }
    if (user_count > 0) {
        return 0;
    }

    const char *admin_username = getenv("DEFAULT_ADMIN_USERNAME");
    if (admin_username == NULL || *admin_username == '\0') {
        admin_username = DEFAULT_ADMIN_USERNAME;
    }

    const char *admin_password = getenv("DEFAULT_ADMIN_PASSWORD");
    if (admin_password == NULL || *admin_password == '\0') {
        admin_password = DEFAULT_ADMIN_PASSWORD;
    }

    char password_hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(password_hash, admin_password, strlen(admin_password),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        fprintf(stderr, "[SECURITY] 默认管理员密码哈希失败\n");
        return -1;
    }

    char *full_name_enc = NULL;
    char *email_enc = NULL;
    char *phone_enc = NULL;
    if (encrypt_text("系统管理员", &full_name_enc) != 0 ||
        encrypt_text("admin@local", &email_enc) != 0 ||
        encrypt_text("", &phone_enc) != 0) {
        free(full_name_enc);
        free(email_enc);
        free(phone_enc);
        fprintf(stderr, "[SECURITY] 默认管理员信息加密失败\n");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO users (username, password_hash, role, full_name_enc, "
        "email_enc, phone_enc) VALUES (?, ?, 'admin', ?, ?, ?);";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        free(full_name_enc);
        free(email_enc);
        free(phone_enc);
        fprintf(stderr, "[DB] 默认管理员插入预编译失败\n");
        return -1;
    }

    sqlite3_bind_text(stmt, 1, admin_username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, full_name_enc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, email_enc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, phone_enc, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(full_name_enc);
    free(email_enc);
    free(phone_enc);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[DB] 默认管理员创建失败\n");
        return -1;
    }

    fprintf(stdout,
            "[INFO] 已初始化默认管理员账号: %s\n"
            "[INFO] 默认管理员密码可通过环境变量 DEFAULT_ADMIN_PASSWORD 覆盖\n",
            admin_username);
    return 0;
}

static int ensure_seed_stock_movement_consistency(void) {
    sqlite3_stmt *stmt = NULL;
    int admin_user_id = 0;
    int rc = sqlite3_prepare_v2(
        g_db, "SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1;", -1,
        &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DB] 查询管理员失败，无法修复种子库存流水\n");
        return -1;
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        admin_user_id = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    if (admin_user_id <= 0) {
        return 0;
    }

    int product_id = 0;
    int stock_quantity = 0;
    rc = sqlite3_prepare_v2(
        g_db, "SELECT id, stock_quantity FROM products WHERE sku=? LIMIT 1;", -1,
        &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DB] 查询种子商品失败，无法修复种子库存流水\n");
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "SEED-WATER-550", -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        product_id = sqlite3_column_int(stmt, 0);
        stock_quantity = sqlite3_column_int(stmt, 1);
    }
    sqlite3_finalize(stmt);
    if (product_id <= 0) {
        return 0;
    }

    int in_total = 0;
    int out_total = 0;
    rc = sqlite3_prepare_v2(
        g_db,
        "SELECT "
        "COALESCE(SUM(CASE WHEN movement_type='IN' THEN quantity ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN movement_type='OUT' THEN quantity ELSE 0 END), 0) "
        "FROM stock_movements WHERE product_id=?;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DB] 查询种子商品流水失败，无法修复种子库存流水\n");
        return -1;
    }
    sqlite3_bind_int(stmt, 1, product_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "[DB] 读取种子商品流水失败，无法修复种子库存流水\n");
        return -1;
    }
    in_total = sqlite3_column_int(stmt, 0);
    out_total = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);

    if (in_total > 0) {
        return 0;
    }

    int inferred_initial_in = stock_quantity + out_total;
    if (inferred_initial_in <= 0) {
        return 0;
    }

    rc = sqlite3_prepare_v2(
        g_db,
        "INSERT INTO stock_movements "
        "(product_id, movement_type, quantity, unit_price_cents, note, "
        "operator_user_id) "
        "VALUES (?, 'IN', ?, 0, '系统初始化库存补录', ?);",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DB] 补录种子库存流水预编译失败\n");
        return -1;
    }
    sqlite3_bind_int(stmt, 1, product_id);
    sqlite3_bind_int(stmt, 2, inferred_initial_in);
    sqlite3_bind_int(stmt, 3, admin_user_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[DB] 补录种子库存流水失败\n");
        return -1;
    }

    fprintf(stdout, "[INFO] 已修复种子商品库存流水: sku=SEED-WATER-550, in=%d\n",
            inferred_initial_in);
    return 0;
}

static int authenticate_request(struct MHD_Connection *connection,
                                AuthUser *out_user,
                                char token_hash_hex[TOKEN_HASH_HEX_LEN + 1]) {
    const char *auth_header =
        MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
    if (auth_header == NULL || strncmp(auth_header, "Bearer ", 7) != 0) {
        return 0;
    }

    const char *token = auth_header + 7;
    if (*token == '\0') {
        return 0;
    }

    if (hash_token(token, token_hash_hex) != 0) {
        return 0;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT u.id, u.username, u.role "
        "FROM sessions s "
        "JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ? "
        "LIMIT 1;";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, token_hash_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now_epoch());

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    out_user->user_id = sqlite3_column_int(stmt, 0);
    snprintf(out_user->username, sizeof(out_user->username), "%s",
             safe_col_text(stmt, 1));
    snprintf(out_user->role, sizeof(out_user->role), "%s", safe_col_text(stmt, 2));

    sqlite3_finalize(stmt);
    return 1;
}

static int is_admin_role(const AuthUser *user) {
    return strcmp(user->role, "admin") == 0;
}

static int parse_int_field(json_t *obj, const char *key, int min, int max,
                           int *out) {
    json_t *v = json_object_get(obj, key);
    if (!json_is_integer(v)) {
        return -1;
    }

    json_int_t n = json_integer_value(v);
    if (n < min || n > max) {
        return -1;
    }

    *out = (int)n;
    return 0;
}

static int require_string_field(json_t *obj, const char *key, size_t max_len,
                                const char **out) {
    json_t *v = json_object_get(obj, key);
    if (!json_is_string(v)) {
        return -1;
    }

    const char *s = json_string_value(v);
    if (s == NULL) {
        return -1;
    }

    size_t len = strlen(s);
    if (len == 0 || len > max_len) {
        return -1;
    }

    *out = s;
    return 0;
}

static const char *optional_string_field(json_t *obj, const char *key,
                                         size_t max_len) {
    json_t *v = json_object_get(obj, key);
    if (v == NULL || json_is_null(v)) {
        return "";
    }
    if (!json_is_string(v)) {
        return NULL;
    }

    const char *s = json_string_value(v);
    if (s == NULL || strlen(s) > max_len) {
        return NULL;
    }
    return s;
}

static enum MHD_Result handle_health(struct MHD_Connection *connection) {
    json_t *data = json_object();
    json_object_set_new(data, "service", json_string("jinxiaocun-backend-c"));
    json_object_set_new(data, "status", json_string("ok"));
    json_object_set_new(data, "timestamp", json_integer((json_int_t)now_epoch()));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_register(struct MHD_Connection *connection,
                                       ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *username = NULL;
    const char *password = NULL;
    if (require_string_field(body, "username", 64, &username) != 0 ||
        require_string_field(body, "password", 128, &password) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "username/password 必填，且长度必须合法");
    }

    const char *full_name = optional_string_field(body, "full_name", 128);
    const char *email = optional_string_field(body, "email", 128);
    const char *phone = optional_string_field(body, "phone", 64);
    if (full_name == NULL || email == NULL || phone == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "full_name/email/phone 必须是字符串且长度合法");
    }

    const char *role_input = optional_string_field(body, "role", 16);
    if (role_input == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "role 必须是字符串");
    }

    pthread_mutex_lock(&g_db_mutex);

    int user_count = 0;
    if (db_user_count(&user_count) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询用户数量失败");
    }

    AuthUser creator;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    const int first_user = (user_count == 0);
    if (!first_user) {
        if (!authenticate_request(connection, &creator, token_hash)) {
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_UNAUTHORIZED,
                                "UNAUTHORIZED", "需要管理员身份创建用户");
        }
        if (!is_admin_role(&creator)) {
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_FORBIDDEN, "FORBIDDEN",
                                "仅管理员可创建用户");
        }
    }

    const char *role = "staff";
    if (first_user) {
        role = "admin";
    } else if (role_input != NULL && *role_input != '\0') {
        if (strcmp(role_input, "admin") != 0 && strcmp(role_input, "staff") != 0) {
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_BAD_REQUEST,
                                "INVALID_INPUT", "role 仅支持 admin/staff");
        }
        role = role_input;
    }

    char username_copy[65];
    char role_copy[17];
    snprintf(username_copy, sizeof(username_copy), "%s", username);
    snprintf(role_copy, sizeof(role_copy), "%s", role);

    char password_hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(password_hash, password, strlen(password),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "密码加密失败");
    }

    char *full_name_enc = NULL;
    char *email_enc = NULL;
    char *phone_enc = NULL;
    if (encrypt_text(full_name, &full_name_enc) != 0 ||
        encrypt_text(email, &email_enc) != 0 ||
        encrypt_text(phone, &phone_enc) != 0) {
        free(full_name_enc);
        free(email_enc);
        free(phone_enc);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "用户信息加密失败");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO users (username, password_hash, role, full_name_enc, "
        "email_enc, phone_enc) VALUES (?, ?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        free(full_name_enc);
        free(email_enc);
        free(phone_enc);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建用户预编译失败");
    }

    sqlite3_bind_text(stmt, 1, username_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, role_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, full_name_enc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, email_enc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, phone_enc, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(full_name_enc);
    free(email_enc);
    free(phone_enc);
    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            return respond_error(connection, MHD_HTTP_CONFLICT, "CONFLICT",
                                "用户名已存在");
        }
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建用户失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "username", json_string(username_copy));
    json_object_set_new(data, "role", json_string(role_copy));
    json_object_set_new(data, "first_user", first_user ? json_true() : json_false());
    return respond_success(connection, MHD_HTTP_CREATED, data);
}

static enum MHD_Result handle_login(struct MHD_Connection *connection,
                                    ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *username = NULL;
    const char *password = NULL;
    if (require_string_field(body, "username", 64, &username) != 0 ||
        require_string_field(body, "password", 128, &password) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "username/password 必填");
    }

    char username_copy[65];
    snprintf(username_copy, sizeof(username_copy), "%s", username);

    pthread_mutex_lock(&g_db_mutex);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT id, password_hash, role FROM users WHERE username = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "数据库查询失败");
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "用户名或密码错误");
    }

    int user_id = sqlite3_column_int(stmt, 0);
    const char *password_hash = safe_col_text(stmt, 1);
    char role_copy[32];
    snprintf(role_copy, sizeof(role_copy), "%s", safe_col_text(stmt, 2));

    if (crypto_pwhash_str_verify(password_hash, password, strlen(password)) != 0) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "用户名或密码错误");
    }
    sqlite3_finalize(stmt);

    char token[128] = {0};
    if (generate_access_token(token, sizeof(token)) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "生成令牌失败");
    }

    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (hash_token(token, token_hash) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "处理令牌失败");
    }

    const time_t expires_at = now_epoch() + (time_t)g_cfg.session_ttl_hours * 3600;

    if (db_exec("DELETE FROM sessions WHERE expires_at <= strftime('%s', 'now');") != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "会话清理失败");
    }

    const char *insert_sql =
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(g_db, insert_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "会话创建失败");
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, token_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)expires_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    if (rc != SQLITE_DONE) {
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "会话创建失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "access_token", json_string(token));
    json_object_set_new(data, "token_type", json_string("Bearer"));
    json_object_set_new(data, "expires_at", json_integer((json_int_t)expires_at));
    json_object_set_new(data, "user_id", json_integer(user_id));
    json_object_set_new(data, "username", json_string(username_copy));
    json_object_set_new(data, "role", json_string(role_copy));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_logout(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "未登录或令牌无效");
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, "DELETE FROM sessions WHERE token_hash = ?;", -1,
                           &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "退出登录失败");
    }

    sqlite3_bind_text(stmt, 1, token_hash, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_db_mutex);

    json_t *data = json_object();
    json_object_set_new(data, "message", json_string("已退出登录"));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_auth_me(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "未登录或令牌无效");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT full_name_enc, email_enc, phone_enc, created_at "
        "FROM users WHERE id = ? LIMIT 1;";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询用户详情失败");
    }

    sqlite3_bind_int(stmt, 1, user.user_id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "用户不存在");
    }

    const char *full_name_enc = safe_col_text(stmt, 0);
    const char *email_enc = safe_col_text(stmt, 1);
    const char *phone_enc = safe_col_text(stmt, 2);
    char created_at[64];
    snprintf(created_at, sizeof(created_at), "%s", safe_col_text(stmt, 3));

    char *full_name = NULL;
    char *email = NULL;
    char *phone = NULL;

    int ok = decrypt_text(full_name_enc, &full_name) == 0 &&
             decrypt_text(email_enc, &email) == 0 &&
             decrypt_text(phone_enc, &phone) == 0;

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (!ok) {
        free(full_name);
        free(email);
        free(phone);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "解密用户信息失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "user_id", json_integer(user.user_id));
    json_object_set_new(data, "username", json_string(user.username));
    json_object_set_new(data, "role", json_string(user.role));
    json_object_set_new(data, "full_name", json_string(full_name));
    json_object_set_new(data, "email", json_string(email));
    json_object_set_new(data, "phone", json_string(phone));
    json_object_set_new(data, "created_at", json_string(created_at));

    free(full_name);
    free(email);
    free(phone);

    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_create_product(struct MHD_Connection *connection,
                                             ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *sku = NULL;
    const char *name = NULL;
    if (require_string_field(body, "sku", 64, &sku) != 0 ||
        require_string_field(body, "name", 128, &name) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "sku/name 必填");
    }

    const char *unit = optional_string_field(body, "unit", 16);
    if (unit == NULL || *unit == '\0') {
        unit = "瓶";
    }

    char sku_copy[65];
    char name_copy[129];
    char unit_copy[17];
    snprintf(sku_copy, sizeof(sku_copy), "%s", sku);
    snprintf(name_copy, sizeof(name_copy), "%s", name);
    snprintf(unit_copy, sizeof(unit_copy), "%s", unit);

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (!is_admin_role(&user)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_FORBIDDEN, "FORBIDDEN",
                            "仅管理员可新增商品");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO products (sku, name, unit, stock_quantity) VALUES (?, ?, ?, 0);";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "新增商品失败");
    }

    sqlite3_bind_text(stmt, 1, sku_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, name_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, unit_copy, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            return respond_error(connection, MHD_HTTP_CONFLICT, "CONFLICT",
                                "商品 SKU 已存在");
        }
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "新增商品失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "sku", json_string(sku_copy));
    json_object_set_new(data, "name", json_string(name_copy));
    json_object_set_new(data, "unit", json_string(unit_copy));
    return respond_success(connection, MHD_HTTP_CREATED, data);
}

static enum MHD_Result handle_list_products(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT id, sku, name, unit, stock_quantity, created_at, updated_at "
        "FROM products ORDER BY id DESC;";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询商品列表失败");
    }

    json_t *items = json_array();
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *item = json_object();
        json_object_set_new(item, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(item, "sku", json_string(safe_col_text(stmt, 1)));
        json_object_set_new(item, "name", json_string(safe_col_text(stmt, 2)));
        json_object_set_new(item, "unit", json_string(safe_col_text(stmt, 3)));
        json_object_set_new(item, "stock_quantity",
                            json_integer(sqlite3_column_int(stmt, 4)));
        json_object_set_new(item, "created_at", json_string(safe_col_text(stmt, 5)));
        json_object_set_new(item, "updated_at", json_string(safe_col_text(stmt, 6)));
        json_array_append_new(items, item);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(items);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取商品列表失败");
    }

    return respond_success(connection, MHD_HTTP_OK, items);
}

static int begin_transaction(void) {
    return db_exec("BEGIN IMMEDIATE TRANSACTION;");
}

static void rollback_transaction(void) { db_exec("ROLLBACK;"); }

static int commit_transaction(void) { return db_exec("COMMIT;"); }

static enum MHD_Result handle_inbound(struct MHD_Connection *connection,
                                      ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *sku = NULL;
    if (require_string_field(body, "sku", 64, &sku) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "sku 必填");
    }

    int quantity = 0;
    int unit_cost = 0;
    if (parse_int_field(body, "quantity", 1, 1000000, &quantity) != 0 ||
        parse_int_field(body, "unit_cost_cents", 0, 100000000, &unit_cost) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "quantity/unit_cost_cents 必须为合法整数");
    }

    const char *note = optional_string_field(body, "note", 256);
    if (note == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "note 需为字符串且不超过256字符");
    }

    char sku_copy[65];
    snprintf(sku_copy, sizeof(sku_copy), "%s", sku);

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    sqlite3_stmt *stmt = NULL;
    int product_id = 0;
    int current_stock = 0;

    const char *find_sql =
        "SELECT id, stock_quantity FROM products WHERE sku = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, find_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询商品失败");
    }

    sqlite3_bind_text(stmt, 1, sku_copy, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "商品不存在");
    }

    product_id = sqlite3_column_int(stmt, 0);
    current_stock = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);

    const int new_stock = current_stock + quantity;

    const char *update_sql =
        "UPDATE products SET stock_quantity = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE id = ?;";
    if (sqlite3_prepare_v2(g_db, update_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新库存失败");
    }

    sqlite3_bind_int(stmt, 1, new_stock);
    sqlite3_bind_int(stmt, 2, product_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新库存失败");
    }

    const char *ins_sql =
        "INSERT INTO stock_movements "
        "(product_id, movement_type, quantity, unit_price_cents, note, "
        "operator_user_id) "
        "VALUES (?, 'IN', ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(g_db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "写入流水失败");
    }

    sqlite3_bind_int(stmt, 1, product_id);
    sqlite3_bind_int(stmt, 2, quantity);
    sqlite3_bind_int(stmt, 3, unit_cost);
    sqlite3_bind_text(stmt, 4, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, user.user_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE || commit_transaction() != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交入库事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "sku", json_string(sku_copy));
    json_object_set_new(data, "movement_type", json_string("IN"));
    json_object_set_new(data, "quantity", json_integer(quantity));
    json_object_set_new(data, "new_stock", json_integer(new_stock));
    json_object_set_new(data, "operator", json_string(user.username));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_sales(struct MHD_Connection *connection,
                                    ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *sku = NULL;
    if (require_string_field(body, "sku", 64, &sku) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "sku 必填");
    }

    int quantity = 0;
    int sale_price = 0;
    if (parse_int_field(body, "quantity", 1, 1000000, &quantity) != 0 ||
        parse_int_field(body, "unit_price_cents", 0, 100000000, &sale_price) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "quantity/unit_price_cents 必须为合法整数");
    }

    const char *note = optional_string_field(body, "note", 256);
    if (note == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "note 需为字符串且不超过256字符");
    }

    char sku_copy[65];
    snprintf(sku_copy, sizeof(sku_copy), "%s", sku);

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    sqlite3_stmt *stmt = NULL;
    int product_id = 0;
    int current_stock = 0;

    const char *find_sql =
        "SELECT id, stock_quantity FROM products WHERE sku = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, find_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询商品失败");
    }

    sqlite3_bind_text(stmt, 1, sku_copy, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "商品不存在");
    }

    product_id = sqlite3_column_int(stmt, 0);
    current_stock = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);

    if (current_stock < quantity) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_CONFLICT, "INSUFFICIENT_STOCK",
                            "库存不足，无法出库");
    }

    const int new_stock = current_stock - quantity;

    const char *update_sql =
        "UPDATE products SET stock_quantity = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE id = ?;";
    if (sqlite3_prepare_v2(g_db, update_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新库存失败");
    }

    sqlite3_bind_int(stmt, 1, new_stock);
    sqlite3_bind_int(stmt, 2, product_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新库存失败");
    }

    const char *ins_sql =
        "INSERT INTO stock_movements "
        "(product_id, movement_type, quantity, unit_price_cents, note, "
        "operator_user_id) "
        "VALUES (?, 'OUT', ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(g_db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "写入流水失败");
    }

    sqlite3_bind_int(stmt, 1, product_id);
    sqlite3_bind_int(stmt, 2, quantity);
    sqlite3_bind_int(stmt, 3, sale_price);
    sqlite3_bind_text(stmt, 4, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, user.user_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE || commit_transaction() != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交出库事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "sku", json_string(sku_copy));
    json_object_set_new(data, "movement_type", json_string("OUT"));
    json_object_set_new(data, "quantity", json_integer(quantity));
    json_object_set_new(data, "new_stock", json_integer(new_stock));
    json_object_set_new(data, "operator", json_string(user.username));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_inventory(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    sqlite3_stmt *summary_stmt = NULL;
    const char *summary_sql =
        "SELECT "
        "  (SELECT COUNT(*) FROM products),"
        "  (SELECT COALESCE(SUM(stock_quantity), 0) FROM products),"
        "  (SELECT COALESCE(SUM(quantity), 0) FROM stock_movements WHERE "
        "movement_type='IN'),"
        "  (SELECT COALESCE(SUM(quantity), 0) FROM stock_movements WHERE "
        "movement_type='OUT');";

    if (sqlite3_prepare_v2(g_db, summary_sql, -1, &summary_stmt, NULL) !=
        SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询库存汇总失败");
    }

    int rc = sqlite3_step(summary_stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(summary_stmt);
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询库存汇总失败");
    }

    int product_count = sqlite3_column_int(summary_stmt, 0);
    int total_stock = sqlite3_column_int(summary_stmt, 1);
    int total_in = sqlite3_column_int(summary_stmt, 2);
    int total_out = sqlite3_column_int(summary_stmt, 3);
    sqlite3_finalize(summary_stmt);

    sqlite3_stmt *list_stmt = NULL;
    const char *list_sql =
        "SELECT sku, name, unit, stock_quantity, updated_at "
        "FROM products ORDER BY stock_quantity DESC, id ASC;";
    if (sqlite3_prepare_v2(g_db, list_sql, -1, &list_stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询库存明细失败");
    }

    json_t *products = json_array();
    while ((rc = sqlite3_step(list_stmt)) == SQLITE_ROW) {
        json_t *item = json_object();
        json_object_set_new(item, "sku", json_string(safe_col_text(list_stmt, 0)));
        json_object_set_new(item, "name", json_string(safe_col_text(list_stmt, 1)));
        json_object_set_new(item, "unit", json_string(safe_col_text(list_stmt, 2)));
        json_object_set_new(item, "stock_quantity",
                            json_integer(sqlite3_column_int(list_stmt, 3)));
        json_object_set_new(item, "updated_at",
                            json_string(safe_col_text(list_stmt, 4)));
        json_array_append_new(products, item);
    }

    sqlite3_finalize(list_stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(products);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取库存明细失败");
    }

    json_t *data = json_object();
    json_t *summary = json_object();
    json_object_set_new(summary, "product_count", json_integer(product_count));
    json_object_set_new(summary, "total_stock_quantity", json_integer(total_stock));
    json_object_set_new(summary, "total_in_quantity", json_integer(total_in));
    json_object_set_new(summary, "total_out_quantity", json_integer(total_out));

    json_object_set_new(data, "summary", summary);
    json_object_set_new(data, "products", products);

    return respond_success(connection, MHD_HTTP_OK, data);
}

static int parse_limit_query(struct MHD_Connection *connection) {
    const char *limit_s =
        MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "limit");
    if (limit_s == NULL || *limit_s == '\0') {
        return 50;
    }

    char *end = NULL;
    errno = 0;
    long v = strtol(limit_s, &end, 10);
    if (errno != 0 || end == limit_s || *end != '\0') {
        return 50;
    }
    if (v < 1) {
        v = 1;
    }
    if (v > 200) {
        v = 200;
    }
    return (int)v;
}

static enum MHD_Result handle_movements(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    const char *type =
        MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "type");
    int use_type = 0;
    if (type != NULL && *type != '\0') {
        if (strcmp(type, "IN") == 0 || strcmp(type, "OUT") == 0) {
            use_type = 1;
        } else {
            pthread_mutex_unlock(&g_db_mutex);
            return respond_error(connection, MHD_HTTP_BAD_REQUEST,
                                "INVALID_INPUT", "type 仅支持 IN 或 OUT");
        }
    }

    int limit = parse_limit_query(connection);

    sqlite3_stmt *stmt = NULL;
    const char *sql_all =
        "SELECT m.id, p.sku, p.name, m.movement_type, m.quantity, "
        "m.unit_price_cents, m.note, u.username, m.created_at "
        "FROM stock_movements m "
        "JOIN products p ON p.id = m.product_id "
        "JOIN users u ON u.id = m.operator_user_id "
        "ORDER BY m.id DESC LIMIT ?;";

    const char *sql_type =
        "SELECT m.id, p.sku, p.name, m.movement_type, m.quantity, "
        "m.unit_price_cents, m.note, u.username, m.created_at "
        "FROM stock_movements m "
        "JOIN products p ON p.id = m.product_id "
        "JOIN users u ON u.id = m.operator_user_id "
        "WHERE m.movement_type = ? "
        "ORDER BY m.id DESC LIMIT ?;";

    if (sqlite3_prepare_v2(g_db, use_type ? sql_type : sql_all, -1, &stmt, NULL) !=
        SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询流水失败");
    }

    int idx = 1;
    if (use_type) {
        sqlite3_bind_text(stmt, idx++, type, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, idx, limit);

    json_t *items = json_array();
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *it = json_object();
        json_object_set_new(it, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(it, "sku", json_string(safe_col_text(stmt, 1)));
        json_object_set_new(it, "product_name", json_string(safe_col_text(stmt, 2)));
        json_object_set_new(it, "movement_type", json_string(safe_col_text(stmt, 3)));
        json_object_set_new(it, "quantity", json_integer(sqlite3_column_int(stmt, 4)));
        json_object_set_new(it, "unit_price_cents",
                            json_integer(sqlite3_column_int(stmt, 5)));
        json_object_set_new(it, "note", json_string(safe_col_text(stmt, 6)));
        json_object_set_new(it, "operator", json_string(safe_col_text(stmt, 7)));
        json_object_set_new(it, "created_at", json_string(safe_col_text(stmt, 8)));
        json_array_append_new(items, it);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(items);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取流水失败");
    }

    return respond_success(connection, MHD_HTTP_OK, items);
}

static void generate_order_no(char *out, size_t out_size) {
    time_t t = now_epoch();
    struct tm tm_info;
    localtime_r(&t, &tm_info);
    char time_part[32];
    strftime(time_part, sizeof(time_part), "%Y%m%d%H%M%S", &tm_info);
    unsigned int rand_part = (unsigned int)randombytes_random();
    snprintf(out, out_size, "ORD%s%06u", time_part, rand_part % 1000000);
}

static void generate_txn_no(const char *prefix, char *out, size_t out_size) {
    time_t t = now_epoch();
    struct tm tm_info;
    localtime_r(&t, &tm_info);
    char time_part[32];
    strftime(time_part, sizeof(time_part), "%Y%m%d%H%M%S", &tm_info);
    unsigned int rand_part = (unsigned int)randombytes_random();
    snprintf(out, out_size, "%s%s%06u", prefix, time_part, rand_part % 1000000);
}

static int get_product_by_sku(const char *sku, int *out_id, int *out_price,
                              int *out_stock, char *out_name, size_t name_size) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT id, name, stock_quantity FROM products WHERE sku = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, sku, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *out_id = sqlite3_column_int(stmt, 0);
    const char *name = (const char *)sqlite3_column_text(stmt, 1);
    snprintf(out_name, name_size, "%s", name ? name : "");
    *out_stock = sqlite3_column_int(stmt, 2);
    sqlite3_finalize(stmt);
    return 0;
}

static int get_product_price(int product_id, int *out_price) {
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT unit_price_cents FROM stock_movements "
        "WHERE product_id = ? AND movement_type = 'IN' "
        "ORDER BY id DESC LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, product_id);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_price = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    return -1;
}

typedef struct {
    int product_id;
    char product_name[128];
    int quantity;
    int unit_price_cents;
    int subtotal_cents;
} OrderItemInput;

static enum MHD_Result handle_create_order(struct MHD_Connection *connection,
                                           ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    json_t *items_arr = json_object_get(body, "items");
    if (!json_is_array(items_arr) || json_array_size(items_arr) == 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "items 必须是非空数组");
    }

    size_t item_count = json_array_size(items_arr);
    if (item_count > 100) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "订单项数量不能超过100");
    }

    OrderItemInput *items = (OrderItemInput *)calloc(item_count, sizeof(OrderItemInput));
    if (items == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "INTERNAL_ERROR", "内存分配失败");
    }

    int total_amount = 0;
    int parse_ok = 1;

    for (size_t i = 0; i < item_count; ++i) {
        json_t *item = json_array_get(items_arr, i);
        const char *sku = json_string_value(json_object_get(item, "sku"));
        if (sku == NULL || *sku == '\0') {
            parse_ok = 0;
            break;
        }

        json_t *qty_j = json_object_get(item, "quantity");
        if (!json_is_integer(qty_j)) {
            parse_ok = 0;
            break;
        }
        int qty = (int)json_integer_value(qty_j);
        if (qty <= 0 || qty > 10000) {
            parse_ok = 0;
            break;
        }

        int product_id = 0;
        int stock = 0;
        if (get_product_by_sku(sku, &product_id, &items[i].unit_price_cents,
                               &stock, items[i].product_name,
                               sizeof(items[i].product_name)) != 0) {
            parse_ok = 0;
            snprintf(err, sizeof(err), "商品不存在: %s", sku);
            break;
        }

        if (stock < qty) {
            parse_ok = 0;
            snprintf(err, sizeof(err), "商品库存不足: %s", sku);
            break;
        }

        json_t *price_j = json_object_get(item, "unit_price_cents");
        if (json_is_integer(price_j)) {
            items[i].unit_price_cents = (int)json_integer_value(price_j);
        }
        if (items[i].unit_price_cents < 0) {
            parse_ok = 0;
            break;
        }

        items[i].product_id = product_id;
        items[i].quantity = qty;
        items[i].subtotal_cents = items[i].unit_price_cents * qty;
        total_amount += items[i].subtotal_cents;
    }

    if (!parse_ok) {
        free(items);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT", err);
    }

    const char *note = optional_string_field(body, "note", 512);
    if (note == NULL) {
        free(items);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "note 需为字符串且不超过512字符");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    int has_auth = authenticate_request(connection, &user, token_hash);

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        free(items);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    char order_no[64];
    generate_order_no(order_no, sizeof(order_no));

    sqlite3_stmt *stmt = NULL;
    const char *order_sql =
        "INSERT INTO orders (order_no, total_amount_cents, paid_amount_cents, "
        "change_amount_cents, status, operator_user_id, note) "
        "VALUES (?, ?, 0, 0, 'PENDING', ?, ?);";
    if (sqlite3_prepare_v2(g_db, order_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        free(items);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建订单预编译失败");
    }
    sqlite3_bind_text(stmt, 1, order_no, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, total_amount);
    if (has_auth) {
        sqlite3_bind_int(stmt, 3, user.user_id);
    } else {
        sqlite3_bind_null(stmt, 3);
    }
    sqlite3_bind_text(stmt, 4, note, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        free(items);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建订单失败");
    }

    int order_id = (int)sqlite3_last_insert_rowid(g_db);

    const char *item_sql =
        "INSERT INTO order_items (order_id, product_id, product_name, quantity, "
        "unit_price_cents, subtotal_cents) VALUES (?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(g_db, item_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        free(items);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "订单项预编译失败");
    }

    for (size_t i = 0; i < item_count; ++i) {
        sqlite3_bind_int(stmt, 1, order_id);
        sqlite3_bind_int(stmt, 2, items[i].product_id);
        sqlite3_bind_text(stmt, 3, items[i].product_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, items[i].quantity);
        sqlite3_bind_int(stmt, 5, items[i].unit_price_cents);
        sqlite3_bind_int(stmt, 6, items[i].subtotal_cents);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            break;
        }
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        free(items);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建订单项失败");
    }

    if (commit_transaction() != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        free(items);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交订单事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    free(items);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "order_id", json_integer(order_id));
    json_object_set_new(data, "order_no", json_string(order_no));
    json_object_set_new(data, "total_amount_cents", json_integer(total_amount));
    json_object_set_new(data, "status", json_string("PENDING"));
    return respond_success(connection, MHD_HTTP_CREATED, data);
}

static int get_order_by_id(int order_id, int *out_total, int *out_paid,
                           int *out_change, char *out_status,
                           size_t status_size, char *out_payment_method,
                           size_t method_size) {
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT total_amount_cents, paid_amount_cents, change_amount_cents, "
        "status, payment_method FROM orders WHERE id = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, order_id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *out_total = sqlite3_column_int(stmt, 0);
    *out_paid = sqlite3_column_int(stmt, 1);
    *out_change = sqlite3_column_int(stmt, 2);
    const char *st = (const char *)sqlite3_column_text(stmt, 3);
    snprintf(out_status, status_size, "%s", st ? st : "");
    const char *pm = (const char *)sqlite3_column_text(stmt, 4);
    snprintf(out_payment_method, method_size, "%s", pm ? pm : "");
    sqlite3_finalize(stmt);
    return 0;
}

static enum MHD_Result handle_payment(struct MHD_Connection *connection,
                                      ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    int order_id = 0;
    if (parse_int_field(body, "order_id", 1, INT_MAX, &order_id) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "order_id 必填且为正整数");
    }

    const char *payment_method = NULL;
    if (require_string_field(body, "payment_method", 16, &payment_method) != 0 ||
        (strcmp(payment_method, "COIN") != 0 &&
         strcmp(payment_method, "BILL") != 0 &&
         strcmp(payment_method, "QR_CODE") != 0)) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "payment_method 必须是 COIN/BILL/QR_CODE");
    }

    int amount = 0;
    if (parse_int_field(body, "amount_cents", 1, 100000000, &amount) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "amount_cents 必填且为正整数");
    }

    const char *denomination = optional_string_field(body, "denomination", 32);
    if (denomination == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "denomination 需为字符串且不超过32字符");
    }

    const char *external_ref = optional_string_field(body, "external_ref", 128);
    if (external_ref == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "external_ref 需为字符串且不超过128字符");
    }

    const char *note = optional_string_field(body, "note", 256);
    if (note == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "note 需为字符串且不超过256字符");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    int has_auth = authenticate_request(connection, &user, token_hash);

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    int total_amount = 0;
    int paid_amount = 0;
    int change_amount = 0;
    char status[32] = {0};
    char curr_payment_method[32] = {0};

    if (get_order_by_id(order_id, &total_amount, &paid_amount, &change_amount,
                        status, sizeof(status), curr_payment_method,
                        sizeof(curr_payment_method)) != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "订单不存在");
    }

    if (strcmp(status, "PENDING") != 0 && strcmp(status, "PAID") != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_CONFLICT, "INVALID_STATUS",
                            "订单状态不允许支付");
    }

    if (paid_amount >= total_amount) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_CONFLICT, "ALREADY_PAID",
                            "订单已足额支付");
    }

    int remaining = total_amount - paid_amount;
    int actual_pay = (amount > remaining) ? remaining : amount;

    char txn_no[64];
    generate_txn_no("PAY", txn_no, sizeof(txn_no));

    sqlite3_stmt *stmt = NULL;
    const char *pay_sql =
        "INSERT INTO payment_transactions "
        "(order_id, txn_no, payment_method, amount_cents, denomination, "
        " status, external_ref, operator_user_id) "
        "VALUES (?, ?, ?, ?, ?, 'SUCCESS', ?, ?);";
    if (sqlite3_prepare_v2(g_db, pay_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "支付流水预编译失败");
    }
    sqlite3_bind_int(stmt, 1, order_id);
    sqlite3_bind_text(stmt, 2, txn_no, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, payment_method, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, actual_pay);
    sqlite3_bind_text(stmt, 5, denomination, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, external_ref, -1, SQLITE_TRANSIENT);
    if (has_auth) {
        sqlite3_bind_int(stmt, 7, user.user_id);
    } else {
        sqlite3_bind_null(stmt, 7);
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "记录支付流水失败");
    }

    int new_paid = paid_amount + actual_pay;
    int new_change = (new_paid > total_amount) ? (new_paid - total_amount) : 0;
    char new_status[32] = {0};

    if (new_paid >= total_amount) {
        if (new_change > 0) {
            snprintf(new_status, sizeof(new_status), "CHANGE_PENDING");
        } else {
            snprintf(new_status, sizeof(new_status), "COMPLETED");
        }
    } else {
        snprintf(new_status, sizeof(new_status), "PAID");
    }

    char new_payment_method[32] = {0};
    if (curr_payment_method[0] == '\0') {
        snprintf(new_payment_method, sizeof(new_payment_method), "%s", payment_method);
    } else if (strcmp(curr_payment_method, payment_method) != 0) {
        snprintf(new_payment_method, sizeof(new_payment_method), "MIXED");
    } else {
        snprintf(new_payment_method, sizeof(new_payment_method), "%s", curr_payment_method);
    }

    const char *upd_sql =
        "UPDATE orders SET paid_amount_cents = ?, change_amount_cents = ?, "
        "status = ?, payment_method = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE id = ?;";
    if (sqlite3_prepare_v2(g_db, upd_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新订单预编译失败");
    }
    sqlite3_bind_int(stmt, 1, new_paid);
    sqlite3_bind_int(stmt, 2, new_change);
    sqlite3_bind_text(stmt, 3, new_status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, new_payment_method, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, order_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新订单失败");
    }

    if (commit_transaction() != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交支付事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "order_id", json_integer(order_id));
    json_object_set_new(data, "payment_txn_no", json_string(txn_no));
    json_object_set_new(data, "payment_method", json_string(payment_method));
    json_object_set_new(data, "paid_amount_cents", json_integer(actual_pay));
    json_object_set_new(data, "total_paid_cents", json_integer(new_paid));
    json_object_set_new(data, "change_amount_cents", json_integer(new_change));
    json_object_set_new(data, "order_status", json_string(new_status));
    return respond_success(connection, MHD_HTTP_OK, data);
}

typedef struct {
    char denomination[32];
    int value_cents;
    int quantity;
    int coin_type;
} DenominationInfo;

static int load_all_denominations(DenominationInfo *out, int max_count,
                                  int *out_count) {
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT denomination, denomination_value_cents, quantity, coin_type "
        "FROM cash_drawer ORDER BY denomination_value_cents DESC;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    int count = 0;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && count < max_count) {
        snprintf(out[count].denomination, sizeof(out[count].denomination),
                 "%s", (const char *)sqlite3_column_text(stmt, 0));
        out[count].value_cents = sqlite3_column_int(stmt, 1);
        out[count].quantity = sqlite3_column_int(stmt, 2);
        const char *ct = (const char *)sqlite3_column_text(stmt, 3);
        out[count].coin_type = (ct && strcmp(ct, "COIN") == 0) ? 0 : 1;
        count++;
    }
    sqlite3_finalize(stmt);
    *out_count = count;
    return (rc == SQLITE_DONE || rc == SQLITE_ROW) ? 0 : -1;
}

typedef struct {
    char denomination[32];
    int value_cents;
    int dispense_count;
} ChangePlanItem;

static int calculate_change(int amount_cents, DenominationInfo *denoms,
                            int denom_count, ChangePlanItem *out_plan,
                            int max_plan_items, int *out_plan_count,
                            int *out_actual_total) {
    int remaining = amount_cents;
    int plan_count = 0;
    int actual_total = 0;

    for (int i = 0; i < denom_count && remaining > 0 && plan_count < max_plan_items; i++) {
        if (denoms[i].quantity <= 0) continue;
        if (denoms[i].value_cents > remaining) continue;

        int max_need = remaining / denoms[i].value_cents;
        int can_dispense = (max_need < denoms[i].quantity) ? max_need : denoms[i].quantity;

        if (can_dispense > 0) {
            snprintf(out_plan[plan_count].denomination,
                     sizeof(out_plan[plan_count].denomination),
                     "%s", denoms[i].denomination);
            out_plan[plan_count].value_cents = denoms[i].value_cents;
            out_plan[plan_count].dispense_count = can_dispense;
            actual_total += can_dispense * denoms[i].value_cents;
            remaining -= can_dispense * denoms[i].value_cents;
            plan_count++;
        }
    }

    *out_plan_count = plan_count;
    *out_actual_total = actual_total;
    return (remaining == 0) ? 0 : -1;
}

static int update_cash_drawer_for_change(ChangePlanItem *plan, int plan_count,
                                         int order_id, int change_txn_id,
                                         int operator_id) {
    for (int i = 0; i < plan_count; i++) {
        sqlite3_stmt *stmt = NULL;
        const char *sel_sql =
            "SELECT quantity, total_value_cents FROM cash_drawer "
            "WHERE denomination = ?;";
        if (sqlite3_prepare_v2(g_db, sel_sql, -1, &stmt, NULL) != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_text(stmt, 1, plan[i].denomination, -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return -1;
        }
        int qty_before = sqlite3_column_int(stmt, 0);
        int total_before = sqlite3_column_int(stmt, 1);
        sqlite3_finalize(stmt);

        int qty_after = qty_before - plan[i].dispense_count;
        int value_change = -plan[i].dispense_count * plan[i].value_cents;
        int total_after = total_before + value_change;

        const char *upd_sql =
            "UPDATE cash_drawer SET quantity = ?, total_value_cents = ?, "
            "updated_at = CURRENT_TIMESTAMP WHERE denomination = ?;";
        if (sqlite3_prepare_v2(g_db, upd_sql, -1, &stmt, NULL) != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_int(stmt, 1, qty_after);
        sqlite3_bind_int(stmt, 2, total_after);
        sqlite3_bind_text(stmt, 3, plan[i].denomination, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            return -1;
        }

        const char *mv_sql =
            "INSERT INTO cash_drawer_movements "
            "(denomination, movement_type, quantity_before, quantity_change, "
            " quantity_after, value_change_cents, order_id, change_txn_id, "
            " operator_user_id, note) "
            "VALUES (?, 'DISPENSE', ?, ?, ?, ?, ?, ?, ?, '找零支出');";
        if (sqlite3_prepare_v2(g_db, mv_sql, -1, &stmt, NULL) != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_text(stmt, 1, plan[i].denomination, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, qty_before);
        sqlite3_bind_int(stmt, 3, -plan[i].dispense_count);
        sqlite3_bind_int(stmt, 4, qty_after);
        sqlite3_bind_int(stmt, 5, value_change);
        if (order_id > 0) {
            sqlite3_bind_int(stmt, 6, order_id);
        } else {
            sqlite3_bind_null(stmt, 6);
        }
        if (change_txn_id > 0) {
            sqlite3_bind_int(stmt, 7, change_txn_id);
        } else {
            sqlite3_bind_null(stmt, 7);
        }
        if (operator_id > 0) {
            sqlite3_bind_int(stmt, 8, operator_id);
        } else {
            sqlite3_bind_null(stmt, 8);
        }
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            return -1;
        }
    }
    return 0;
}

static char *build_denom_breakdown(ChangePlanItem *plan, int plan_count) {
    size_t buf_size = 512;
    char *buf = (char *)malloc(buf_size);
    if (buf == NULL) return NULL;
    buf[0] = '\0';
    size_t pos = 0;
    for (int i = 0; i < plan_count; i++) {
        int n = snprintf(buf + pos, buf_size - pos, "%s:%d%s",
                         plan[i].denomination, plan[i].dispense_count,
                         (i < plan_count - 1) ? "," : "");
        if (n < 0 || (size_t)n >= buf_size - pos) break;
        pos += (size_t)n;
    }
    return buf;
}

static enum MHD_Result handle_dispense_change(struct MHD_Connection *connection,
                                              ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    int order_id = 0;
    if (parse_int_field(body, "order_id", 1, INT_MAX, &order_id) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "order_id 必填且为正整数");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    int has_auth = authenticate_request(connection, &user, token_hash);

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    int total_amount = 0;
    int paid_amount = 0;
    int change_amount = 0;
    char status[32] = {0};
    char payment_method[32] = {0};

    if (get_order_by_id(order_id, &total_amount, &paid_amount, &change_amount,
                        status, sizeof(status), payment_method,
                        sizeof(payment_method)) != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "订单不存在");
    }

    if (strcmp(status, "CHANGE_PENDING") != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_CONFLICT, "INVALID_STATUS",
                            "订单状态不需要找零");
    }

    if (change_amount <= 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "NO_CHANGE",
                            "找零金额为0");
    }

    char txn_no[64];
    generate_txn_no("CHG", txn_no, sizeof(txn_no));

    DenominationInfo denoms[32];
    int denom_count = 0;
    if (load_all_denominations(denoms, 32, &denom_count) != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "加载找零盒数据失败");
    }

    ChangePlanItem plan[32];
    int plan_count = 0;
    int actual_total = 0;
    int can_full_change = (calculate_change(change_amount, denoms, denom_count,
                                            plan, 32, &plan_count,
                                            &actual_total) == 0);

    char *breakdown = build_denom_breakdown(plan, plan_count);
    const char *change_status = NULL;
    const char *failure_reason = NULL;
    const char *order_status = NULL;
    const char *order_failure_reason = NULL;

    if (can_full_change) {
        change_status = "SUCCESS";
        order_status = "COMPLETED";
    } else if (actual_total > 0) {
        change_status = "PARTIAL";
        failure_reason = "INSUFFICIENT_CHANGE";
        order_status = "CHANGE_FAILED";
        order_failure_reason = "INSUFFICIENT_CHANGE";
    } else {
        change_status = "FAILED";
        failure_reason = "INSUFFICIENT_CHANGE";
        order_status = "CHANGE_FAILED";
        order_failure_reason = "INSUFFICIENT_CHANGE";
    }

    sqlite3_stmt *stmt = NULL;
    const char *ins_sql =
        "INSERT INTO change_transactions "
        "(order_id, txn_no, request_amount_cents, actual_amount_cents, "
        " status, failure_reason, denomination_breakdown, operator_user_id, note) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, '自动找零');";
    if (sqlite3_prepare_v2(g_db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        free(breakdown);
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "找零流水预编译失败");
    }
    sqlite3_bind_int(stmt, 1, order_id);
    sqlite3_bind_text(stmt, 2, txn_no, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, change_amount);
    sqlite3_bind_int(stmt, 4, actual_total);
    sqlite3_bind_text(stmt, 5, change_status, -1, SQLITE_TRANSIENT);
    if (failure_reason) {
        sqlite3_bind_text(stmt, 6, failure_reason, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 6);
    }
    if (breakdown) {
        sqlite3_bind_text(stmt, 7, breakdown, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 7);
    }
    if (has_auth) {
        sqlite3_bind_int(stmt, 8, user.user_id);
    } else {
        sqlite3_bind_null(stmt, 8);
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        free(breakdown);
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "记录找零流水失败");
    }

    int change_txn_id = (int)sqlite3_last_insert_rowid(g_db);

    if (actual_total > 0) {
        if (update_cash_drawer_for_change(plan, plan_count, order_id,
                                          change_txn_id,
                                          has_auth ? user.user_id : 0) != 0) {
            free(breakdown);
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                "DB_ERROR", "更新找零盒失败");
        }
    }

    const char *upd_sql =
        "UPDATE orders SET status = ?, change_failure_reason = ?, "
        "updated_at = CURRENT_TIMESTAMP WHERE id = ?;";
    if (strcmp(change_status, "SUCCESS") == 0) {
        upd_sql =
            "UPDATE orders SET status = ?, change_failure_reason = NULL, "
            "updated_at = CURRENT_TIMESTAMP WHERE id = ?;";
    }
    if (sqlite3_prepare_v2(g_db, upd_sql, -1, &stmt, NULL) != SQLITE_OK) {
        free(breakdown);
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新订单预编译失败");
    }
    int idx = 1;
    sqlite3_bind_text(stmt, idx++, order_status, -1, SQLITE_TRANSIENT);
    if (strcmp(change_status, "SUCCESS") != 0) {
        sqlite3_bind_text(stmt, idx++, order_failure_reason, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, idx, order_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        free(breakdown);
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新订单失败");
    }

    if (commit_transaction() != 0) {
        free(breakdown);
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交找零事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "order_id", json_integer(order_id));
    json_object_set_new(data, "change_txn_no", json_string(txn_no));
    json_object_set_new(data, "request_amount_cents", json_integer(change_amount));
    json_object_set_new(data, "actual_amount_cents", json_integer(actual_total));
    json_object_set_new(data, "status", json_string(change_status));
    if (failure_reason) {
        json_object_set_new(data, "failure_reason", json_string(failure_reason));
    }
    if (breakdown) {
        json_object_set_new(data, "denomination_breakdown", json_string(breakdown));
    }
    free(breakdown);
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_change_exception(struct MHD_Connection *connection,
                                               ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    int order_id = 0;
    if (parse_int_field(body, "order_id", 1, INT_MAX, &order_id) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "order_id 必填且为正整数");
    }

    const char *exception_type = NULL;
    if (require_string_field(body, "exception_type", 32, &exception_type) != 0 ||
        (strcmp(exception_type, "COIN_JAM") != 0 &&
         strcmp(exception_type, "USER_CANCELLED") != 0 &&
         strcmp(exception_type, "MANUAL_REFUND") != 0)) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "exception_type 必须是 COIN_JAM/USER_CANCELLED/MANUAL_REFUND");
    }

    const char *note = optional_string_field(body, "note", 512);
    if (note == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "note 需为字符串且不超过512字符");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    int has_auth = authenticate_request(connection, &user, token_hash);

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    int total_amount = 0;
    int paid_amount = 0;
    int change_amount = 0;
    char status[32] = {0};
    char payment_method[32] = {0};

    if (get_order_by_id(order_id, &total_amount, &paid_amount, &change_amount,
                        status, sizeof(status), payment_method,
                        sizeof(payment_method)) != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "订单不存在");
    }

    if (strcmp(status, "CHANGE_PENDING") != 0 &&
        strcmp(status, "CHANGE_FAILED") != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_CONFLICT, "INVALID_STATUS",
                            "当前订单状态不允许此操作");
    }

    char txn_no[64];
    generate_txn_no("CHG", txn_no, sizeof(txn_no));

    const char *txn_status = NULL;
    const char *order_status = NULL;

    if (strcmp(exception_type, "COIN_JAM") == 0) {
        txn_status = "FAILED";
        order_status = "CHANGE_FAILED";
    } else if (strcmp(exception_type, "USER_CANCELLED") == 0) {
        txn_status = "CANCELLED";
        order_status = "CHANGE_FAILED";
    } else if (strcmp(exception_type, "MANUAL_REFUND") == 0) {
        txn_status = "MANUAL_REFUND";
        order_status = "COMPLETED";
    }

    sqlite3_stmt *stmt = NULL;
    const char *ins_sql =
        "INSERT INTO change_transactions "
        "(order_id, txn_no, request_amount_cents, actual_amount_cents, "
        " status, failure_reason, operator_user_id, note) "
        "VALUES (?, ?, ?, 0, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(g_db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "找零异常流水预编译失败");
    }
    sqlite3_bind_int(stmt, 1, order_id);
    sqlite3_bind_text(stmt, 2, txn_no, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, change_amount);
    sqlite3_bind_text(stmt, 4, txn_status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, exception_type, -1, SQLITE_TRANSIENT);
    if (has_auth) {
        sqlite3_bind_int(stmt, 6, user.user_id);
    } else {
        sqlite3_bind_null(stmt, 6);
    }
    sqlite3_bind_text(stmt, 7, note, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "记录找零异常流水失败");
    }

    const char *upd_sql = NULL;
    if (strcmp(exception_type, "MANUAL_REFUND") == 0) {
        upd_sql =
            "UPDATE orders SET status = ?, change_failure_reason = ?, "
            "updated_at = CURRENT_TIMESTAMP WHERE id = ?;";
    } else {
        upd_sql =
            "UPDATE orders SET status = ?, change_failure_reason = ?, "
            "updated_at = CURRENT_TIMESTAMP WHERE id = ?;";
    }
    if (sqlite3_prepare_v2(g_db, upd_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新订单预编译失败");
    }
    sqlite3_bind_text(stmt, 1, order_status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, exception_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, order_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新订单失败");
    }

    if (commit_transaction() != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "order_id", json_integer(order_id));
    json_object_set_new(data, "change_txn_no", json_string(txn_no));
    json_object_set_new(data, "exception_type", json_string(exception_type));
    json_object_set_new(data, "order_status", json_string(order_status));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_cash_drawer_status(struct MHD_Connection *connection,
                                                 ConnectionInfo *ci) {
    (void)ci;
    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT denomination, denomination_value_cents, quantity, "
        "total_value_cents, coin_type, updated_at "
        "FROM cash_drawer ORDER BY denomination_value_cents ASC;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询找零盒失败");
    }

    json_t *items = json_array();
    int total_cents = 0;
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *item = json_object();
        json_object_set_new(item, "denomination",
                            json_string(safe_col_text(stmt, 0)));
        json_object_set_new(item, "value_cents",
                            json_integer(sqlite3_column_int(stmt, 1)));
        json_object_set_new(item, "quantity",
                            json_integer(sqlite3_column_int(stmt, 2)));
        json_object_set_new(item, "total_value_cents",
                            json_integer(sqlite3_column_int(stmt, 3)));
        json_object_set_new(item, "coin_type",
                            json_string(safe_col_text(stmt, 4)));
        json_object_set_new(item, "updated_at",
                            json_string(safe_col_text(stmt, 5)));
        json_array_append_new(items, item);
        total_cents += sqlite3_column_int(stmt, 3);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(items);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取找零盒数据失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "total_value_cents", json_integer(total_cents));
    json_object_set_new(data, "denominations", items);
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_cash_drawer_refill(struct MHD_Connection *connection,
                                                  ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    json_t *items_arr = json_object_get(body, "items");
    if (!json_is_array(items_arr) || json_array_size(items_arr) == 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "items 必须是非空数组");
    }

    const char *note = optional_string_field(body, "note", 256);
    if (note == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "note 需为字符串且不超过256字符");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (!is_admin_role(&user)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_FORBIDDEN, "FORBIDDEN",
                            "仅管理员可补充找零盒");
    }

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    size_t item_count = json_array_size(items_arr);
    int total_added = 0;

    for (size_t i = 0; i < item_count; ++i) {
        json_t *item = json_array_get(items_arr, i);
        const char *denom = json_string_value(json_object_get(item, "denomination"));
        if (denom == NULL || *denom == '\0') {
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                                "denomination 必填");
        }

        json_t *qty_j = json_object_get(item, "add_quantity");
        if (!json_is_integer(qty_j)) {
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                                "add_quantity 必须是整数");
        }
        int add_qty = (int)json_integer_value(qty_j);
        if (add_qty <= 0 || add_qty > 100000) {
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                                "add_quantity 必须在1-100000之间");
        }

        sqlite3_stmt *stmt = NULL;
        const char *sel_sql =
            "SELECT quantity, total_value_cents, denomination_value_cents "
            "FROM cash_drawer WHERE denomination = ?;";
        if (sqlite3_prepare_v2(g_db, sel_sql, -1, &stmt, NULL) != SQLITE_OK) {
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                "DB_ERROR", "查询面额失败");
        }
        sqlite3_bind_text(stmt, 1, denom, -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                                "面额不存在");
        }
        int qty_before = sqlite3_column_int(stmt, 0);
        int total_before = sqlite3_column_int(stmt, 1);
        int value_each = sqlite3_column_int(stmt, 2);
        sqlite3_finalize(stmt);

        int qty_after = qty_before + add_qty;
        int value_change = add_qty * value_each;
        int total_after = total_before + value_change;
        total_added += value_change;

        const char *upd_sql =
            "UPDATE cash_drawer SET quantity = ?, total_value_cents = ?, "
            "updated_at = CURRENT_TIMESTAMP WHERE denomination = ?;";
        if (sqlite3_prepare_v2(g_db, upd_sql, -1, &stmt, NULL) != SQLITE_OK) {
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                "DB_ERROR", "更新找零盒失败");
        }
        sqlite3_bind_int(stmt, 1, qty_after);
        sqlite3_bind_int(stmt, 2, total_after);
        sqlite3_bind_text(stmt, 3, denom, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                "DB_ERROR", "更新找零盒失败");
        }

        const char *mv_sql =
            "INSERT INTO cash_drawer_movements "
            "(denomination, movement_type, quantity_before, quantity_change, "
            " quantity_after, value_change_cents, operator_user_id, note) "
            "VALUES (?, 'REFILL', ?, ?, ?, ?, ?, ?);";
        if (sqlite3_prepare_v2(g_db, mv_sql, -1, &stmt, NULL) != SQLITE_OK) {
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                "DB_ERROR", "写入流水失败");
        }
        sqlite3_bind_text(stmt, 1, denom, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, qty_before);
        sqlite3_bind_int(stmt, 3, add_qty);
        sqlite3_bind_int(stmt, 4, qty_after);
        sqlite3_bind_int(stmt, 5, value_change);
        sqlite3_bind_int(stmt, 6, user.user_id);
        sqlite3_bind_text(stmt, 7, note, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            rollback_transaction();
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                "DB_ERROR", "写入流水失败");
        }
    }

    if (commit_transaction() != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "total_added_cents", json_integer(total_added));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_order_detail(struct MHD_Connection *connection,
                                            ConnectionInfo *ci) {
    (void)ci;
    const char *id_s = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "id");
    if (id_s == NULL || *id_s == '\0') {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "id 参数必填");
    }
    int order_id = atoi(id_s);
    if (order_id <= 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "id 必须为正整数");
    }

    pthread_mutex_lock(&g_db_mutex);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT o.id, o.order_no, o.total_amount_cents, o.paid_amount_cents, "
        "o.change_amount_cents, o.status, o.payment_method, o.change_failure_reason, "
        "o.note, o.created_at, o.updated_at, u.username "
        "FROM orders o "
        "LEFT JOIN users u ON u.id = o.operator_user_id "
        "WHERE o.id = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询订单失败");
    }
    sqlite3_bind_int(stmt, 1, order_id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "订单不存在");
    }

    json_t *order = json_object();
    json_object_set_new(order, "id", json_integer(sqlite3_column_int(stmt, 0)));
    json_object_set_new(order, "order_no", json_string(safe_col_text(stmt, 1)));
    json_object_set_new(order, "total_amount_cents",
                        json_integer(sqlite3_column_int(stmt, 2)));
    json_object_set_new(order, "paid_amount_cents",
                        json_integer(sqlite3_column_int(stmt, 3)));
    json_object_set_new(order, "change_amount_cents",
                        json_integer(sqlite3_column_int(stmt, 4)));
    json_object_set_new(order, "status", json_string(safe_col_text(stmt, 5)));
    json_object_set_new(order, "payment_method",
                        json_string(safe_col_text(stmt, 6)));
    const char *fr = safe_col_text(stmt, 7);
    if (fr && *fr) {
        json_object_set_new(order, "change_failure_reason", json_string(fr));
    }
    json_object_set_new(order, "note", json_string(safe_col_text(stmt, 8)));
    json_object_set_new(order, "created_at", json_string(safe_col_text(stmt, 9)));
    json_object_set_new(order, "updated_at", json_string(safe_col_text(stmt, 10)));
    json_object_set_new(order, "operator", json_string(safe_col_text(stmt, 11)));
    sqlite3_finalize(stmt);

    const char *item_sql =
        "SELECT id, product_id, product_name, quantity, unit_price_cents, "
        "subtotal_cents FROM order_items WHERE order_id = ? ORDER BY id ASC;";
    if (sqlite3_prepare_v2(g_db, item_sql, -1, &stmt, NULL) != SQLITE_OK) {
        json_decref(order);
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询订单项失败");
    }
    sqlite3_bind_int(stmt, 1, order_id);
    json_t *items = json_array();
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *it = json_object();
        json_object_set_new(it, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(it, "product_id",
                            json_integer(sqlite3_column_int(stmt, 1)));
        json_object_set_new(it, "product_name",
                            json_string(safe_col_text(stmt, 2)));
        json_object_set_new(it, "quantity",
                            json_integer(sqlite3_column_int(stmt, 3)));
        json_object_set_new(it, "unit_price_cents",
                            json_integer(sqlite3_column_int(stmt, 4)));
        json_object_set_new(it, "subtotal_cents",
                            json_integer(sqlite3_column_int(stmt, 5)));
        json_array_append_new(items, it);
    }
    sqlite3_finalize(stmt);
    json_object_set_new(order, "items", items);

    const char *pay_sql =
        "SELECT id, txn_no, payment_method, amount_cents, denomination, "
        "status, failure_reason, external_ref, created_at "
        "FROM payment_transactions WHERE order_id = ? ORDER BY id ASC;";
    if (sqlite3_prepare_v2(g_db, pay_sql, -1, &stmt, NULL) != SQLITE_OK) {
        json_decref(order);
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询支付流水失败");
    }
    sqlite3_bind_int(stmt, 1, order_id);
    json_t *payments = json_array();
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *it = json_object();
        json_object_set_new(it, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(it, "txn_no",
                            json_string(safe_col_text(stmt, 1)));
        json_object_set_new(it, "payment_method",
                            json_string(safe_col_text(stmt, 2)));
        json_object_set_new(it, "amount_cents",
                            json_integer(sqlite3_column_int(stmt, 3)));
        json_object_set_new(it, "denomination",
                            json_string(safe_col_text(stmt, 4)));
        json_object_set_new(it, "status",
                            json_string(safe_col_text(stmt, 5)));
        const char *pfr = safe_col_text(stmt, 6);
        if (pfr && *pfr) {
            json_object_set_new(it, "failure_reason", json_string(pfr));
        }
        json_object_set_new(it, "external_ref",
                            json_string(safe_col_text(stmt, 7)));
        json_object_set_new(it, "created_at",
                            json_string(safe_col_text(stmt, 8)));
        json_array_append_new(payments, it);
    }
    sqlite3_finalize(stmt);
    json_object_set_new(order, "payment_transactions", payments);

    const char *chg_sql =
        "SELECT id, txn_no, request_amount_cents, actual_amount_cents, "
        "status, failure_reason, denomination_breakdown, note, created_at "
        "FROM change_transactions WHERE order_id = ? ORDER BY id ASC;";
    if (sqlite3_prepare_v2(g_db, chg_sql, -1, &stmt, NULL) != SQLITE_OK) {
        json_decref(order);
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询找零流水失败");
    }
    sqlite3_bind_int(stmt, 1, order_id);
    json_t *changes = json_array();
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *it = json_object();
        json_object_set_new(it, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(it, "txn_no",
                            json_string(safe_col_text(stmt, 1)));
        json_object_set_new(it, "request_amount_cents",
                            json_integer(sqlite3_column_int(stmt, 2)));
        json_object_set_new(it, "actual_amount_cents",
                            json_integer(sqlite3_column_int(stmt, 3)));
        json_object_set_new(it, "status",
                            json_string(safe_col_text(stmt, 4)));
        const char *cfr = safe_col_text(stmt, 5);
        if (cfr && *cfr) {
            json_object_set_new(it, "failure_reason", json_string(cfr));
        }
        json_object_set_new(it, "denomination_breakdown",
                            json_string(safe_col_text(stmt, 6)));
        json_object_set_new(it, "note", json_string(safe_col_text(stmt, 7)));
        json_object_set_new(it, "created_at",
                            json_string(safe_col_text(stmt, 8)));
        json_array_append_new(changes, it);
    }
    sqlite3_finalize(stmt);
    json_object_set_new(order, "change_transactions", changes);

    pthread_mutex_unlock(&g_db_mutex);
    return respond_success(connection, MHD_HTTP_OK, order);
}

static enum MHD_Result handle_order_list(struct MHD_Connection *connection,
                                         ConnectionInfo *ci) {
    (void)ci;
    int limit = parse_limit_query(connection);

    const char *status_filter =
        MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "status");
    int use_status = 0;
    if (status_filter != NULL && *status_filter != '\0') {
        use_status = 1;
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    int has_auth = authenticate_request(connection, &user, token_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql_all =
        "SELECT o.id, o.order_no, o.total_amount_cents, o.paid_amount_cents, "
        "o.change_amount_cents, o.status, o.payment_method, o.created_at, u.username "
        "FROM orders o "
        "LEFT JOIN users u ON u.id = o.operator_user_id "
        "ORDER BY o.id DESC LIMIT ?;";
    const char *sql_status =
        "SELECT o.id, o.order_no, o.total_amount_cents, o.paid_amount_cents, "
        "o.change_amount_cents, o.status, o.payment_method, o.created_at, u.username "
        "FROM orders o "
        "LEFT JOIN users u ON u.id = o.operator_user_id "
        "WHERE o.status = ? "
        "ORDER BY o.id DESC LIMIT ?;";

    if (sqlite3_prepare_v2(g_db, use_status ? sql_status : sql_all, -1,
                           &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        (void)has_auth;
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询订单列表失败");
    }
    int idx = 1;
    if (use_status) {
        sqlite3_bind_text(stmt, idx++, status_filter, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, idx, limit);

    json_t *items = json_array();
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *it = json_object();
        json_object_set_new(it, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(it, "order_no", json_string(safe_col_text(stmt, 1)));
        json_object_set_new(it, "total_amount_cents",
                            json_integer(sqlite3_column_int(stmt, 2)));
        json_object_set_new(it, "paid_amount_cents",
                            json_integer(sqlite3_column_int(stmt, 3)));
        json_object_set_new(it, "change_amount_cents",
                            json_integer(sqlite3_column_int(stmt, 4)));
        json_object_set_new(it, "status", json_string(safe_col_text(stmt, 5)));
        json_object_set_new(it, "payment_method",
                            json_string(safe_col_text(stmt, 6)));
        json_object_set_new(it, "created_at",
                            json_string(safe_col_text(stmt, 7)));
        json_object_set_new(it, "operator", json_string(safe_col_text(stmt, 8)));
        json_array_append_new(items, it);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(items);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取订单列表失败");
    }
    return respond_success(connection, MHD_HTTP_OK, items);
}

static enum MHD_Result handle_shift_settlement(struct MHD_Connection *connection,
                                                ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *start_time = NULL;
    const char *end_time = NULL;
    if (require_string_field(body, "start_time", 32, &start_time) != 0 ||
        require_string_field(body, "end_time", 32, &end_time) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "start_time/end_time 必填");
    }

    int actual_cash = 0;
    if (parse_int_field(body, "actual_cash_cents", 0, INT_MAX, &actual_cash) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "actual_cash_cents 必填且非负");
    }

    const char *note = optional_string_field(body, "note", 512);
    if (note == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "note 需为字符串且不超过512字符");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sales_sql =
        "SELECT COALESCE(SUM(total_amount_cents), 0), "
        "COALESCE(SUM(change_amount_cents), 0), COUNT(*) "
        "FROM orders "
        "WHERE created_at >= ? AND created_at <= ? "
        "AND status IN ('COMPLETED','CHANGE_FAILED','CHANGE_PENDING') "
        "AND payment_method IN ('COIN','BILL','MIXED');";
    if (sqlite3_prepare_v2(g_db, sales_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "统计销售数据失败");
    }
    sqlite3_bind_text(stmt, 1, start_time, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, end_time, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    int total_sales = 0;
    int total_change = 0;
    int order_count = 0;
    if (rc == SQLITE_ROW) {
        total_sales = sqlite3_column_int(stmt, 0);
        total_change = sqlite3_column_int(stmt, 1);
        order_count = sqlite3_column_int(stmt, 2);
    }
    sqlite3_finalize(stmt);

    const char *qr_sql =
        "SELECT COALESCE(SUM(amount_cents), 0) "
        "FROM payment_transactions "
        "WHERE created_at >= ? AND created_at <= ? "
        "AND payment_method = 'QR_CODE' AND status = 'SUCCESS';";
    if (sqlite3_prepare_v2(g_db, qr_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "统计扫码支付失败");
    }
    sqlite3_bind_text(stmt, 1, start_time, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, end_time, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int total_qr = 0;
    if (rc == SQLITE_ROW) {
        total_qr = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    const char *fail_sql =
        "SELECT COUNT(*) FROM change_transactions "
        "WHERE created_at >= ? AND created_at <= ? "
        "AND status IN ('FAILED','PARTIAL','CANCELLED','MANUAL_REFUND');";
    if (sqlite3_prepare_v2(g_db, fail_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "统计找零失败次数失败");
    }
    sqlite3_bind_text(stmt, 1, start_time, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, end_time, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int change_fail_count = 0;
    if (rc == SQLITE_ROW) {
        change_fail_count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    int expected_cash = total_sales - total_change;
    int difference = actual_cash - expected_cash;

    char shift_no[64];
    generate_txn_no("SHIFT", shift_no, sizeof(shift_no));

    const char *ins_sql =
        "INSERT INTO shift_settlements "
        "(shift_no, operator_user_id, start_time, end_time, "
        " expected_cash_cents, actual_cash_cents, difference_cents, "
        " total_sales_cents, total_change_cents, total_qr_sales_cents, "
        " order_count, change_failure_count, status, note) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'COMPLETED', ?);";
    if (sqlite3_prepare_v2(g_db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "盘点记录预编译失败");
    }
    sqlite3_bind_text(stmt, 1, shift_no, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, user.user_id);
    sqlite3_bind_text(stmt, 3, start_time, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, end_time, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, expected_cash);
    sqlite3_bind_int(stmt, 6, actual_cash);
    sqlite3_bind_int(stmt, 7, difference);
    sqlite3_bind_int(stmt, 8, total_sales);
    sqlite3_bind_int(stmt, 9, total_change);
    sqlite3_bind_int(stmt, 10, total_qr);
    sqlite3_bind_int(stmt, 11, order_count);
    sqlite3_bind_int(stmt, 12, change_fail_count);
    sqlite3_bind_text(stmt, 13, note, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建盘点记录失败");
    }

    int settlement_id = (int)sqlite3_last_insert_rowid(g_db);

    if (commit_transaction() != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交盘点事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "settlement_id", json_integer(settlement_id));
    json_object_set_new(data, "shift_no", json_string(shift_no));
    json_object_set_new(data, "expected_cash_cents", json_integer(expected_cash));
    json_object_set_new(data, "actual_cash_cents", json_integer(actual_cash));
    json_object_set_new(data, "difference_cents", json_integer(difference));
    json_object_set_new(data, "total_sales_cents", json_integer(total_sales));
    json_object_set_new(data, "total_change_cents", json_integer(total_change));
    json_object_set_new(data, "total_qr_sales_cents", json_integer(total_qr));
    json_object_set_new(data, "order_count", json_integer(order_count));
    json_object_set_new(data, "change_failure_count",
                        json_integer(change_fail_count));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_shift_list(struct MHD_Connection *connection,
                                         ConnectionInfo *ci) {
    (void)ci;
    int limit = parse_limit_query(connection);

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT s.id, s.shift_no, u.username, s.start_time, s.end_time, "
        "s.expected_cash_cents, s.actual_cash_cents, s.difference_cents, "
        "s.total_sales_cents, s.total_change_cents, s.total_qr_sales_cents, "
        "s.order_count, s.change_failure_count, s.status, s.created_at "
        "FROM shift_settlements s "
        "JOIN users u ON u.id = s.operator_user_id "
        "ORDER BY s.id DESC LIMIT ?;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询盘点记录失败");
    }
    sqlite3_bind_int(stmt, 1, limit);

    json_t *items = json_array();
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *it = json_object();
        json_object_set_new(it, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(it, "shift_no", json_string(safe_col_text(stmt, 1)));
        json_object_set_new(it, "operator", json_string(safe_col_text(stmt, 2)));
        json_object_set_new(it, "start_time", json_string(safe_col_text(stmt, 3)));
        json_object_set_new(it, "end_time", json_string(safe_col_text(stmt, 4)));
        json_object_set_new(it, "expected_cash_cents",
                            json_integer(sqlite3_column_int(stmt, 5)));
        json_object_set_new(it, "actual_cash_cents",
                            json_integer(sqlite3_column_int(stmt, 6)));
        json_object_set_new(it, "difference_cents",
                            json_integer(sqlite3_column_int(stmt, 7)));
        json_object_set_new(it, "total_sales_cents",
                            json_integer(sqlite3_column_int(stmt, 8)));
        json_object_set_new(it, "total_change_cents",
                            json_integer(sqlite3_column_int(stmt, 9)));
        json_object_set_new(it, "total_qr_sales_cents",
                            json_integer(sqlite3_column_int(stmt, 10)));
        json_object_set_new(it, "order_count",
                            json_integer(sqlite3_column_int(stmt, 11)));
        json_object_set_new(it, "change_failure_count",
                            json_integer(sqlite3_column_int(stmt, 12)));
        json_object_set_new(it, "status", json_string(safe_col_text(stmt, 13)));
        json_object_set_new(it, "created_at",
                            json_string(safe_col_text(stmt, 14)));
        json_array_append_new(items, it);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(items);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取盘点记录失败");
    }
    return respond_success(connection, MHD_HTTP_OK, items);
}

static enum MHD_Result route_health(struct MHD_Connection *connection,
                                    ConnectionInfo *ci) {
    (void)ci;
    return handle_health(connection);
}

static enum MHD_Result route_register(struct MHD_Connection *connection,
                                      ConnectionInfo *ci) {
    return handle_register(connection, ci);
}

static enum MHD_Result route_login(struct MHD_Connection *connection,
                                   ConnectionInfo *ci) {
    return handle_login(connection, ci);
}

static enum MHD_Result route_logout(struct MHD_Connection *connection,
                                    ConnectionInfo *ci) {
    (void)ci;
    return handle_logout(connection);
}

static enum MHD_Result route_auth_me(struct MHD_Connection *connection,
                                     ConnectionInfo *ci) {
    (void)ci;
    return handle_auth_me(connection);
}

static enum MHD_Result route_create_product(struct MHD_Connection *connection,
                                            ConnectionInfo *ci) {
    return handle_create_product(connection, ci);
}

static enum MHD_Result route_list_products(struct MHD_Connection *connection,
                                           ConnectionInfo *ci) {
    (void)ci;
    return handle_list_products(connection);
}

static enum MHD_Result route_inbound(struct MHD_Connection *connection,
                                     ConnectionInfo *ci) {
    return handle_inbound(connection, ci);
}

static enum MHD_Result route_sales(struct MHD_Connection *connection,
                                   ConnectionInfo *ci) {
    return handle_sales(connection, ci);
}

static enum MHD_Result route_inventory(struct MHD_Connection *connection,
                                       ConnectionInfo *ci) {
    (void)ci;
    return handle_inventory(connection);
}

static enum MHD_Result route_movements(struct MHD_Connection *connection,
                                       ConnectionInfo *ci) {
    (void)ci;
    return handle_movements(connection);
}

static enum MHD_Result route_create_order(struct MHD_Connection *connection,
                                          ConnectionInfo *ci) {
    return handle_create_order(connection, ci);
}

static enum MHD_Result route_payment(struct MHD_Connection *connection,
                                     ConnectionInfo *ci) {
    return handle_payment(connection, ci);
}

static enum MHD_Result route_dispense_change(struct MHD_Connection *connection,
                                             ConnectionInfo *ci) {
    return handle_dispense_change(connection, ci);
}

static enum MHD_Result route_change_exception(struct MHD_Connection *connection,
                                              ConnectionInfo *ci) {
    return handle_change_exception(connection, ci);
}

static enum MHD_Result route_cash_drawer_status(struct MHD_Connection *connection,
                                                ConnectionInfo *ci) {
    return handle_cash_drawer_status(connection, ci);
}

static enum MHD_Result route_cash_drawer_refill(struct MHD_Connection *connection,
                                                 ConnectionInfo *ci) {
    return handle_cash_drawer_refill(connection, ci);
}

static enum MHD_Result route_order_detail(struct MHD_Connection *connection,
                                          ConnectionInfo *ci) {
    return handle_order_detail(connection, ci);
}

static enum MHD_Result route_order_list(struct MHD_Connection *connection,
                                        ConnectionInfo *ci) {
    return handle_order_list(connection, ci);
}

static enum MHD_Result route_shift_settlement(struct MHD_Connection *connection,
                                               ConnectionInfo *ci) {
    return handle_shift_settlement(connection, ci);
}

static enum MHD_Result route_shift_list(struct MHD_Connection *connection,
                                        ConnectionInfo *ci) {
    return handle_shift_list(connection, ci);
}

static enum MHD_Result route_openapi_doc(struct MHD_Connection *connection,
                                         ConnectionInfo *ci);

static enum MHD_Result route_swagger_ui(struct MHD_Connection *connection,
                                        ConnectionInfo *ci) {
    (void)ci;
    return docs_send_swagger_ui(connection);
}

static enum MHD_Result route_home(struct MHD_Connection *connection,
                                  ConnectionInfo *ci) {
    (void)ci;
    return docs_send_home(connection);
}

static const ApiRoute g_api_routes[] = {
    {MHD_HTTP_METHOD_GET, "/", route_home, "Home", "服务首页", "System", 0, 0, 0},
    {MHD_HTTP_METHOD_GET, "/api/v1/health", route_health, "Health Check",
     "服务健康检查", "System", 0, 0, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/auth/register", route_register, "Create User",
     "创建用户（需管理员鉴权）", "Auth", 1, 1, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/auth/login", route_login, "Login",
     "用户登录并获取访问令牌", "Auth", 0, 1, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/auth/logout", route_logout, "Logout",
     "当前令牌退出登录", "Auth", 1, 0, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/auth/me", route_auth_me, "Current User",
     "获取当前登录用户信息", "Auth", 1, 0, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/products", route_create_product,
     "Create Product", "新增商品（管理员）", "Product", 1, 1, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/products", route_list_products, "List Products",
     "查询商品列表", "Product", 0, 0, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/inbound", route_inbound, "Inbound",
     "入库（进货）", "Inventory", 1, 1, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/sales", route_sales, "Sales",
     "销售出库", "Inventory", 1, 1, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/inventory", route_inventory, "Inventory Summary",
     "库存汇总与明细", "Inventory", 0, 0, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/movements", route_movements, "Movement History",
     "库存流水查询", "Inventory", 1, 0, 1},

    {MHD_HTTP_METHOD_POST, "/api/v1/orders", route_create_order, "Create Order",
     "创建订单", "Order", 1, 1, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/orders", route_order_list, "List Orders",
     "订单列表", "Order", 1, 0, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/order", route_order_detail, "Order Detail",
     "订单详情（含支付和找零流水）", "Order", 1, 0, 1},

    {MHD_HTTP_METHOD_POST, "/api/v1/payment", route_payment, "Payment",
     "支付（投币/纸币/扫码）", "Payment", 0, 1, 1},

    {MHD_HTTP_METHOD_POST, "/api/v1/change/dispense", route_dispense_change,
     "Dispense Change", "执行找零", "Change", 0, 1, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/change/exception", route_change_exception,
     "Change Exception", "找零异常处理（卡币/取消/人工补退）", "Change", 1, 1, 1},

    {MHD_HTTP_METHOD_GET, "/api/v1/cash-drawer", route_cash_drawer_status,
     "Cash Drawer Status", "找零盒状态", "CashDrawer", 1, 0, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/cash-drawer/refill", route_cash_drawer_refill,
     "Refill Cash Drawer", "补充找零盒", "CashDrawer", 1, 1, 1},

    {MHD_HTTP_METHOD_POST, "/api/v1/shift/settlement", route_shift_settlement,
     "Shift Settlement", "收班盘点", "Shift", 1, 1, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/shift/settlements", route_shift_list,
     "Shift Settlement List", "盘点记录列表", "Shift", 1, 0, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/openapi.json", route_openapi_doc,
     "OpenAPI Document", "自动生成的 OpenAPI 文档", "System", 0, 0, 1},
    {MHD_HTTP_METHOD_GET, "/docs", route_swagger_ui, "Swagger UI",
     "Swagger 交互式文档页面", "System", 0, 0, 1},
};

static const size_t g_api_routes_count =
    sizeof(g_api_routes) / sizeof(g_api_routes[0]);

static enum MHD_Result route_openapi_doc(struct MHD_Connection *connection,
                                         ConnectionInfo *ci) {
    (void)ci;
    return docs_send_openapi(connection, g_api_routes, g_api_routes_count);
}

static enum MHD_Result handle_options(struct MHD_Connection *connection) {
    struct MHD_Response *response =
        MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
    if (response == NULL) {
        return MHD_NO;
    }

    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Headers",
                            "Content-Type, Authorization");
    MHD_add_response_header(response, "Access-Control-Allow-Methods",
                            "GET, POST, OPTIONS");

    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_NO_CONTENT, response);
    MHD_destroy_response(response);
    return ret;
}

static enum MHD_Result route_request(struct MHD_Connection *connection,
                                     const char *url, const char *method,
                                     ConnectionInfo *ci) {
    if (strcmp(method, MHD_HTTP_METHOD_OPTIONS) == 0) {
        return handle_options(connection);
    }

    for (size_t i = 0; i < g_api_routes_count; ++i) {
        if (strcmp(method, g_api_routes[i].method) == 0 &&
            strcmp(url, g_api_routes[i].path) == 0) {
            return g_api_routes[i].handler(connection, ci);
        }
    }

    return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND", "接口不存在");
}

static enum MHD_Result request_handler(void *cls,
                                       struct MHD_Connection *connection,
                                       const char *url, const char *method,
                                       const char *version,
                                       const char *upload_data,
                                       size_t *upload_data_size, void **con_cls) {
    (void)cls;
    (void)version;

    ConnectionInfo *ci = (ConnectionInfo *)(*con_cls);
    if (ci == NULL) {
        ci = (ConnectionInfo *)calloc(1, sizeof(ConnectionInfo));
        if (ci == NULL) {
            return MHD_NO;
        }
        *con_cls = ci;
        return MHD_YES;
    }

    if (is_method_with_body(method) && *upload_data_size != 0) {
        if (append_body(ci, upload_data, *upload_data_size) != 0) {
            *upload_data_size = 0;
            return respond_error(connection, MHD_HTTP_CONTENT_TOO_LARGE,
                                "PAYLOAD_TOO_LARGE", "请求体超过限制");
        }

        *upload_data_size = 0;
        return MHD_YES;
    }

    if (ci->processed) {
        return MHD_YES;
    }
    ci->processed = 1;

    return route_request(connection, url, method, ci);
}

static void request_completed_callback(void *cls, struct MHD_Connection *connection,
                                       void **con_cls,
                                       enum MHD_RequestTerminationCode toe) {
    (void)cls;
    (void)connection;
    (void)toe;

    ConnectionInfo *ci = (ConnectionInfo *)(*con_cls);
    if (ci != NULL) {
        free(ci->body);
        free(ci);
        *con_cls = NULL;
    }
}

static void load_config(void) {
    g_cfg.port = env_to_int("PORT", DEFAULT_PORT);
    g_cfg.session_ttl_hours =
        env_to_int("SESSION_TTL_HOURS", DEFAULT_SESSION_TTL_HOURS);
    g_cfg.db_path = getenv("DB_PATH");
    if (g_cfg.db_path == NULL || *g_cfg.db_path == '\0') {
        g_cfg.db_path = DEFAULT_DB_PATH;
    }

    g_cfg.key_file = getenv("USER_DATA_KEY_FILE");
    if (g_cfg.key_file == NULL || *g_cfg.key_file == '\0') {
        g_cfg.key_file = DEFAULT_KEY_FILE;
    }
}

int main(void) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    load_config();

    if (sodium_init() < 0) {
        fprintf(stderr, "[FATAL] libsodium 初始化失败\n");
        return 1;
    }

    if (db_init() != 0) {
        fprintf(stderr, "[FATAL] 数据库初始化失败\n");
        return 1;
    }

    if (load_or_create_key() != 0) {
        fprintf(stderr, "[FATAL] 用户字段加密密钥初始化失败\n");
        sqlite3_close(g_db);
        return 1;
    }

    if (ensure_default_admin_user() != 0) {
        fprintf(stderr, "[FATAL] 默认管理员初始化失败\n");
        sqlite3_close(g_db);
        return 1;
    }

    if (ensure_seed_stock_movement_consistency() != 0) {
        fprintf(stderr, "[FATAL] 种子库存流水修复失败\n");
        sqlite3_close(g_db);
        return 1;
    }

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD, (uint16_t)g_cfg.port, NULL, NULL,
        &request_handler, NULL, MHD_OPTION_NOTIFY_COMPLETED,
        request_completed_callback, NULL, MHD_OPTION_END);

    if (daemon == NULL) {
        fprintf(stderr, "[FATAL] HTTP 服务启动失败\n");
        sqlite3_close(g_db);
        return 1;
    }

    fprintf(stdout,
            "[INFO] 服务启动成功\n"
            "[INFO] 端口: %d\n"
            "[INFO] 数据库: %s\n"
            "[INFO] 会话时长(小时): %d\n",
            g_cfg.port, g_cfg.db_path, g_cfg.session_ttl_hours);

    while (g_running) {
        sleep(1);
    }

    MHD_stop_daemon(daemon);
    sqlite3_close(g_db);
    pthread_mutex_destroy(&g_db_mutex);

    fprintf(stdout, "[INFO] 服务已停止\n");
    return 0;
}
