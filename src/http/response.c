#include "response.h"

#include <stdlib.h>
#include <string.h>

enum MHD_Result send_json_response(struct MHD_Connection *connection,
                                   unsigned int status, json_t *payload) {
    char *body = json_dumps(payload, JSON_COMPACT);
    json_decref(payload);
    if (body == NULL) {
        return MHD_NO;
    }

    struct MHD_Response *response =
        MHD_create_response_from_buffer(strlen(body), body, MHD_RESPMEM_MUST_FREE);

    if (response == NULL) {
        free(body);
        return MHD_NO;
    }

    MHD_add_response_header(response, "Content-Type", "application/json; charset=utf-8");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Headers",
                            "Content-Type, Authorization");
    MHD_add_response_header(response, "Access-Control-Allow-Methods",
                            "GET, POST, OPTIONS");

    enum MHD_Result ret = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return ret;
}

enum MHD_Result send_text_response(struct MHD_Connection *connection,
                                   unsigned int status,
                                   const char *content_type,
                                   const char *body) {
    if (body == NULL) {
        body = "";
    }

    const size_t body_len = strlen(body);
    char *payload = (char *)malloc(body_len + 1);
    if (payload == NULL) {
        return MHD_NO;
    }
    memcpy(payload, body, body_len + 1);

    struct MHD_Response *response =
        MHD_create_response_from_buffer(body_len, payload, MHD_RESPMEM_MUST_FREE);
    if (response == NULL) {
        free(payload);
        return MHD_NO;
    }

    MHD_add_response_header(response, "Content-Type", content_type);
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Headers",
                            "Content-Type, Authorization");
    MHD_add_response_header(response, "Access-Control-Allow-Methods",
                            "GET, POST, OPTIONS");

    enum MHD_Result ret = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return ret;
}

enum MHD_Result respond_error(struct MHD_Connection *connection,
                              unsigned int status, const char *code,
                              const char *message) {
    json_t *root = json_object();
    json_t *err = json_object();
    json_object_set_new(root, "success", json_false());
    json_object_set_new(err, "code", json_string(code));
    json_object_set_new(err, "message", json_string(message));
    json_object_set_new(root, "error", err);
    return send_json_response(connection, status, root);
}

enum MHD_Result respond_success(struct MHD_Connection *connection,
                                unsigned int status, json_t *data) {
    json_t *root = json_object();
    json_object_set_new(root, "success", json_true());
    if (data == NULL) {
        json_object_set_new(root, "data", json_null());
    } else {
        json_object_set_new(root, "data", data);
    }
    return send_json_response(connection, status, root);
}
