#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <jansson.h>
#include <microhttpd.h>

enum MHD_Result send_json_response(struct MHD_Connection *connection,
                                   unsigned int status, json_t *payload);

enum MHD_Result send_text_response(struct MHD_Connection *connection,
                                   unsigned int status,
                                   const char *content_type,
                                   const char *body);

enum MHD_Result respond_error(struct MHD_Connection *connection,
                              unsigned int status, const char *code,
                              const char *message);

enum MHD_Result respond_success(struct MHD_Connection *connection,
                                unsigned int status, json_t *data);

#endif
