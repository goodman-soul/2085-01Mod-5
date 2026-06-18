#ifndef ROUTES_META_H
#define ROUTES_META_H

#include <microhttpd.h>

typedef struct {
    char *body;
    size_t body_size;
    int processed;
} ConnectionInfo;

typedef enum MHD_Result (*RouteHandlerFn)(struct MHD_Connection *connection,
                                          ConnectionInfo *ci);

typedef struct {
    const char *method;
    const char *path;
    RouteHandlerFn handler;
    const char *summary;
    const char *description;
    const char *tag;
    int requires_auth;
    int has_request_body;
    int include_in_openapi;
} ApiRoute;

#endif
