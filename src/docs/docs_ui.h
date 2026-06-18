#ifndef DOCS_UI_H
#define DOCS_UI_H

#include <microhttpd.h>

#include "../http/routes_meta.h"

enum MHD_Result docs_send_openapi(struct MHD_Connection *connection,
                                  const ApiRoute *routes,
                                  size_t route_count);

enum MHD_Result docs_send_swagger_ui(struct MHD_Connection *connection);

enum MHD_Result docs_send_home(struct MHD_Connection *connection);

#endif
