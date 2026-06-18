cmake_minimum_required(VERSION 3.16)
project(jinxiaocun_backend_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)
pkg_check_modules(JANSSON REQUIRED jansson)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

add_executable(
  jinxiaocun-server
  src/main.c
  src/http/response.c
  src/docs/docs_ui.c
)

target_include_directories(jinxiaocun-server PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${MICROHTTPD_INCLUDE_DIRS}
  ${JANSSON_INCLUDE_DIRS}
  ${SODIUM_INCLUDE_DIRS}
  ${SQLITE3_INCLUDE_DIRS}
)

target_compile_options(jinxiaocun-server PRIVATE
  -Wall
  -Wextra
  -Wpedantic
)

target_link_directories(jinxiaocun-server PRIVATE
  ${MICROHTTPD_LIBRARY_DIRS}
  ${JANSSON_LIBRARY_DIRS}
  ${SODIUM_LIBRARY_DIRS}
  ${SQLITE3_LIBRARY_DIRS}
)

target_link_libraries(jinxiaocun-server PRIVATE
  ${MICROHTTPD_LIBRARIES}
  ${JANSSON_LIBRARIES}
  ${SODIUM_LIBRARIES}
  ${SQLITE3_LIBRARIES}
  pthread
)
