cmake_minimum_required(VERSION 3.16)

# ------------------------------------------------------------
#  libpki – 一份顶层 CMakeLists.txt 即可编译全部目标
# ------------------------------------------------------------
project(libpki C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 可通过 -DCMAKE_BUILD_TYPE=Release 或 Debug 控制
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ----------------------------------------------------------------------------
# 依赖库
# ----------------------------------------------------------------------------
find_package(Threads REQUIRED)

# 使用 pkg-config 查找其余库
find_package(PkgConfig REQUIRED)
pkg_check_modules(MHD REQUIRED libmicrohttpd)
pkg_check_modules(ZLOG REQUIRED zlog)
pkg_check_modules(JSONC REQUIRED json-c)
pkg_check_modules(CURL REQUIRED libcurl)

# 备选项：手动指定OpenSSL库
add_library(OpenSSL::Crypto SHARED IMPORTED)
set_target_properties(OpenSSL::Crypto PROPERTIES
  IMPORTED_LOCATION /usr/local/openssl/lib64/libcrypto.so.3
  INTERFACE_INCLUDE_DIRECTORIES /usr/local/openssl/include
)

# 设置运行时库搜索路径，确保使用自定义的OpenSSL库
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH "/usr/local/openssl/lib64")

# ----------------------------------------------------------------------------
# 包含目录与编译选项
# ----------------------------------------------------------------------------
include_directories(
  ${PROJECT_SOURCE_DIR}/include
  ${MHD_INCLUDE_DIRS}
  ${ZLOG_INCLUDE_DIRS}
  ${JSONC_INCLUDE_DIRS}
)

add_compile_options(-Wall -Wno-sign-compare -Wno-maybe-uninitialized -Wno-unused-result -Wno-sometimes-uninitialized)

# ----------------------------------------------------------------------------
# 项目静态库libpki
# ----------------------------------------------------------------------------
file(GLOB LIBPKI_SRC
     "${PROJECT_SOURCE_DIR}/src/*.c")

add_library(libpki STATIC ${LIBPKI_SRC})

target_link_libraries(libpki
  PUBLIC
    OpenSSL::Crypto
    Threads::Threads
)

# ----------------------------------------------------------------------------
# 可执行文件: CA 服务器
# ----------------------------------------------------------------------------
add_executable(ca server/ca-server/ca.c)

target_link_libraries(ca
  PRIVATE
    libpki
    ${MHD_LIBRARIES}
    ${ZLOG_LIBRARIES}
)

set_target_properties(ca PROPERTIES
  OUTPUT_NAME ca
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/server/ca-server)

# ----------------------------------------------------------------------------
# 可执行文件: User 客户端
# ----------------------------------------------------------------------------
add_executable(user server/user-client/user.c)

target_link_libraries(user
  PRIVATE
    libpki
    ${CURL_LIBRARIES}
)

set_target_properties(user PROPERTIES
  OUTPUT_NAME user
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/server/user-client)

# ----------------------------------------------------------------------------
# 可执行文件: ca_web
# ----------------------------------------------------------------------------
add_executable(caweb caweb.c)

target_link_libraries(caweb
  PRIVATE
    libpki
    ${MHD_LIBRARIES}
    ${JSONC_LIBRARIES}
    Threads::Threads
    OpenSSL::Crypto
)

# 输出目录与别名
set_target_properties(caweb PROPERTIES
  OUTPUT_NAME caweb
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

# ----------------------------------------------------------------------------
# 可执行文件: cert_parser
# ----------------------------------------------------------------------------
add_executable(cert_parser cert_parser.c)

target_link_libraries(cert_parser
  PRIVATE
    libpki
    OpenSSL::Crypto
)

set_target_properties(cert_parser PROPERTIES
  OUTPUT_NAME cert_parser
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})
