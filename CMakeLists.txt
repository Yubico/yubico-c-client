cmake_minimum_required(VERSION 3.14.4)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_C_STANDARD 11)
project(yubico-c-client)

file(
	GLOB libykclient_la_SOURCES
	ykclient_server_response.h ykclient_server_response.c
	ykclient.h ykclient_errors.h
	ykclient.c ykclient_version.c
	sha.h sha-private.h hmac.c sha1.c usha.c sha224-256.c sha384-512.c
	cencode.h cencode.c cdecode.h cdecode.c
)

add_library(ykclient STATIC ${libykclient_la_SOURCES})
target_compile_definitions(ykclient PRIVATE PACKAGE="yubico-c-client" PACKAGE_VERSION=${VERSION})
target_include_directories(ykclient PUBLIC ${CMAKE_CURRENT_LIST_DIR})
if(HAVE_LD_VERSION_SCRIPT)
	target_link_options(ykclient PRIVATE -Wl,--version-script=$(srcdir)/libykclient.map)
else()
	target_link_options(ykclient PRIVATE -export-symbols-regex '^ykclient_.*')
endif()

# TODO: load version major/minor/patch from somewhere
set(YKCLIENT_VERSION_MAJOR 2)
set(YKCLIENT_VERSION_MINOR 16)
set(YKCLIENT_VERSION_PATCH 0)
set(VERSION "${YKCLIENT_VERSION_MAJOR}.${YKCLIENT_VERSION_MINOR}.${YKCLIENT_VERSION_PATCH}")
math(
	EXPR YKCLIENT_VERSION_NUMBER
	"(${YKCLIENT_VERSION_MAJOR} << 24) | (${YKCLIENT_VERSION_MINOR} << 16) | (${YKCLIENT_VERSION_PATCH} << 8)"
	OUTPUT_FORMAT HEXADECIMAL
)
configure_file(ykclient_version.h.in ykclient_version.h)
target_sources(ykclient PRIVATE ykclient_version.h)
target_include_directories(ykclient PUBLIC ${CMAKE_BINARY_DIR})

if(MINGW)
	# For statically linking zlib
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif()
find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)
target_link_libraries(ykclient PUBLIC CURL::libcurl ${ZLIB_LIBRARIES})

if(MINGW)
	target_compile_definitions(ykclient PRIVATE srandom=srand random=rand -DCURL_STATICLIB)
  target_link_libraries(ykclient PUBLIC wsock32 ws2_32 crypt32 wldap32)
endif()

# ykclient tool
file(GLOB ykclient_SOURCES tool.c)
add_executable(ykclient-tool ${ykclient_SOURCES})
target_compile_definitions(ykclient-tool PRIVATE VERSION="${VERSION}")
target_link_libraries(ykclient-tool ykclient)
set_target_properties(ykclient-tool PROPERTIES OUTPUT_NAME ykclient)
