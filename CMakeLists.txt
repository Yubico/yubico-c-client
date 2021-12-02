cmake_minimum_required(VERSION 3.14.4)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_C_STANDARD 11)
project(yubico-c-client)

#------------------------------------------------------------------ ykclient lib
# Configure file
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

# Get all normal library files
file(
	GLOB ykclient_SOURCES
	ykclient_server_response.c ykclient.c ykclient_version.c
	hmac.c sha1.c usha.c sha224-256.c sha384-512.c
	cencode.c cdecode.c
)

file(
	GLOB ykclient_HEADERS_PUBLIC
	ykclient_server_response.h ykclient.h ykclient_errors.h
)
file(GLOB ykclient_HEADERS_PRIVATE sha.h sha-private.h cencode.h cdecode.h)

list(APPEND ykclient_HEADERS_PUBLIC "${CMAKE_BINARY_DIR}/ykclient_version.h")
add_library(
	ykclient STATIC
	${ykclient_SOURCES} ${ykclient_HEADERS_PUBLIC} ${ykclient_HEADERS_PRIVATE}
)
add_library(ykclient::ykclient ALIAS ykclient)

if(MINGW)
	# For statically linking curl
	target_compile_definitions(ykclient PRIVATE CURL_STATICLIB)
	# Missing stuff in MinGW headers
	target_compile_definitions(ykclient PRIVATE srandom=srand random=rand)
endif()
find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)
target_link_libraries(ykclient PUBLIC CURL::libcurl ZLIB::ZLIB)
if(MINGW)
  target_link_libraries(ykclient PUBLIC wsock32 ws2_32 crypt32 wldap32)
endif()

target_compile_definitions(ykclient PRIVATE PACKAGE="yubico-c-client" PACKAGE_VERSION="${VERSION}")
target_include_directories(ykclient PUBLIC
	$<INSTALL_INTERFACE:include/ykclient>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>
)
set_target_properties(ykclient PROPERTIES PUBLIC_HEADER "${ykclient_HEADERS_PUBLIC}")

if(HAVE_LD_VERSION_SCRIPT)
	target_link_options(ykclient PRIVATE -Wl,--version-script=$(srcdir)/libykclient.map)
else()
	target_link_options(ykclient PRIVATE -export-symbols-regex '^ykclient_.*')
endif()

include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/ykclient)

install(TARGETS ykclient
	EXPORT ykclient-targets
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ykclient
)

# Export the targets to a script
install(EXPORT ykclient-targets
	FILE ykclientTargets.cmake
	NAMESPACE ykclient::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ykclient
)

# Generate config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
	${CMAKE_CURRENT_LIST_DIR}/cmake/ykclientConfig.cmake.in
	${CMAKE_CURRENT_BINARY_DIR}/ykclientConfig.cmake
	INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

# Install config file
install(FILES
	${CMAKE_CURRENT_BINARY_DIR}/ykclientConfig.cmake
	DESTINATION ${INSTALL_CONFIGDIR}
)

export(
	EXPORT ykclient-targets
	FILE ${CMAKE_CURRENT_BINARY_DIR}/ykclientTargets.cmake
	NAMESPACE ykclient::
)

# Register package in user's package registry
export(PACKAGE ykclient)

#----------------------------------------------------------------- ykclient tool
file(GLOB ykclient_tool_SOURCES tool.c)
add_executable(ykclient-tool ${ykclient_tool_SOURCES})
target_compile_definitions(ykclient-tool PRIVATE VERSION="${VERSION}")
target_link_libraries(ykclient-tool ykclient)
set_target_properties(ykclient-tool PROPERTIES OUTPUT_NAME ykclient)
