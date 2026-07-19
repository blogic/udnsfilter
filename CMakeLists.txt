cmake_minimum_required(VERSION 3.10)
project(udnsfilter C)

add_compile_options(-Os -ggdb -Wall -Werror --std=gnu11 -Wmissing-declarations -Wno-unused-parameter)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

# Find required libraries
find_path(ubox_include_dir NAMES libubox/uloop.h)
find_path(ubus_include_dir NAMES libubus.h)
find_path(ucode_include_dir NAMES ucode/module.h)
find_package(CURL REQUIRED)

# Use c-ares from source tree
set(CARES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/c-ares")
set(CARES_INCLUDE_DIR "${CARES_DIR}/include" "${CARES_DIR}")
set(CARES_LIBRARY "${CARES_DIR}/lib/libcares.so")

include_directories(
	${ubox_include_dir}
	${ubus_include_dir}
	${ucode_include_dir}
	${CARES_INCLUDE_DIR}
	${CURL_INCLUDE_DIRS}
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_library(ubox NAMES ubox)
find_library(ubus NAMES ubus)
find_library(blobmsg_json NAMES blobmsg_json)
find_library(ucode NAMES ucode)

set(LIBS ${ubox} ${ubus} ${blobmsg_json} ${ucode} ${CARES_LIBRARY} ${CURL_LIBRARIES} resolv)

# C binding module sources
set(BINDING_SOURCES
	src/module.c
	src/packet.c
	src/socket.c
	src/tcp.c
	src/resolver.c
	src/filter.c
	src/callback.c
	src/util.c
	src/privilege.c
)

# Build ucode module (udnsfilter.so)
add_library(udnsfilter MODULE ${BINDING_SOURCES})
set_target_properties(udnsfilter PROPERTIES
	OUTPUT_NAME udnsfilter
	PREFIX ""
	LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
target_link_libraries(udnsfilter ${LIBS})
target_compile_definitions(udnsfilter PRIVATE
	DOH_PROXY_PATH="${CMAKE_INSTALL_PREFIX}/bin/doh_proxy"
)

# Build doh_proxy standalone executable
add_executable(doh_proxy
	src/doh_proxy.c
	src/privilege.c
)
target_link_libraries(doh_proxy ${ubox} ${CURL_LIBRARIES})

# Installation
install(TARGETS udnsfilter
	LIBRARY DESTINATION lib/ucode
)

install(TARGETS doh_proxy
	RUNTIME DESTINATION bin
)

install(PROGRAMS
	udnsfilter
	DESTINATION bin
)

install(PROGRAMS
	files/usr/libexec/udnsfilter-update
	DESTINATION libexec
)

install(FILES
	lib/udnsfilter/config.uc
	lib/udnsfilter/filter.uc
	lib/udnsfilter/tracking.uc
	DESTINATION share/ucode/udnsfilter
)

# Testing
if(UNIT_TESTING)
	enable_testing()
	add_subdirectory(tests)
endif()
