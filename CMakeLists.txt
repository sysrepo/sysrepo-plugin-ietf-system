project(sysrepo-plugin-ietf-system C)
cmake_minimum_required(VERSION 3.0)

include(GNUInstallDirs)

find_package(PkgConfig)
pkg_check_modules(SYSREPO REQUIRED libsysrepo)

set(CMAKE_CFLAGS "-Wall -pedantic -O2 ${CMAKE_CFLAGS}")

add_definitions(${SYSREPO_CFLAGS})
include_directories(${SYSREPO_INCLUDE_DIRS})
link_directories(${SYSREPO_LIBRARY_DIRS})

set(YANG_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/iana-crypt-hash.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/ietf-netconf-acm.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/ietf-system.yang
)
add_custom_target(YANG_files ${YANG_SRCS})

add_library(sysrepo-plugin-ietf-system SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/system-plugin.c
)
target_link_libraries(sysrepo-plugin-ietf-system ${SYSREPO_LIBRARIES})

set(YANG_DIR ${CMAKE_INSTALL_PREFIX}/share/sysrepo/yang)

# get sysrepo plugins directory
if (NOT SR_PLUGINS_DIR)
    if (PKG_CONFIG_FOUND)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=SR_PLUGINS_DIR" "libsysrepo" OUTPUT_VARIABLE SR_PLUGINS_DIR)
        string(STRIP ${SR_PLUGINS_DIR} SR_PLUGINS_DIR)
    endif()
endif()
if (NOT SR_PLUGINS_DIR)
    message(FATAL_ERROR "Cannot get sysrepo plugins directory due to missing pkg-config, set SR_PLUGINS_DIR manually.")
endif()

install(FILES ${YANG_SRCS} DESTINATION ${YANG_DIR})
install(TARGETS sysrepo-plugin-ietf-system DESTINATION ${SR_PLUGINS_DIR})
install(CODE "MESSAGE(STATUS
\"To enable this plugin, run:

 - sysrepoctl --install --yang ${YANG_DIR}/ietf-system.yang
 - sysrepoctl -m ietf-system -e timezone-name
 - systemctl restart sysrepo-plugind
\")")
