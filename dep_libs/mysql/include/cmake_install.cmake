# Install script for directory: /home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include

# Set the install prefix
IF(NOT DEFINED CMAKE_INSTALL_PREFIX)
  SET(CMAKE_INSTALL_PREFIX "/usr/local/mysql")
ENDIF(NOT DEFINED CMAKE_INSTALL_PREFIX)
STRING(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
IF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  IF(BUILD_TYPE)
    STRING(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  ELSE(BUILD_TYPE)
    SET(CMAKE_INSTALL_CONFIG_NAME "RelWithDebInfo")
  ENDIF(BUILD_TYPE)
  MESSAGE(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
ENDIF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)

# Set the component getting installed.
IF(NOT CMAKE_INSTALL_COMPONENT)
  IF(COMPONENT)
    MESSAGE(STATUS "Install component: \"${COMPONENT}\"")
    SET(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  ELSE(COMPONENT)
    SET(CMAKE_INSTALL_COMPONENT)
  ENDIF(COMPONENT)
ENDIF(NOT CMAKE_INSTALL_COMPONENT)

# Install shared libraries without execute permission?
IF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  SET(CMAKE_INSTALL_SO_NO_EXE "1")
ENDIF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Development")
  FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/mysql.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/mysql_com.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_command.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/mysql_time.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_list.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_alloc.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/typelib.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/binary_log_types.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_dbug.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/m_string.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_sys.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_xml.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/mysql_embed.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_thread.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_thread_local.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/decimal.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/errmsg.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_global.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_getopt.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/sslopt-longopts.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_dir.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/sslopt-vars.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/sslopt-case.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/sql_common.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/keycache.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/m_ctype.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_compiler.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/mysql_com_server.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_byteorder.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/byte_order_generic.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/byte_order_generic_x86.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/little_endian.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/big_endian.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/thr_cond.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/thr_mutex.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/thr_rwlock.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/mysql_version.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/my_config.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/mysqld_ername.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/mysqld_error.h"
    "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/sql_state.h"
    )
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Development")

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Development")
  FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/mysql" TYPE DIRECTORY FILES "/home/wilesduan/work/github/mysql-connector-c-6.1.9-src/include/mysql/" REGEX "/[^/]*\\.h$" REGEX "/psi\\_abi[^/]*$" EXCLUDE)
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Development")

