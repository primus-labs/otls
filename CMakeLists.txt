cmake_minimum_required (VERSION 3.0)
project (pado)
set(NAME "pado")


# IF(${CMAKE_SYSTEM_PROCESSOR} MATCHES "(aarch64)|(arm64)|(x86_64)")
# find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
# include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
# 
# find_package(emp-ot REQUIRED)
# include_directories(${EMP-OT_INCLUDE_DIRS})
# 
# find_package(emp-zk REQUIRED)
# include_directories(${EMP-ZK_INCLUDE_DIRS})
# ELSE()
# find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
set(CMAKE_FOLDER ${CMAKE_PREFIX_PATH})
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
# find_package(emp-tool REQUIRED)
# include_directories(${EMP-TOOL_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(EMP-TOOL_INCLUDE_DIRS ${CMAKE_PREFIX_PATH}/include)
set(EMP-TOOL_LIBRARIES ${CMAKE_PREFIX_PATH}/lib/libemp-tool.a ${OPENSSL_LIBRARIES})
include_directories(${EMP-TOOL_INCLUDE_DIRS})

set(EMP-OT_INCLUDE_DIRS ${CMAKE_PREFIX_PATH}/include)
set(EMP-OT_LIBRARIES ${CMAKE_PREFIX_PATH}/lib/libemp-tool.a ${OPENSSL_LIBRARIES})
include_directories(${EMP-OT_INCLUDE_DIRS})

set(EMP-ZK_INCLUDE_DIRS ${CMAKE_PREFIX_PATH}/include)
set(EMP-ZK_LIBRARIES ${CMAKE_PREFIX_PATH}/lib/libemp-tool.a ${CMAKE_PREFIX_PATH}/lib/libemp-zk.a ${OPENSSL_LIBRARIES})
include_directories(${EMP-ZK_INCLUDE_DIRS})


# set(NO_WARN_FLAGS "-Wno-unused-function -Wno-unused-command-line-argument")
# set(CCFLAGS "-msimd128 -msse -msse2 -msse4.1 -msse4.2 -s ASSERTIONS=1")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NO_WARN_FLAGS} ${CCFLAGS}")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${NO_WARN_FLAGS} ${CCFLAGS}")
# ENDIF()


ENABLE_TESTING()
# ADD_SUBDIRECTORY(test)
