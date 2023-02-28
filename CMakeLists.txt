cmake_minimum_required (VERSION 3.0)
project (otls)
set(NAME "otls")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

find_package(emp-zk REQUIRED)
include_directories(${EMP-ZK_INCLUDE_DIRS})


ENABLE_TESTING()
ADD_SUBDIRECTORY(test)

add_subdirectory(notary)
