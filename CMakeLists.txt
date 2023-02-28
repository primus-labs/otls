cmake_minimum_required (VERSION 3.0)
project (pado)
set(NAME "pado")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

find_package(emp-zk REQUIRED)
include_directories(${EMP-ZK_INCLUDE_DIRS})

# Installation
# install(FILES cmake/emp-sh2pc-config.cmake DESTINATION cmake/)
# install(DIRECTORY emp-sh2pc DESTINATION include/)


#aux_source_directory(prf PRF_SRC)
#include_directories(prf)

#add_executable(test_hmac "test/hmac.cpp" ${PRF_SRC})
#target_link_libraries(test_hmac ${EMP-TOOL_LIBRARIES} ${EMP-OT_LIBRARIES})

#add_executable(test_tlsprf "test/tlsprf.cpp" ${PRF_SRC})
#target_link_libraries(test_tlsprf ${EMP-TOOL_LIBRARIES} ${EMP-OT_LIBRARIES})

ENABLE_TESTING()
ADD_SUBDIRECTORY(test)

add_subdirectory(mpc_tls)
