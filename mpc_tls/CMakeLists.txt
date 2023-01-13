cmake_minimum_required(VERSION 3.0)
project(otls)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

add_library(otls SHARED mpc_tls.cpp)
target_include_directories(otls PUBLIC ${PROJECT_SOURCE_DIRECTORY}/../../install_openssl/include/)
target_link_libraries(otls PUBLIC ${EMP-OT_LIBRARIES})

install(TARGETS otls DESTINATION lib)

# list(APPEND EXTRA_LIBS crypto)
# target_link_libraries(mpc_tls PUBLIC ${EXTRA_LIBS})
