cmake_minimum_required (VERSION 3.0)
project (otls)
set(NAME "otls")

IF(ENABLE_WASM)
  set(CMAKE_FOLDER ${CMAKE_PREFIX_PATH})
  include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

  find_package(OpenSSL REQUIRED)
  include_directories(${OPENSSL_INCLUDE_DIR})

  set(EMP-TOOL_INCLUDE_DIRS ${CMAKE_PREFIX_PATH}/include)
  set(EMP-TOOL_LIBRARIES ${CMAKE_PREFIX_PATH}/lib/libemp-tool.a ${OPENSSL_LIBRARIES})
  include_directories(${EMP-TOOL_INCLUDE_DIRS})

  set(EMP-OT_INCLUDE_DIRS ${CMAKE_PREFIX_PATH}/include)
  set(EMP-OT_LIBRARIES "")
  include_directories(${EMP-OT_INCLUDE_DIRS})

  set(EMP-ZK_INCLUDE_DIRS ${CMAKE_PREFIX_PATH}/include)
  set(EMP-ZK_LIBRARIES ${CMAKE_PREFIX_PATH}/lib/libemp-zk.a)
  include_directories(${EMP-ZK_INCLUDE_DIRS})

  set(NO_WARN_FLAGS "-Wno-unused-function -Wno-unused-command-line-argument")
  set(CCFLAGS "-msimd128 -msse -msse2 -msse4.1 -msse4.2 -s ASSERTIONS=1")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NO_WARN_FLAGS} ${CCFLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${NO_WARN_FLAGS} ${CCFLAGS}")
ELSE()
  find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
  include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

  find_package(emp-ot REQUIRED)
  include_directories(${EMP-OT_INCLUDE_DIRS})

  find_package(emp-zk REQUIRED)
  include_directories(${EMP-ZK_INCLUDE_DIRS})
ENDIF()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(sources
  backend/switch.cpp
  cipher/utils.cpp
)
option(USE_PRIMUS_EMP "use primus emp" OFF)
IF(USE_PRIMUS_EMP)
  add_definitions(-DUSE_PRIMUS_EMP=1)
ENDIF()
add_compile_options(-fPIC)
IF(USE_PRIMUS_EMP)
add_library(otls ${sources})
ELSE()
add_library(otls SHARED ${sources})
ENDIF()
target_link_libraries(otls ${EMP-TOOL_LIBRARIES} ${EMP-ZK_LIBRARIES} dl)

install(FILES cmake/otls-config.cmake DESTINATION cmake/)
install(TARGETS otls DESTINATION lib)

install(DIRECTORY backend cipher protocol DESTINATION include)

option(ENABLE_OTLS_TEST "otls test" ON)
IF(ENABLE_OTLS_TEST)
  ENABLE_TESTING()
  ADD_SUBDIRECTORY(test)
ENDIF()
