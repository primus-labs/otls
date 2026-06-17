cmake_minimum_required (VERSION 3.0)
project (otls)
set(NAME "otls")

IF(DEFINED EMP_UPSTREAM_ROOT)
  # FULLPORT: upstream emp-toolkit via EXPLICIT paths (install-up ships no cmake
  # configs / emp-base.cmake). No emp arch flags needed — upstream headers are
  # portable on arm64 (validated: `clang++ -std=c++20` compiles+links the full
  # stack, see migration/FULLPORT_LOG.md Phase 4). emp-ot is now a real .a.
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  find_package(OpenSSL REQUIRED)
  include_directories(${OPENSSL_INCLUDE_DIR})
  # FULLPORT: vendored emp-tool headers the migration needs but upstream-from-source
  # does not produce (emp::Backend, fork BristolFormat, + 3 path-placeholders). Listed
  # FIRST so the flat `emp-tool/...` includes resolve here; runtime headers come from
  # install-up. Makes the build reproducible without patching external emp repos.
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/emp-compat/include)
  include_directories(${EMP_UPSTREAM_ROOT}/include)
  set(EMP-TOOL_INCLUDE_DIRS ${EMP_UPSTREAM_ROOT}/include)
  set(EMP-OT_INCLUDE_DIRS   ${EMP_UPSTREAM_ROOT}/include)
  set(EMP-ZK_INCLUDE_DIRS   ${EMP_UPSTREAM_ROOT}/include)
  # link order: zk -> ot -> tool (static, callee after caller); tool carries openssl.
  set(EMP-ZK_LIBRARIES   ${EMP_UPSTREAM_ROOT}/lib/libemp-zk.a)
  set(EMP-OT_LIBRARIES   ${EMP_UPSTREAM_ROOT}/lib/libemp-ot.a)
  set(EMP-TOOL_LIBRARIES ${EMP_UPSTREAM_ROOT}/lib/libemp-tool.a ${OPENSSL_LIBRARIES})
  # FULLPORT: replicate emp-tool's PUBLIC SIMD arch floor (we consume emp via explicit
  # paths, not the cmake target). x86_64/g++ otherwise can't inline emp's AES-NI/SSSE3
  # always_inline intrinsics. arm64/clang needs none. See pado/CMakeLists.txt for detail.
  add_compile_options(-Wno-ignored-attributes)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64|i.86)")
    add_compile_options(-march=native)
  endif()
ELSEIF(ENABLE_WASM)
  set(CMAKE_FOLDER ${CMAKE_INSTALL_PREFIX})
  include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

  find_package(OpenSSL REQUIRED)
  include_directories(${OPENSSL_INCLUDE_DIR})

  set(EMP-TOOL_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
  set(EMP-TOOL_LIBRARIES ${CMAKE_INSTALL_PREFIX}/lib/libemp-tool.a ${OPENSSL_LIBRARIES})
  include_directories(${EMP-TOOL_INCLUDE_DIRS})

  set(EMP-OT_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
  set(EMP-OT_LIBRARIES "")
  include_directories(${EMP-OT_INCLUDE_DIRS})

  set(EMP-ZK_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
  set(EMP-ZK_LIBRARIES ${CMAKE_INSTALL_PREFIX}/lib/libemp-zk.a)
  include_directories(${EMP-ZK_INCLUDE_DIRS})
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
option(LOAD_CIRCUIT_FROM_MEM "" OFF)
IF(LOAD_CIRCUIT_FROM_MEM)
  add_definitions(-DLOAD_CIRCUIT_FROM_MEM=1)
  list(APPEND sources
    cipher/circuit_files/aes128_ks_data.cpp
    cipher/circuit_files/aes128_with_ks_data.cpp
  )
ENDIF()
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
target_link_libraries(otls ${EMP-ZK_LIBRARIES} ${EMP-OT_LIBRARIES} ${EMP-TOOL_LIBRARIES} dl)

install(FILES cmake/otls-config.cmake DESTINATION cmake/)
install(TARGETS otls DESTINATION lib)

# FULLPORT: under the upstream build, pado consumes otls headers from the 3rd/otls
# SOURCE tree (it needs compat/primus_compat.h, which is not installed). Installing
# backend/cipher/protocol into ${prefix}/include would put a SECOND copy on pado's
# path and double-define (e.g. GateType). So skip the header install upstream.
IF(NOT DEFINED EMP_UPSTREAM_ROOT)
  install(DIRECTORY backend cipher protocol DESTINATION include)
ENDIF()

option(ENABLE_OTLS_TEST "otls test" ON)
IF(ENABLE_OTLS_TEST)
  ENABLE_TESTING()
  ADD_SUBDIRECTORY(test)
ENDIF()
