#!/bin/bash
. ./scripts/_config.sh wasm

ossl_root=${pado_emp_dir}/deps/install
PWD=`pwd`
ossl_root=${PWD}/../install_emopenssl

#
# compile pado-emp
# ######################
echo "compile pado-emp(wasm)"
cd ${pado_emp_dir}
bash ./scripts/compile_wasm.sh
cd ${curdir}

#
#
# ######################
echo "compile otls(wasm)"
cd ${curdir}
mkdir -p ${builddir}
cd ${builddir}

EMCC_CFLAGS="-O3 -s WASM=1"

# sse* simd
SIMD_CFLAGS=" -msimd128"
EMCC_CFLAGS+=${SIMD_CFLAGS}

# WebSocket/POSIX Socket
SOCKET_FLAGS=" -lwebsocket.js -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD"
# EMCC_CFLAGS+=${SOCKET_FLAGS}

export EMCC_CFLAGS=${EMCC_CFLAGS}
echo "EMCC_CFLAGS: ${EMCC_CFLAGS}"

# -DCMAKE_CROSSCOMPILING_EMULATOR=$NODE_HOME/bin/node
emcmake cmake ${curdir}/${repo} \
  -DCMAKE_INSTALL_PREFIX=${builddir} \
  -DCMAKE_PREFIX_PATH=${pado_emp_prefix_path} \
  -DCMAKE_BUILD_TYPE=${build_type} \
  -DOPENSSL_INCLUDE_DIR=${ossl_root}/include \
  -DOPENSSL_SSL_LIBRARY=${ossl_root}/lib/libssl.a \
  -DOPENSSL_CRYPTO_LIBRARY=${ossl_root}/lib/libcrypto.a
emmake make -j8 VERBOSE=1
make install

cd ${curdir}
bash ./scripts/compile.sh websocket_io

exit 0

