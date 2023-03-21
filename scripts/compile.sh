#!/bin/bash
. ./scripts/_config.sh local

ossl_root=${pado_emp_dir}/deps/install
#
# compile pado-emp
# ######################
echo "compile pado-emp"
cd ${pado_emp_dir}
bash ./scripts/compile.sh
cd ${curdir}

#
#
# ######################
echo "compile otls"
cd ${curdir}
mkdir -p ${builddir}
cd ${builddir}

cmake .. \
  -DCMAKE_INSTALL_PREFIX=${builddir} \
  -DCMAKE_PREFIX_PATH=${pado_emp_prefix_path} \
  -DCMAKE_BUILD_TYPE=${build_type}
  -DOPENSSL_INCLUDE_DIR=${ossl_root}/include \
  -DOPENSSL_SSL_LIBRARY=${ossl_root}/lib/libssl.a \
  -DOPENSSL_CRYPTO_LIBRARY=${ossl_root}/lib/libcrypto.a
make -j8
# make install

cd ${curdir}
exit 0
