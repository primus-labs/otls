#!/bin/bash
. ./scripts/_config.sh local

WEBSOCKET_IO=0
if [ $# -eq  1 ] && [ "$1" == "websocket_io" ]; then
    WEBSOCKET_IO=1
fi
 
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

echo "websocket io ${WEBSOCKET_IO}"
cmake .. \
  -DCMAKE_INSTALL_PREFIX=${builddir} \
  -DCMAKE_PREFIX_PATH=${pado_emp_prefix_path} \
  -DCMAKE_BUILD_TYPE=${build_type} \
  -DWEBSOCKET_IO=${WEBSOCKET_IO}
make -j8
make install

cd ${curdir}
exit 0
