#! /bin/bash
curdir=`pwd`
builddir=${curdir}/build
installdir=${curdir}/install
mkdir -p ${builddir} ${installdir}

# Compile Pado SSL
if [ ! -f "${installdir}/lib/libcrypto.a" ]; then
  cd ${curdir}/pssl
  ./config --prefix=${installdir} -no-shared 
  make -j4
  make install
fi


# Compile otls
mkdir -p build
cd ${curdir}/build
cmake ..
make -j4

# publish
cd ${curdir}
mkdir -p ${curdir}/demo
cp build/bin/otls_client ${curdir}/demo
cp build/bin/otls_pado ${curdir}/demo
