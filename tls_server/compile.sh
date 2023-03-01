#! /bin/bash
curdir=`pwd`
builddir=${curdir}/build
mkdir -p ${builddir}


mkdir -p ${builddir}
cd ${builddir}
cmake ..
make -j4
