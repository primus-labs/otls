#!/bin/bash
curdir=$(pwd)
builddir=${curdir}/build
installdir=${curdir}/install
mkdir -p ${builddir} ${installdir}

build_type=${1:-"Release"}
enable_threading=ON
enable_test=ON

#######################################################################
#######################################################################

# ######################
repo=otls
# ######################

#
#
# ######################
echo "compile ${repo}"
repo_dir=${curdir}/${repo}
if [ -d ${repo_dir} ]; then
  mkdir -p ${builddir}/${repo}
  cd ${builddir}/${repo}

  cmake ${repo_dir} \
    -DTHREADING=${enable_threading} \
    -DENABLE_OTLS_TEST=${enable_test} \
    -DCMAKE_INSTALL_PREFIX=${installdir} \
    -DCMAKE_PREFIX_PATH=${installdir} \
    -DCMAKE_BUILD_TYPE=${build_type}
  make -j4
  make install
else
  echo "${repo} not exist!"
fi

cd ${curdir}
exit 0
