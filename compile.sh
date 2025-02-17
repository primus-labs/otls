#!/bin/bash
if [ $# -ne 1 ]; then
    echo "Usage: $0 \${path_to_primus_emp}"
    exit 1;
fi

primus_emp_dir=$1
primus_emp_installdir=${primus_emp_dir}/install

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
repo_dir=${curdir}
mkdir -p ${builddir}/${repo}
cd ${builddir}/${repo}

cmake ${repo_dir} \
  -DTHREADING=${enable_threading} \
  -DENABLE_OTLS_TEST=${enable_test} \
  -DCMAKE_INSTALL_PREFIX=${installdir} \
  -DCMAKE_PREFIX_PATH=${primus_emp_installdir} \
  -DCMAKE_BUILD_TYPE=${build_type}
make -j4
make install

cd ${curdir}
exit 0
