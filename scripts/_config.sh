#!/bin/bash
target=${1:-"local"} # local, wasm

curdir=$(pwd)
uname_s=$(uname -s)
echo "===== compile target: ${target}, on ${uname_s} ====="
#######################################################################
#######################################################################
builddir=${curdir}/build
if [ "${target}" = "wasm" ]; then
  builddir=${curdir}/build_${target}
fi
build_type=Debug
build_type=Release
installdir=${curdir}/install
scripts_dir=${curdir}/scripts
logs_dir=${builddir}/logs
mkdir -p ${logs_dir}
#######################################################################
#######################################################################
pado_emp_dir=${curdir}/../pado-emp
pado_emp_prefix_path=${pado_emp_dir}/build
if [ "${target}" = "wasm" ]; then
  pado_emp_prefix_path=${pado_emp_dir}/build_${target}
fi
