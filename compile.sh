#! /bin/bash
mkdir -p build
cd build
cmake ../
make VERBOSE=1
sudo make install

cp bin/otls_server ../mpc_tls_test/
cp bin/otls_client ../mpc_tls_test/
cp bin/otls_pado ../mpc_tls_test/

