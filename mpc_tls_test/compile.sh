# sudo apt install libssl-dev

# OPENSSL_PATH=/home/ubuntu/test_openssl/install_openssl/
# OTLS_PATH=/home/ubuntu/test_openssl/otls/
# export LD_LIBRARY_PATH=${OPENSSL_PATH}/lib/:/usr/local/lib/
# export LIBRARY_PATH=${OPENSSL_PATH}/lib/
# export CPLUS_INCLUDE_PATH=${OPENSSL_PATH}/include/
# OPENSSL_PATH=${OPENSSL_PATH}/lib/
# MPC_TLS_PATH=${OTLS_PATH}/build/mpc_tls/

echo ${LD_LIBRARY_PATH}
echo "compile server"
g++ -ggdb3 server.cpp  -L../build/mpc_tls -lotls -lssl -lcrypto -pthread -ldl -o server -I../
echo "compile client"
g++  -ggdb3 client.cpp   -L../build/mpc_tls -L../../pado-emp/build/lib -L../../install_openssl/lib -lotls -lemp-tool -lssl -lcrypto -pthread -ldl -o client -I../ -I../../install_openssl/include
echo "compile pado"
g++ -ggdb3 pado.cpp  -L../build/mpc_tls -L../../pado-emp/build/lib -L../../install_openssl/lib -lotls -lemp-tool -lssl -lcrypto -pthread -ldl -o pado -I../ -I../../install_openssl/include


