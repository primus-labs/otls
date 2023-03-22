# sudo apt install libssl-dev


echo ${LD_LIBRARY_PATH}
echo "compile server"
g++ -ggdb3 server.cpp  -L../build/mpc_tls -L../pado-emp/build/lib -L../pado-emp/deps/install/lib -ggdb -lotls -lemp-tool -lemp-zk -lssl -lcrypto -pthread -ldl -o server -I../ -I../pado-emp/deps/install/include
echo "compile client"
g++  -ggdb3 client.cpp   -L../build/mpc_tls -L../pado-emp/build/lib -L../pado-emp/deps/install/lib -ggdb -lotls -lemp-tool -lemp-zk -lssl -lcrypto -pthread -ldl -o client -I../ -I../pado-emp/deps/install/include
echo "compile pado"
g++ -ggdb3 pado.cpp  -L../build/mpc_tls -L../pado-emp/build/lib -L../pado-emp/deps/install/lib -ggdb -lotls -lemp-tool -lemp-zk -lssl -lcrypto -pthread -ldl -o pado -I../ -I../pado-emp/deps/install/include


