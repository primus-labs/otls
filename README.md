## Installation
### Install Emp-Toolkit
`otls` is dependent on `emp-toolkit`. If you have installed `emp-toolkit`, you can skip this section. Otherwise, follow the below instructions.
1. `wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py`
2. `python install.py --deps --tool --ot --zk`
    1. You can use `--ot=[release]` to install a particular branch or release
    2. By default it will build for Release. `-DCMAKE_BUILD_TYPE=[Release|Debug]` option is also available.
    3. No sudo? Change [`CMAKE_INSTALL_PREFIX`](https://cmake.org/cmake/help/v2.8.8/cmake.html#variable%3aCMAKE_INSTALL_PREFIX).

### Install OTLS
1. `wget https://raw.githubusercontent.com/primus-labs/otls/main/install.sh`
2. `bash install.sh`

## Introduction
`otls` provides primitive building blocks for proving `TLS` with `IZK` without leaking private information. Currently, it has implemented `SHA256` and `AES128-GCM`. In other words, it can prove TLS 1.2 with two cipher suites: `ECDHE-RSA-AES128-GCM-SHA256` and `ECDHE-ECDSA-AES128-GCM-SHA256`. It has two proving models, `Proxy Model` and `MPC Model`.
### Proxy Model
In this model, Prover connects to data source server via Verifier. Prover proves to Verifier that he knowns the AES keys with IZK. Since Verifier can record all the data flowing between Prover and Data Source Server, it can check the ciphertext of the output of AEAD encryptions.
For how to integate this model, you can refer to the test case located in `test/prove_proxy_tls.cpp`.

### MPC Model
In this model, Prover and Verifier jointly form `TLS Client`, execute TLS Handshake and TLS Query using garble circuit and oblivious transfer. From the respective of Data Source Server, there is no difference between the joint TLS Client and traditional TLS Client. To enforce security, Verifier sits between Prover and Data Source Server and all the data flowing between the Prover and Data Source Server should be transfered by Verifier. similar with the Proxy Model.

Note there are some optimizations in this model:
- ENABLE-OFFLINE-ONLINE. If offline-online is enabled, offline can be executed withouting providing the actual requests to the Data Source Server. In this way, when the requests are provided, the online phase is started and will consume much time.
- ENABLE-OPT-ROUNDS. If opt-rounds is enabled, it will take fewer rounds when executing HMAC in TLS Handshake. However, it will send/recv more data. Think twice before enabling opt-rounds.

For how to integate this model without enabling offline-online, you can refer to the test case located in `test/protocol.cpp`.
For how to integate this model with offline-online enabled, you can refer to the test case located in `test/prot_on_off.cpp`.

## Test
All the test cases are located in the directory `test`.

* If you want to test the code in local machine, type

   `./run ./bin/[binaries] 12345 [more opts]`
* IF you want to test the code over two machine, type

  `./bin/[binaries] 1 12345 [more opts]` on one machine and 
  
  `./bin/[binaries] 2 12345 [more opts]` on the other.
  
  IP addresses are hardcoded in the test files.

* example_semi_honest should run as 
    `./bin/example 1 12345 123 & ./bin/example 2 12345 124`
    
    because different parties need different numbers
