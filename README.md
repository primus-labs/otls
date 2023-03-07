
<<<<<<< HEAD
3. download file `https://github.com/pado-labs/otls/blob/xjq/install.sh`
4. execute the following commands
   ```bash
   $ chmod +x install.sh
   $ ./install.sh
   ```

# Generate TLS certificate
   execute the following commands
   ```bash
   $ cd otls/mpc_tls_test
   $ ./gen.sh
   ```

## Test
=======
## Overview


## Dependenices

When compiling to wasm, please ref [here](./pado-emp/docs/INSTALL.md) to install emcc and node.


## Compile (non-WebAssembly)

```sh
bash ./scripts/compile.sh
```


## Compile (WebAssembly)

```sh
bash ./scripts/compile_wasm.sh
```

## Test (non-WebAssembly)

>>>>>>> origin/main

* If you want to test the code in local machine, type

   `./run ./build/bin/[binaries] 12345 [more opts]`

* IF you want to test the code over two machine, type

  `./build/bin/[binaries] 1 12345 [more opts]` on one machine and 
  
  `./build/bin/[binaries] 2 12345 [more opts]` on the other.
  
  IP addresses are hardcoded in the test files.

* example_semi_honest should run as 
<<<<<<< HEAD
    `./bin/example 1 12345 123 & ./bin/example 2 12345 124`
    
    because different parties need different numbers

## TLS Test
1. open a terminal and execute as following steps to start server
   ```bash
   $ cd otls
   $ ./mpc_tls_test/otls_server
   ```

2. open a terminal and execute as following steps to start pado
   ```bash
   $ cd otls
   $ ./mpc_tls_test/otls_pado
   ```

3. open a terminal and execute as following steps to start client
   ```bash
   $ cd otls
   $ ./mpc_tls_test/client
   ```

=======

	`./build/bin/example 1 12345 123 & ./build/bin/example 2 12345 124`
	
	because different parties need different numbers
>>>>>>> origin/main
