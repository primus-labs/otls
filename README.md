
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


* If you want to test the code in local machine, type

   `./run ./build/bin/[binaries] 12345 [more opts]`

* IF you want to test the code over two machine, type

  `./build/bin/[binaries] 1 12345 [more opts]` on one machine and 
  
  `./build/bin/[binaries] 2 12345 [more opts]` on the other.
  
  IP addresses are hardcoded in the test files.

* example_semi_honest should run as 

	`./build/bin/example 1 12345 123 & ./build/bin/example 2 12345 124`
	
	because different parties need different numbers
