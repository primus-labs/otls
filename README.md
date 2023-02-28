
## Overview



## Dependencies

Run the following commands to install `emp libraries`:

```bash
wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python install.py --deps --tool --ot --zk
```

## Compile


- Compile General TLS Server.

```bash
./compile_tls_server.sh
```


- Compile Pado Server and Pado Client.

```bash
./compile_otls.sh
```


## Test

First of all, run the following commands once to generate ssl certificates:


```bash
cd certs
./gen.sh
```

<br/>

Run `TLS Server`:

```bash
./demo/tls_server
```

Run `Pado Server`:

```bash
./demo/otls_pado
```

Run `Pado Client`:

```bash
./demo/otls_client
```