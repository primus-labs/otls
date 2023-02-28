
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


- Compile Notary Server and Notary Client.

```bash
./compile_notary.sh
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

Run `Notary Server`:

```bash
./demo/notary_server
```

Run `Notary Client`:

```bash
./demo/notary_client
```