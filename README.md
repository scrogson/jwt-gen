# JWT Generator

This is a basic JWT generator based on HS512 and some hard-coded claims for my
needs.

## Usage

### Encode

```
USAGE:
    jwt encode [OPTIONS] --key <key>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -A, --alg <alg>    JWT algorithm. [env: ALG=]  [default: HS512]  [possible values: HS256, HS384, HS512, RS256,
                       RS384, RS512, ES256, ES384, ES512]
    -a, --aud <aud>     [env: AUD=]
    -i, --iss <iss>     [env: ISS=]
    -k, --key <key>     [env: KEY=]
    -s, --sub <sub>     [env: SUB=]
```

### Decode

Not implemented yet.

## TODO

- [x] Add CLI options instead of environment variables
- [ ] Make algorithm configurable
- [ ] Support RSA public key signing/verification
- [ ] Custom derive to encode/decode claims
