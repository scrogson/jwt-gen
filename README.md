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
    -a, --aud <aud>    Audience claim [env: AUD=]
    -i, --iss <iss>    Issuer claim [env: ISS=]
    -k, --key <key>    The secret key which is used to sign the token.

                       In the case for HMAC based tokens, this should be a raw secret. In the case for RS/EC algorithms,
                       a file path to the private key is expected. [env: KEY=]
    -s, --sub <sub>    Subject claim [env: SUB=]
```

### Decode

Not implemented yet.

## Generating private/public key for RS algorithms:

### RS256

```
ssh-keygen -t rsa -b 2048 -f RS256.key
# Don't add passphrase
openssl rsa -in RS256.key -pubout -outform PEM -out RS256.pub
```

### RS512

```
ssh-keygen -t rsa -b 4096 -f RS512.key
# Don't add passphrase
openssl rsa -in RS512.key -pubout -outform PEM -out RS512.pub
```

## TODO

- [x] Add CLI options instead of environment variables
- [x] Make algorithm configurable
- [x] Support RSA public key signing/verification
- [ ] Custom derive to encode/decode claims
