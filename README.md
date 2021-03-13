# Rust RSA

### How to Run

1. clone this repo
2. cd into the repo folder
3. install Docker
4. run `docker run --rm --user "$(id -u)":"$(id -g)" -v "$PWD:/usr/src/myapp" -w /usr/src/myapp rust cargo build --release && ./target/release/rust-rsa`
