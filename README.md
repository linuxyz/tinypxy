# TinyPxy

A tiny HTTP+SOCKS5 proxy on the same TCP:port. 
*tinypxy* is acting as HTTP and SOCKS5 proxy without Authentication!!!

*Using as your own risk!*

## Building with Cargo

[Cargo][cargo] -- Rust's package manager, is used to build and test this
project. If you don't have Cargo installed, we suggest getting it via
<https://rustup.rs/>.

For release build: 
`cargo build -r`

## Run with Cargo

Start the *tinypxy* and listen on TCP:8081
 `cargo run 0.0.0.0:8081`

or execute the *tinypxy* execution directly.
 `tinypxy 0.0.0.0:1080` 

# License
*tinypxy* is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See LICENSE-APACHE and LICENSE-MIT for details.

<!-- refs -->
[cargo]: https://github.com/rust-lang/cargo/