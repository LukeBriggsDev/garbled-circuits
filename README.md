# Garbled Circuits Framework
This is a proof-of-concept Rust implementation of Multi-Party Computation and Oblivious transfer protocols in Rust using post-quantum primitives.

Programs are written using [`garble-lang`](https://github.com/sine-fdn/garble-lang), and example programs can be found in `programs/`.

## Compilation
`cargo build -r`

## Example usage
`./oblivious programs/arithmetic.garble.rs 99i64 88i64`