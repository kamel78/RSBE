# Recursive Shamir-Based Encryption (RSBE): A Hybrid Post-Quantum Symmetric Scheme for Scalable and Secure Cloud Data Protection

**Author:** Kamel Mohamed Faraoun  
**Affiliation:** Computer Science Department, EEDIS Laboratory,  
Djilalli Liabbes University, Sidi Bel Abbès, Algeria  
*kamel.faraoun@univ-sba.dz*

##  Overview

This repository provides the official Rust implementation and experimental benchmarking framework accompanying the research paper  
**“Recursive Shamir-Based Encryption (RSBE): A Hybrid Post-Quantum Symmetric Scheme for Scalable and Secure Cloud Data Protection.”** RSBE introduces a **recursive encryption model** derived from **Shamir’s Secret Sharing**, achieving **hybrid post-quantum security** by combining:
- **Information-theoretic secrecy** for the majority of ciphertext blocks, and  
- **Computational security** for a single terminal block protected by a pseudorandom permutation (PRP).

This design ensures strong quantum resistance, high throughput, and excellent scalability for **cloud**, **distributed**, and **high-performance cryptographic systems**.

## Key Features

-  **Recursive Shamir-based construction:** hierarchical encryption through layered secret sharing.  
-  **Hybrid post-quantum security:** perfect secrecy for intermediate layers + PRP-based computational protection.  
-  **Optimized finite-field operations:** efficient Vandermonde matrix updates and dual inversion.  
-  **Parallel execution:** multi-threaded encoding/decoding using the [`rayon`](https://crates.io/crates/rayon) crate.  
-  **Configurable parameters:** threshold \( t_{\min} \), recursion depth, and PRP choice (AES, Camellia, Aria, CAST, RC5, XTEA).  
-  **Rust-native safety:** strong memory safety and zero-cost concurrency.


## Benchmarking Framework

The repository includes a full benchmarking suite to compare **RSBE** with traditional block cipher modes (CBC, CTR).  
Metrics include **throughput**, **latency**, **parallel scalability**, and **security sensitivity** under varying configurations.

### Evaluated Modes
- `AES-CBC`  
- `AES-CTR`  
- `RSBE (Proposed)`

### Supported PRPs
- `AES`, `Camellia`, `Aria`, `CAST`, `RC5`, `XTEA`

## Benchmark Categories

| Option | Benchmark Type | Description |
|:------:|----------------|-------------|
| (1) | Threshold Optimization | Measures the impact of \( t_{\min} \) on encryption throughput. |
| (2) | Runtime (128-bit) | Compares RSBE with CBC/CTR using 128-bit PRPs. |
| (3) | Runtime (256-bit) | Same as above for 256-bit PRPs (post-quantum scaling). |
| (4) | Parallel Scalability | Evaluates performance with 1–32 threads using Rayon. |
| (5) | Avalanche and SAC | Tests ciphertext sensitivity to key and IV variations. |

## How to Build and Run

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- Cargo (build system)
- `rayon` and `rand` crates (auto-installed)

### Build and Execute
```bash
git clone https://github.com/kamel78/RSBE.git
cd rsbe
cargo run --release
```

## License

This project is released under the **MIT License**.  
You are free to use, modify, and distribute it with appropriate citation to the original paper.


## Author
**FARAOUN Kamel Mohamed**  
Security and Multimedia Research Team  
Computer Science Department, EEDIS Laboratory,  
Djilalli Liabbes University, Sidi Bel Abbès, Algeria  
*kamel.faraoun@univ-sba.dz*  
