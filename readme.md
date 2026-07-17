# POSecure: Evaluating RAG-Based Vulnerability Repair on Realistic TypeScript Repositories

This repository contains the source code, scripts, and configuration files used in the empirical study described in our paper submitted to SBES Main Track. The study evaluates five RAG-based techniques for automatic vulnerability repair (a No RAG baseline, the original SOSecure, two variants of our adaptation POSecure with extractive and abstractive prompt compression, and a CVEfixes-derived variation) on the OWASP Juice Shop, applied at two model scales: Llama 3.1 8B (locally via Ollama) and Llama 3.3 70B (on Oracle Cloud Infrastructure).

## Repository Structure

The pipeline is organized as a sequence of numbered scripts that should be executed in order.

```
.
├── 0_prepare_environment.sh                  # Initial environment setup
├── 1_1_get_datasource_sosecure.py            # Build SO discussions datasource
├── 1_2_show_total_datasource_sosecure.py     # Inspect SO datasource size
├── 1_3_get_datasource_cvefixes.py            # Build CVEfixes datasource (TS/JS subset)
├── 1_4_show_total_datasource_cvefixes.py     # Inspect CVEfixes datasource size
├── 2_1_qdrant_docker_command.sh              # Start Qdrant via Docker
├── 2_2_populate_qdrant_sosecure.py           # Populate Qdrant with SO discussions
├── 2_3_populate_qdrant_cvefixes.py           # Populate Qdrant with CVEfixes data
├── 2_4_test_qdrant_rag_sosecure.py           # Sanity-check retrieval (SO)
├── 2_5_test_qdrant_rag_cvefixes.py           # Sanity-check retrieval (CVEfixes)
├── 3_1_retrieve_so_discussions.py            # Retrieve and cache SO context per function
├── 3_2_compress_discussions_extractive.py    # Apply extractive compression (LLMLingua-2)
├── 3_3_compress_discussions_abstractive.py   # Apply abstractive compression (Llama 3.2 3B)
├── 3_4_retrieve_cvefixes_functions.py        # Retrieve and cache CVEfixes context per function
├── 3_5_get_token_metrics_from_contexts.py    # Compute token statistics for the cached contexts
├── 3_6_generate_corrections.py               # Run patch generation (all treatments)
├── 4_1_sonarqube_docker_command.sh           # Start SonarQube via Docker
├── 4_2_security_tests_all.py                 # Run SAST/code quality evaluation
├── codeql_scanner.py                         # CodeQL wrapper used by the security pipeline
├── end_to_end_example.py                     # Generates a text file containing an end to end example (input for figure of supplementary material)
├── end_to_end_example.txt                    # Output of end_to_end_example.py
├── llm_client.py                             # LLM client (Ollama and OCI providers)
├── utils.py                                  # Shared utilities
├── requirements.txt                          # Python dependencies
├── test_long_llm_lingua.py                   # Standalone test for LongLLMLingua usage
├── test_oci_auth.py                          # Standalone test for OCI authentication
├── data-filtering-scripts/                   # Scripts to generate the SOSecure datasource
│                                             # from the Stack Exchange data dump
└── type-extractor/                           # Node.js server that exposes the
                                              # 1-hop dependency graph extractor
```

The `data-filtering-scripts/` directory contains the scripts used to generate the SOSecure datasource from the Stack Exchange data dump. The `type-extractor/` directory contains a Node.js server that implements the 1-hop dependency graph extractor used by all treatments to retrieve type signatures of imported symbols.

## Required External Data

Two external datasets must be downloaded and placed in specific locations before running the pipeline:

### Stack Exchange Data Dump

Download the Stack Overflow (subset of Stack Exchange) data dump from December 31, 2025 from the [Internet Archive](https://archive.org/details/stackexchange) and place its contents inside `data-filtering-scripts/`.

### CVEfixes Dataset

Download CVEfixes version **1.0.8** from the [official Zenodo record](https://zenodo.org/records/13118970). Create a directory called `cve_fixes/` at the repository root and place the dataset inside it:

```
cve_fixes/
└── CVEfixes_v1.0.8/
    └── Data/
        └── CVEfixes.db
```

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.11 | Pipeline scripts |
| Node.js | 24.x | Juice Shop build, type-extractor server |
| npm | (bundled with Node 24) | Dependency installation |
| Docker | recent | Qdrant, SonarQube, Sonar Scanner |
| CodeQL CLI | recent | SAST analysis |
| Ollama | v0.20.0 | Local model serving |
| Oracle Cloud Infrastructure account | --- | Llama 3.3 70B inference (optional, only for cloud runs) |

The `0_prepare_environment.sh` script automates most of the setup. Python dependencies are pinned in `requirements.txt`.

## Environment Variables

Create a `.env` file at the repository root with as a clone of `.env.example` file and replace the variables with yours.

Use `test_oci_auth.py` to validate OCI credentials before running the cloud pipeline.

## Auxiliary Scripts

- `test_long_llm_lingua.py` — Standalone script used during development to evaluate LongLLMLingua compression behavior. Not part of the main pipeline.
- `test_oci_auth.py` — Standalone script that verifies whether the OCI credentials in your environment are valid before running cloud-based experiments.

## Acknowledgments

This repository accompanies a paper accepted in SBES 2026 - Research Track. Generative AI tools were used during the preparation of the paper and the development of this pipeline; details are disclosed in the paper's Acknowledgments section.
