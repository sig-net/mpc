# GCP gRPC Bindings

MPC Recovery runs on GCP and hence needs to interact with its API. Unfortunately, there is no official GCP Rust API/SDK and the only other option is to use raw gRPC services. This module contains these gRPC bindings, but only for services required by MPC Recovery. Proto files are pulled from a git submodule for [googleapis](https://github.com/googleapis/googleapis) (remember to initialize it if you are compiling this project locally). gRPC code is generated using [tonic](https://github.com/hyperium/tonic).
