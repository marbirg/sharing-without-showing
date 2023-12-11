# Sharing without Showing
This repository contains the prototype showing the concepts presented in the paper 'Sharing without Showing: Securing IoT Data with Trusted Execution Environments'

It consists of two main parts:

## attested_tls
This part contains the code intended to run on the server.
This part contains both code to be run in a secure enclave using the Open Enclave framework, as well as an equivalent part that runs directly on the host cpu.
More details can be found in the corresponding [README.md](attested_tls/README.md)

## client
This part contains code for benchmarking functions implemented in the above part.

For more information and instructions on how to build and run, see respective folders README.

