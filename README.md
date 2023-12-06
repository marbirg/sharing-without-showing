
This repository contains code to show a proof-of-concept for how to use a TEE to securly compute aggregations over multiple mutually distrusting users data.

It consists of two main parts:

## attested_tls
This part contains the code intended to run on the server.
This part contains both code to be run in a secure enclave using the Open Enclave framework, as well as an equivalent part that runs directly on the host cpu.

## client
This part contains code for benchmarking functions implemented in the above part.

For more information and instructions on how to build and run, see respective folders README.

