# Sharing without Showing
This repository contains the prototype showing the concepts presented in the paper 'Sharing without Showing: Securing IoT Data with Trusted Execution Environments'

It consists of two main parts:

## attested_tls
This part contains the code intended to run on the server.
This part contains both code to be run in a secure enclave using the Open Enclave framework, as well as an equivalent part that runs directly on the host cpu.
More details can be found in the corresponding [README.md](attested_tls/README.md)

## client
This part contains code for benchmarking functions implemented in the above part.

For more information and instructions on how to build and run, see corresponding [README.mb](client/README.md).


## Requirements
To run the secure server one needs to install [Open Enclave](https://openenclave.io/sdk/) on an Intel SGX Enabled machine.
The examples are tested using Microsoft Azure environment, but it should be possible to run on any machine where Open Enclave is supported and that has Intel SGX.

## Gnu Scientific Library (GSL)
To be able to use GSL it needs to be built using the Open Enclave libraries. Get the source code from [GSL - GNU Scentific Library](https://www.gnu.org/software/gsl/) to a folder called 'gsl-oe' and run `make build-gsl' in the folder 'attested_tls'

### LIBSVM
The files needed for SVM classification is in 'attested_tls/libsvm/'. The original library can be found at [LIBSVM](https://www.csie.ntu.edu.tw/~cjlin/libsvm/). Two new files has been created for this prototype to work; 'svm-predict-lib.c', which is a modified version of 'svm-predict.c' where the model is provided as a c object rather that a file pointer, and 'models.c' where a pre-trained model has been encoded.


