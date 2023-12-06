
## Client benchmarking
This part contains code to be able to benchmark the server by creating data for the different implemented use cases that the server can handle.

### main.py
Contains code for running benchmarks towards both the enclave and the non-secure version for following functions:
- Sum
- Histogram
- LSF
- SVM

### taxi_congestion_sim.py
Contains code for simulate movements of taxis, store the positions in encrypted form and providing functionality to send this data to the enclave for the purpose of computing the distribution

### taxi-simulation-analysis.py
Contains code for analysing previosly recorded simulations stored in 'recorded_simulation_data'