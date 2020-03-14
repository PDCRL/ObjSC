# Description
        This repository contains the implementation for concurrent execution of Blockchain Smart Contracts using different Software Transactional Memory protocols (RWSTM and Object-based STM) developed by IITH-PDCRL Group and state-of-the-art speculative and static bin based approaches.
        There is Malicious Miner With Simple (non-SCV/ non-Smart Concurrent Validator/Default Validator) and Counter based Validator (Smart Concurrent Validator or Smart Multi-Threaded Validator as used in the paper) Src file for benchmarking on four smart contract benchmarks.
        
# Compile    
	$ make

# Run
	The workloads (w1, w2, and w3) for benchmarking is defined in run.py file of respective contract repository.
	$ python run.py
