# MPC with Publicly Identifiable Abort from Pseudorandomness and Homomorphic Encryption (Artifact)

This repository contains the code to reproduce the experiments from our Eurocrypt 2025 paper "MPC with Publicly Identifiable Abort from Pseudorandomness and Homomorphic Encryption".


## Preparing a Build Environment 🧰

For both Dev Containers and Docker, we assume that you already have a container image for the hmpc library.
To build such a base container image, run the following (see [hmpc README](https://github.com/iko4/hmpc)):

```bash
# initialize hmpc submodule
git submodule update --init
# build hmpc container image
docker buildx build --tag hmpc --target development --build-arg user_id="$(id -u)" --build-arg group_id="$(id -g)" --file hmpc/.devcontainer/Containerfile hmpc
```

### Dev Container

All files to create a build environment with Dev Containers are already set up (assuming a built hmpc container image).
Simply start Visual Studio Code and select "Reopen in Container" with the Dev Containers extension.
This automates the steps shown below for Docker.

### Docker

The following will create a container image called "pia-mpc" that has all required tools to build our software.

```bash
# build image
docker buildx build --tag pia-mpc --file .devcontainer/Containerfile .
```


## Run Demos 🚀

After having built the demos, you can reproduce the results of the paper by running the following commands.
Note that, for the verification demos, the parameters after the script determine the number of ciphertext or MAC tags to be verified (the first number for the 64 bit demo and the second number for the 128 bit demo).
You can increase or decrease these number depending on the available resources on your devices.
The `processors` option fixes the number of processors to be used by the executable (with the special value `0` (default) for all processors and `-1` for using the GPU).

For the online and offline phase, we use `docker compose` to run clients and servers as Docker services.
Then, we emulate different network settings between the instances.
Make sure to run the scripts that use the `--compose` option (online and offline phase) *outside* of a container.
The other scripts (authentication verification and MAC verification) should be run *inside* of a container, unless you want to build and run our demos directly on your local machine.

For our benchmarks, we ran the demos on
1. A laptop with an Intel Core i7-8565U CPU, 4 cores, 1.80 GHz,
1. an HPC server node with an Intel Xeon Gold 6230 CPU, 40 cores, 2.1 GHz,
1. a computer with an Intel Core i9-9940X CPU, 14 cores, 3.30 GHz; and an Nvidia Titan RTX GPU
1. an HPC server node with an Nvidia A100 80 GB GPU.

The laptop device has 16 GB of main memory (RAM).
The server nodes require more main memory for running the larger demo instances.
We ran the online and offline phase only with the third machine as the HPC environment did not allow us to emulate different network settings.


### Authentication Verification

The following runs only the verification of a single authentication operations.
Afterwards, the scripts prints the average verification time (for 64 and 128 bit plaintext size).

```bash
# on the Laptop device
python3 scripts/authentication.py 500 200

# on the HPC node
python3 scripts/authentication.py 4000 2000

# on the GPU device
python3 scripts/authentication.py 1000 500 --processors -1

# on the GPU HPC node
python3 scripts/authentication.py 4000 2000 --processors -1
```


### MAC Verification

The following runs only the MAC tag check.
Afterwards, the scripts prints the average verification time (for 64 and 128 bit plaintext size and for 2 to 32 parties; the 2 party result was reported in the paper).

```bash
# on the Laptop device
python3 scripts/mac.py 327680000 131072000

# on the HPC node
python3 scripts/mac.py 524288000 262144000

# on the GPU device
python3 scripts/mac.py 524288000 262144000 --processors -1

# on the GPU HPC node
python3 scripts/mac.py 524288000 262144000 --processors -1
```


### Online Phase

(Omit the `--gpu` option when not running the GPU-enabled version of the binaries.)
```bash
# ours in LAN setting
python3 scripts/secure-aggregation.py run "[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]" --gpu --compose --delay 10 --bandwidth 1gbit --file reports/secure-aggregation/ours-10ms-1gbit.tsv --all
# SPDZ in LAN setting
python3 scripts/secure-aggregation.py run "[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]" --gpu --prefix spdz --compose --delay 10 --bandwidth 1gbit --file reports/secure-aggregation/spdz-10ms-1gbit.tsv --all
# ours in WAN setting
python3 scripts/secure-aggregation.py run "[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]" --gpu --compose --delay 50 --bandwidth 50mbit --file reports/secure-aggregation/ours-50ms-50mbit.tsv --all
# SPDZ in WAN setting
python3 scripts/secure-aggregation.py run "[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]" --gpu --prefix spdz --compose --delay 50 --bandwidth 50mbit --file reports/secure-aggregation/spdz-50ms-50mbit.tsv --all
```

And plot the results with
```bash
# plot for LAN setting
python3 scripts/secure-aggregation.py plot reports/secure-aggregation/ours-10ms-1gbit.tsv reports/secure-aggregation/spdz-10ms-1gbit.tsv --aggregation mean --names "['Ours (Server)', 'Ours (Client)', 'SPDZ (Server)', 'SPDZ (Client)']" --styles "[{}, {linestyle: dashed}, {}, {}]" --legend --grid --plot reports/secure-aggregation/plot-10ms-1gbit.pdf
# plot for WAN setting
python3 scripts/secure-aggregation.py plot reports/secure-aggregation/ours-50ms-50mbit.tsv reports/secure-aggregation/spdz-50ms-50mbit.tsv --aggregation mean --names "['Ours (Server)', 'Ours (Client)', 'SPDZ (Server)', 'SPDZ (Client)']" --styles "[{}, {linestyle: dashed}, {}, {}]" --grid --plot reports/secure-aggregation/plot-50ms-50mbit.pdf
```


### Offline Phase

(We use a smaller maximum number of ciphertexts for the SPDZ offline phase because the Nvidia Titan RTX ran out of VRAM.)
```bash
# ours in LAN setting
python3 scripts/secure-aggregation.py run-only offline "(1,13)" --gpu --compose --delay 10 --bandwidth 1gbit --file reports/secure-aggregation/ours-offline-10ms-1gbit.tsv --all
# SPDZ in LAN setting
python3 scripts/secure-aggregation.py run-only offline "(1,9)" --gpu --prefix spdz --compose --delay 10 --bandwidth 1gbit --file reports/secure-aggregation/spdz-offline-10ms-1gbit.tsv --all
# ours in WAN setting
python3 scripts/secure-aggregation.py run-only offline "(1,13)" --gpu --compose --delay 50 --bandwidth 50mbit --file reports/secure-aggregation/ours-offline-50ms-50mbit.tsv --all
# SPDZ in WAN setting
python3 scripts/secure-aggregation.py run-only offline "(1,9)" --gpu --prefix spdz --compose --delay 50 --bandwidth 50mbit --file reports/secure-aggregation/spdz-offline-50ms-50mbit.tsv --all
```

And plot the results with
```bash
# plot for LAN setting
python3 scripts/secure-aggregation.py plot reports/secure-aggregation/ours-offline-10ms-1gbit.tsv reports/secure-aggregation/spdz-offline-10ms-1gbit.tsv --element-size 16 --aggregation mean --names "['Ours (Server)', 'SPDZ (Server)']" --styles "[{}, {color: C2}]" --legend --grid --plot reports/secure-aggregation/plot-offline-10ms-1gbit.pdf
# plot for WAN setting
python3 scripts/secure-aggregation.py plot reports/secure-aggregation/ours-offline-50ms-50mbit.tsv reports/secure-aggregation/spdz-offline-50ms-50mbit.tsv --element-size 16 --aggregation mean --names "['Ours (Server)', 'SPDZ (Server)']" --styles "[{}, {color: C2}]" --grid --plot reports/secure-aggregation/plot-offline-50ms-50mbit.pdf
```

### Multiplication Benchmark (Online)

For the multiplication benchmark, run
```bash
# ours in LAN setting
python3 scripts/secure-aggregation.py run-only server-multiply "[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]" --path build/bench-multiply/Release --gpu --compose --delay 10 --bandwidth 1gbit --file reports/bench-multiply/ours-10ms-1gbit.tsv --all
# SPDZ in LAN setting
python3 scripts/secure-aggregation.py run-only server-multiply "[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]" --path build/bench-multiply/Release --gpu --prefix spdz --compose --delay 10 --bandwidth 1gbit --file reports/bench-multiply/spdz-10ms-1gbit.tsv --all
# ours in WAN setting
python3 scripts/secure-aggregation.py run-only server-multiply "[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]" --path build/bench-multiply/Release --gpu --compose --delay 50 --bandwidth 50mbit --file reports/bench-multiply/ours-50ms-50mbit.tsv --all
# SPDZ in WAN setting
python3 scripts/secure-aggregation.py run-only server-multiply "[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]" --path build/bench-multiply/Release --gpu --prefix spdz --compose --delay 50 --bandwidth 50mbit --file reports/bench-multiply/spdz-50ms-50mbit.tsv --all
```

And plot the results with
```bash
# plot for LAN setting
python3 scripts/secure-aggregation.py plot reports/bench-multiply/ours-10ms-1gbit.tsv reports/bench-multiply/spdz-10ms-1gbit.tsv --aggregation mean --names "['Ours (Server)', 'SPDZ (Server)']" --styles "[{}, {color: C2}]" --legend --grid --plot reports/bench-multiply/plot-10ms-1gbit.pdf
# plot for WAN setting
python3 scripts/secure-aggregation.py plot reports/bench-multiply/ours-50ms-50mbit.tsv reports/bench-multiply/spdz-50ms-50mbit.tsv --aggregation mean --names "['Ours (Server)', 'SPDZ (Server)']" --styles "[{}, {color: C2}]" --grid --plot reports/bench-multiply/plot-50ms-50mbit.pdf
```
