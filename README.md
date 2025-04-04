# MPC with Publicly Identifiable Abort from Pseudorandomness and Homomorphic Encryption (Artifact)

This repository contains the code to reproduce the experiments from our Eurocrypt 2025 paper "MPC with Publicly Identifiable Abort from Pseudorandomness and Homomorphic Encryption" (extended version available [online](https://eprint.iacr.org/2025/258)).
Additionally, we give code to reproduce the parameter and complexity estimation from the paper.

To reproduce our results, you need [Docker](https://www.docker.com/) and [Python](https://www.python.org) installed on your machine.
We use the [hmpc](https://github.com/iko4/hmpc) library for our implementation and a few [Python dependencies](requirements.txt) to automate running the experiments.
Internally, the container images use [CMake](https://cmake.org/) and [Rust](https://rust-lang.org) to build our implementation, as well as [oneAPI](https://oneapi.io) and (optionally) [CUDA](https://developer.nvidia.com/cuda-toolkit) to run it.
The containerized build process downloads most of these components and you need might implicitly agree to the corresponding licenses and/or end user agreements:

- [oneAPI runtime](https://github.com/intel/oneapi-containers/blob/master/licensing/oneapi-runtime-2024.2.1-0-devel-ubuntu22.04/2024.2/licensing/2024.2/license.htm)
- [CMake](https://cmake.org/licensing/)
- [vcpkg](https://github.com/microsoft/vcpkg/blob/master/README.md#licence)
    - [Catch2](https://github.com/catchorg/Catch2/blob/devel/LICENSE.txt)
    - [fmt](https://github.com/fmtlib/fmt/blob/master/LICENSE)
- [LLVM](https://github.com/intel/llvm/blob/sycl/sycl/LICENSE.TXT)
- [Rust](https://www.rust-lang.org/policies/licenses)
- [hmpc](https://github.com/iko4/hmpc/blob/main/LICENSE)
- other (binary) apt packages installed in the container
- other (binary) Python packages installed in the container

Note that you will be redistributing these components if you distribute a container image built as described below.
The code in this repository is distributed under the [MIT license](LICENSE).


## Structure of the Artifact 🗂️

This artifact contains code to build the implementation for the paper, as well as scripts to run the experiments.
In the sections below, we describe how to build and run the experiments.
The artifact is structured as follows.

- Benchmarking the verification of the authentication

    - Code: [./src/drowning-bgv.cpp](src/drowning-bgv.cpp)

    - Script to run the experiment: [./scripts/authentication.py](scripts/authentication.py)

- Benchmarking the verification of MACs
    - Code: [./src/mac.cpp](src/mac.cpp)

    - Script to run the experiment: [./scripts/mac.py](scripts/mac.py)

- Benchmarking multiplications in the online phase

    - Code for our protocol: [./src/bench-multiply/server.cpp](src/bench-multiply/server.cpp)

    - Code for the SPDZ protocol: [./src/bench-multiply/spdz-server.cpp](src/bench-multiply/spdz-server.cpp)

    - Script to run and plot the experiment: [./scripts/secure-aggregation.py](scripts/secure-aggregation.py)

- Benchmarking secure aggregation in the online phase

    - Code for our protocol (clients): [./src/secure-aggregation/client.cpp](src/secure-aggregation/client.cpp)

    - Code for our protocol (servers): [./src/secure-aggregation/server.cpp](src/secure-aggregation/server.cpp)

    - Shared code between clients and servers: [./src/secure-aggregation/common.hpp](src/secure-aggregation/common.hpp)

    - Code for the SPDZ protocol (clients): [./src/secure-aggregation/spdz-client.cpp](src/secure-aggregation/spdz-client.cpp)

    - Code for the SPDZ protocol (servers): [./src/secure-aggregation/spdz-server.cpp](src/secure-aggregation/spdz-server.cpp)

    - Shared code between clients and servers for the SPDZ protocol: [./src/secure-aggregation/spdz-common.hpp](src/secure-aggregation/spdz-common.hpp)

    - Script to run and plot the experiment: [./scripts/secure-aggregation.py](scripts/secure-aggregation.py)

- Benchmarking secure aggregation in the offline phase

    - Code for our protocol (servers): [./src/secure-aggregation/offline.cpp](src/secure-aggregation/offline.cpp)

    - Code for the SPDZ protocol (servers): [./src/secure-aggregation/spdz-offline.cpp](src/secure-aggregation/spdz-offline.cpp)

    - Script to run and plot the experiment: [./scripts/secure-aggregation.py](scripts/secure-aggregation.py)

- Parameter estimation for the BGV encryption scheme

    - Script: [./scripts/bgv-parameters.py](scripts/bgv-parameters.py)

- Complexity estimation of the related work

    - Script: [./scripts/complexity.py](scripts/complexity.py)

- Other files:

    - Our main dependency, the [hmpc](https://github.com/iko4/hmpc) library, is integrated as git submodule: [./hmpc](hmpc)

        If you already have hmpc installed or a container image containing hmpc, you do not need to use it as submodule.
        Otherwise, we describe below how to build a container image with hmpc installed.

    - CMake files to build the code: [./CMakeLists.txt](CMakeLists.txt), [./src/bench-multiply/CMakeLists.txt](src/bench-multiply/CMakeLists.txt) (for the multiplication benchmark), and [./src/secure-aggregation/CMakeLists.txt](src/secure-aggregation/CMakeLists.txt) (for the secure aggregation benchmark)

    - A script to generate tables for the parameter and complexity estimation (see below): [./scripts/tables.sh](scripts/tables.sh)

    - Docker compose files to run the MPC parties as different services: [./config/compose.yaml](config/compose.yaml) and [./config/cuda/compose.yaml](config/cuda/compose.yaml) (for GPU enabled benchmarks)

    - Config files for the MPC parties, mostly indicating which party can be reached via which hostname and port: [./config/mpc.yaml](config/mpc.yaml) (for local benchmarks), [./config/compose-2-2.mpc.yaml](config/compose-2-2.mpc.yaml) (for benchmarks using Docker compose with 2 servers and 2 clients), etc.


## Preparing the Python Environment 📦

We recommend that you use a Python virtual environments to install all required Python dependencies.
You can run the following:

```bash
# create a virtual environment
python3 -m venv .venv
# enter virtual environment
source .venv/bin/activate
# install Python dependencies
pip3 install -r requirements.txt
```

The same requirements are also automatically installed in the container below.
Therefore, you can run some steps also in the container instead.
However, there are some steps that need to run *outside* of a container, for which you need the Python dependencies also on your host machine that runs Docker.
We highlight these cases below.


## Preparing the Container Environment 🧰

We tested the following containerized build environments for our software:
[Dev Containers](https://code.visualstudio.com/docs/devcontainers/tutorial) and
[Docker](https://www.docker.com/).

For both Dev Containers and Docker, we assume that you already have a container image for the [hmpc](https://github.com/iko4/hmpc) library.
To build such a base container image, run the following:

```bash
# initialize hmpc submodule
git submodule update --init
# build hmpc container image
docker buildx build --tag hmpc --target development --build-arg user_id="$(id -u)" --build-arg group_id="$(id -g)" --file hmpc/.devcontainer/Containerfile hmpc

# Alternative for last step:
# build CUDA-enabled hmpc container image
docker buildx build --tag hmpc --build-arg cuda_version="${CUDA_VERSION:?}" --build-arg cuda_arch=sm_70 --build-arg user_id="$(id -u)" --build-arg group_id="$(id -g)" --build-context cuda="${CUDA_HOME:?}" --file hmpc/.devcontainer/cuda/Containerfile hmpc
```

Note: For the CUDA container, you can replace the CUDA architecture (`cuda_arch`) by a value matching your GPU.
For this, use the [compute capability](https://developer.nvidia.com/cuda-gpus) for your GPU while dropping the decimal point.
For example, compute capability 7.5 (for the Nvidia Titan RTX used below) becomes "sm_75".

Note: This can take a few hours to build, as it builds a version of [clang](https://clang.llvm.org/) from source.

### Dev Container

All files to create a build environment with Dev Containers are already set up (assuming a built hmpc container image).
Simply start Visual Studio Code and select "Reopen in Container" with the Dev Containers extension.
This automates creating and starting a Docker container (without CUDA support).
Most steps to reproduce our results below can be run either from inside the Dev Container or a manually created and started Docker container.

### Docker

The following will create a container image called "pia-mpc" that has all required tools to build and run our implementation.

```bash
# build image
docker buildx build --tag pia-mpc --file .devcontainer/Containerfile .
# run container
docker run --rm -it --mount type=bind,source="$(pwd)",target=/workspaces/pia-mpc pia-mpc

# Alternative for last step:
# run CUDA-enabled container
docker run --rm -it --gpus all --mount type=bind,source="$(pwd)",target=/workspaces/pia-mpc --mount type=bind,source="${CUDA_HOME:?}",target="/opt/cuda-${CUDA_VERSION:?}" pia-mpc
```

## Parameter and Complexity Estimation 🎛

*(Inside the Python virtual environment or container:)*

The [parameter estimation](scripts/bgv-parameters.py) and [complexity estimation](scripts/complexity.py) can be run together with a single Bash script:

```bash
SUBSTITUTION="s/any_party/P2P/;s/bulletin_board/BC/" ./scripts/tables.sh
```

This creates Latex-style tables in the "./paper/tables" directory.
The "SUBSTITUTION" environment variable can be used to substitute text of the tables, for example, paper names to Latex `\cite{...}` macros.

The resulting tables are for
- communication complexity ("./paper/tables/related-work-communication-core.tex" used as Table 2)
- computation complexity ("./paper/tables/related-work-computation-core.tex" used as Table 3)
- BGV parameters ("./paper/tables/bgv-params-core.tex" used as Table 5 of the extended paper)


## Build the Implementation 🏗

*(Inside the container:)*

To configure and compile the examples, run the following:

```bash
# configure
cmake --preset default
# build
cmake --build --preset default
```

Note: This builds multiple executables (one for each party and use case).
If your machine runs out of memory (RAM) when building many executables in parallel, reduce the build parallelism.
For example, appending `-j4` limits the number of parallel builds to 4.
You can also just build the executables for the individual use cases;
for this, we give the build instructions below.

Note: Building some or all of the examples can take several hours.


## Run Experiments 🚀

For our experiments, we used the following machines:
1. a laptop with an Intel Core i7-8565U CPU, 4 cores, 1.80 GHz
2. a server with an Intel Core i9-9940X CPU, 14 cores, 3.30 GHz; and an Nvidia Titan RTX GPU
3. an HPC node with an Intel Xeon Gold 6230 CPU, 40 cores, 2.1 GHz; and an Nvidia A100 80 GB GPU

Note: We rebuilt the executables for each of the three machines.
You should rebuild them at least for every different GPU that you want to run the experiments with.

The following shows how to reproduce the results for
- verifying the authentication (Section 8.2 "Benchmark: Verifying Authentication and MACs" and Table 4)
- verifying MACs (Section 8.2 "Benchmark: Verifying Authentication and MACs" and Table 4)
- multiplication benchmark (Section 8.2 "Benchmark: Multiplication Throughput" and Figure 9 of the extended paper)
- secure aggregation online phase (Section 8.2 "Use Case: Secure Aggregation" and Figure 10 of the extended paper)
- secure aggregation offline phase (Section 8.2 "Use Case: Secure Aggregation" and Figure 10 of the extended paper)

For the latter three experiments, we use a Python script to orchestrate multiple Docker containers.
This is why the commands should be run *outside* of a container.

### Verifying the Authentication

*(Inside the container:)*

Build instructions (if you did not build everything above):
```bash
# build
cmake --build --preset default --target verify-authentication
```

The following runs only the verification of a single authentication operation.
Afterwards, the scripts prints the average verification time (for 64 and 128 bit plaintext size).
The parameters indicate the number of ciphertexts to check.
The option `--processors -1` indicates that a GPU should be used.

```bash
# on the Laptop
python3 scripts/authentication.py 500 200

# on the HPC node
python3 scripts/authentication.py 4000 2000

# on the server using the GPU
python3 scripts/authentication.py 1000 500 --processors -1

# on the HPC node using the GPU
python3 scripts/authentication.py 4000 2000 --processors -1
```

Detailed results can be found in "./reports/{TIMESTAMP}-authentication.tsv".


### Verifying MACs

*(Inside the container:)*

Build instructions (if you did not build everything above):
```bash
# build
cmake --build --preset default --target verify-macs
```

The following runs only the MAC tag check.
Afterwards, the scripts prints the average verification time (for 64 and 128 bit plaintext size and for 2 to 32 parties; the 2 party result was reported in the paper).
The parameters indicate the number of MAC tags to check.
The option `--processors -1` indicates that a GPU should be used.

```bash
# on the Laptop
python3 scripts/mac.py 327680000 131072000

# on the HPC node
python3 scripts/mac.py 524288000 262144000

# on the server using the GPU
python3 scripts/mac.py 524288000 262144000 --processors -1

# on the HPC node using the GPU
python3 scripts/mac.py 524288000 262144000 --processors -1
```

Detailed results can be found in "./reports/{TIMESTAMP}-mac.tsv".


### Multiplication Benchmark

*(Inside the container:)*

Build instructions (if you did not build everything above):
```bash
# build
cmake --build --preset default --target benchmark-multiply
```

*(Inside the Python virtual environment:)*

For the multiplication benchmark, run the following.
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

Note:
We performed this experiment on the "server" machine, only.
Omit the `--gpu` option when not running the GPU-enabled version of the binaries.
Additionally, you can reduce the problem sizes given as the array `[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]` if they are too big for your machine.


Plot the results with:
```bash
# plot for LAN setting
python3 scripts/secure-aggregation.py plot reports/bench-multiply/ours-10ms-1gbit.tsv reports/bench-multiply/spdz-10ms-1gbit.tsv --aggregation mean --names "['Ours (Server)', 'SPDZ (Server)']" --styles "[{}, {color: C2}]" --legend --grid --plot reports/bench-multiply/plot-10ms-1gbit.pdf
# plot for WAN setting
python3 scripts/secure-aggregation.py plot reports/bench-multiply/ours-50ms-50mbit.tsv reports/bench-multiply/spdz-50ms-50mbit.tsv --aggregation mean --names "['Ours (Server)', 'SPDZ (Server)']" --styles "[{}, {color: C2}]" --grid --plot reports/bench-multiply/plot-50ms-50mbit.pdf
```

This produces plots and detailed results in the "./reports/bench-multiply" directory.


### Secure Aggregation Online Phase

*(Inside the container:)*

Build instructions (if you did not build everything above):
```bash
# build
cmake --build --preset default --target secure-aggregation-online
```

*(Inside the Python virtual environment:)*

For the secure aggregation online phase, run the following.

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

Note:
We performed this experiment on the "server" machine, only.
Omit the `--gpu` option when not running the GPU-enabled version of the binaries.
Additionally, you can reduce the problem sizes given as the array `[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]` if they are too big for your machine.

Plot the results with:
```bash
# plot for LAN setting
python3 scripts/secure-aggregation.py plot reports/secure-aggregation/ours-10ms-1gbit.tsv reports/secure-aggregation/spdz-10ms-1gbit.tsv --aggregation mean --names "['Ours (Server)', 'Ours (Client)', 'SPDZ (Server)', 'SPDZ (Client)']" --styles "[{}, {linestyle: dashed}, {}, {}]" --legend --grid --plot reports/secure-aggregation/plot-10ms-1gbit.pdf
# plot for WAN setting
python3 scripts/secure-aggregation.py plot reports/secure-aggregation/ours-50ms-50mbit.tsv reports/secure-aggregation/spdz-50ms-50mbit.tsv --aggregation mean --names "['Ours (Server)', 'Ours (Client)', 'SPDZ (Server)', 'SPDZ (Client)']" --styles "[{}, {linestyle: dashed}, {}, {}]" --grid --plot reports/secure-aggregation/plot-50ms-50mbit.pdf
```

This produces plots and detailed results in the "./reports/secure-aggregation" directory.


### Secure Aggregation Offline Phase

*(Inside the container:)*

Build instructions (if you did not build everything above):
```bash
# build
cmake --build --preset default --target secure-aggregation-offline
```

*(Inside the Python virtual environment:)*

For the secure aggregation offline phase, run the following.

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

Note:
We performed this experiment on the "server" machine, only.
Omit the `--gpu` option when not running the GPU-enabled version of the binaries.
Additionally, you can reduce the problem sizes given as the range `(1,13)` if they are too big for your machine.
This is what we did for the SPDZ benchmark as it used too much RAM.

Plot the results with:
```bash
# plot for LAN setting
python3 scripts/secure-aggregation.py plot reports/secure-aggregation/ours-offline-10ms-1gbit.tsv reports/secure-aggregation/spdz-offline-10ms-1gbit.tsv --element-size 16 --aggregation mean --names "['Ours (Server)', 'SPDZ (Server)']" --styles "[{}, {color: C2}]" --legend --grid --plot reports/secure-aggregation/plot-offline-10ms-1gbit.pdf
# plot for WAN setting
python3 scripts/secure-aggregation.py plot reports/secure-aggregation/ours-offline-50ms-50mbit.tsv reports/secure-aggregation/spdz-offline-50ms-50mbit.tsv --element-size 16 --aggregation mean --names "['Ours (Server)', 'SPDZ (Server)']" --styles "[{}, {color: C2}]" --grid --plot reports/secure-aggregation/plot-offline-50ms-50mbit.pdf
```

This produces plots and detailed results in the "./reports/secure-aggregation" directory.
