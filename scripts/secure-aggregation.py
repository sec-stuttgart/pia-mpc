from csv import QUOTE_NONE, reader, writer
from matplotlib import pyplot as plt
from tqdm import tqdm
import numpy
import os
import re
import shlex
import subprocess
import sys

class Compose:
    def __init__(self, compose, name="pia-mpc", **service_count):
        self.compose = compose
        self.name = name
        self.service_count = service_count

    def __enter__(self):
        if self.compose:
            command = ["docker", "compose", "-f", self.compose, "-p", self.name, "up", "-d", "--wait"]
            for service, count in self.service_count.items():
                command += ["--scale", f"{service}={count}"]
            subprocess.check_output(command)
        return self

    def __bool__(self):
        return bool(self.compose)

    def check(self, service, index, *args, user=None, cwd=None, err=False):
        if err:
            err = None
        else:
            err = subprocess.STDOUT
        if self.compose:
            command = ["docker", "compose", "-f", self.compose, "-p", self.name, "exec", "--index", str(index + 1), "-T"]
            if user is not None:
                command += ["-u", user]
            if cwd is not None:
                command += ["-w", cwd]
            command += [service, *map(str, args)]
            return subprocess.check_output(command, stderr=err)
        else:
            command = list(map(str, args))
            return subprocess.check_output(command, cwd=cwd, stderr=err)

    def simulate_network(self, delay=None, bandwidth=None):
        if delay or bandwidth:
            for service, count in self.service_count.items():
                for i in range(count):
                    self._tc(service, i, delay, bandwidth)

    def _tc(self, service, index, delay, bandwidth=None):
        command = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", f"{delay}ms"]
        if bandwidth:
            if isinstance(bandwidth, (int, float)):
                command += ["rate", f"{bandwidth}mbit"]
            else:
                command += ["rate", bandwidth]
        self.check(service, index, *command, user="root", err=True)

    def run(self, service, index, *args, env=None):
        if self.compose:
            command = ["docker", "compose", "-f", self.compose, "-p", self.name, "exec", "--index", str(index + 1), "-T"]
            if env is not None:
                for k, v in env.items():
                    command += ["-e", f"{k}={v}"]
            command += [service, *map(str, args)]
        else:
            command = list(map(str, args))
        return subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.compose:
            subprocess.check_output(["docker", "compose", "-f", self.compose, "-p", self.name, "down"])


def server(runtime, path, prefix, id, *args, **kwargs):
    exe = os.path.join(path, f"{prefix}server-{id}")
    return runtime.run(f"server", id, exe, *args, **kwargs)

def custom_server(base_name, runtime, path, prefix, id, *args, **kwargs):
    exe = os.path.join(path, f"{prefix}{base_name}-{id}")
    return runtime.run(f"server", id, exe, *args, **kwargs)

def client(runtime, path, prefix, id, *args, **kwargs):
    exe = os.path.join(path, f"{prefix}client-{id}")
    return runtime.run(f"client", id, exe, *args, **kwargs)

def wait(processes):
    for k, p in processes.items():
        stdout, stderr = p.communicate()
        if stderr:
            t, party = k
            print(f"{t} party {party} failed:\n{stderr}", file=sys.stderr)
        yield k, stdout

def collect(results, party, count, output, aggregate_parties=True):
    key = []
    if aggregate_parties:
        key.append(("party", party[0]))
    else:
        key.append(("party", party))

    key.append(("count", count))

    last = None

    for line in output.splitlines():
        tokens = line.split("\t")
        if len(tokens) == 1:
            continue
        else:
            assert len(tokens) == 2
            value = tokens[1]
            value = float(value)
            last = value

    try:
        r = results[tuple(key)]
    except KeyError:
        r = []
        results[tuple(key)] = r
    r.append(last)

def tsv(results, file):
    tsv = writer(file, delimiter="\t", quoting=QUOTE_NONE)
    for i, (keys, items) in enumerate(results.items()):
        if i == 0:
            tsv.writerow([k[0] for k in keys] + list(range(len(items))))
        tsv.writerow([k[1] for k in keys] + items)

def read_tsv(file):
    tsv = reader(file, delimiter="\t", quoting=QUOTE_NONE)
    result = {}
    for i, line in enumerate(tsv):
        if i == 0:
            assert line[0] == "party"
            assert line[1] == "count"
            keys = 2
            for j in range(keys, len(line)):
                assert line[j] == str(j - keys)

            samples = len(line) - keys
            continue
        party = line[0]
        count = int(line[1])
        data = list(float(line[j]) for j in range(keys, keys + samples))

        try:
            result[party][count] = data
        except KeyError:
            result[party] = {count: data}
    return result


def _setup(compose, config, compute_party_count, input_party_count, all_party_count=None):
    if all_party_count is None:
        all_party_count = compute_party_count + input_party_count
    if compose:
        config = f"config/compose-{compute_party_count}-{input_party_count}.mpc.yaml"
    compose.check("server", 0, "hmpc-setup", "--config", config, "certificate", "-f", "-s", *map(str, range(all_party_count)))

def run(counts=[1], gpu=False, path="build/secure-aggregation/Release", compute_party_count=2, input_party_count=2, prefix=None, config="config/mpc.yaml", setup=True, repeats=10, compose=False, file="--", all=False, delay=0, bandwidth=0):
    """
    :param counts:
    :param gpu:
    :param path: Base path to search for executables.
    :param compute_party_count: Number of compute parties.
    :param input_party_count: Number of input parties.
    :param prefix: Prefix for the client and server names; e.g., "spdz" produces "spdz-server-0" etc.
    :param config: Path to the config file. Uses "config/compose-{SERVERS}-{CLIENTS}.mpc.yaml" if `compose` is given.
    :param setup: Run the `setup` utility to generate certificates etc.
    :param compose: Use `docker compose` to run the parties as services. Uses "config/compose.yaml" as compose file or `compose` interpreted as string.
    :param delay: Network delay in milliseconds.
    :param bandwidth: Network delay in mbit (if given as int or float) or network delay given with units, e.g., "1gbit".
    """
    compute_parties = list(range(compute_party_count))
    input_parties = list(range(input_party_count))
    if compose and isinstance(compose, bool):
        if gpu:
            compose = "config/cuda/compose.yaml"
        else:
            compose = "config/compose.yaml"

    repeats = list(range(repeats))
    if isinstance(counts, tuple):
        counts = range(*counts)
    elif isinstance(counts, list):
        counts = counts
    else:
        counts = [counts]

    if gpu:
        processors = -1
    else:
        processors = 0

    if all and isinstance(all, bool):
        assert file and file != "--"
        dir = os.path.dirname(file)
        if dir:
            os.makedirs(dir, exist_ok=True)
        all = f"{file}-all.log"
        all = open(all, "tw")
        all.write(f"```bash\n# generated by\n{sys.executable} {shlex.join(sys.argv)}\n```\n\n")

    if file == "--" or file is None:
        file = sys.stdout
    else:
        dir = os.path.dirname(file)
        if dir: # if we are in the current directory, we do not have to make parents
            os.makedirs(dir, exist_ok=True)
        file = open(file, "tw")

    results = {}

    with Compose(compose, server=compute_party_count, client=input_party_count) as compose, tqdm(total=len(counts) * len(repeats) + (1 if setup else 0), leave=False) as progress:
        if setup:
            progress.set_description("Setup")
            _setup(compose, config, compute_party_count, input_party_count)
            progress.update()
        if compose:
            env = dict(HMPC_CONFIG=f"config/compose-{compute_party_count}-{input_party_count}.mpc.yaml")
        else:
            env = None

        if delay or bandwidth:
            compose.simulate_network(delay, bandwidth)
            if all:
                all.write(f"# delay {delay}ms, bandwidth {bandwidth}")
                if isinstance(bandwidth, (int, float)):
                    all.write("mbit")
                all.write("\n\n")

        if prefix:
            prefix = f"{prefix}-"
        else:
            prefix = ""

        for count in counts:
            args = [count, processors]
            for repeat in repeats:
                progress.set_description(f"{count=},{repeat=}")
                processes = {}
                for compute_party in compute_parties:
                    processes[("compute", compute_party)] = server(compose, path, prefix, compute_party, *args, env=env)
                for input_party in input_parties:
                    processes[("input", input_party)] = client(compose, path, prefix, input_party, *args, env=env)

                for party, stdout in wait(processes):
                    if all:
                        party_type, party_id = party
                        all.write(f"# {party_type} {party_id} (count {count}, processors {processors}, repeat {repeat})\n\n{stdout}\n")
                        all.flush()
                    collect(results, party, count, stdout)
                progress.update()

        tsv(results, file)

def run_only(name, counts=[1], gpu=False, path="build/secure-aggregation/Release", party_count=2, prefix=None, config="config/mpc.yaml", setup=True, repeats=10, compose=False, file="--", all=False, delay=0, bandwidth=0):
    """
    :param name: Executable base name, e.g., "offline" or "server".
    :param counts:
    :param gpu:
    :param path: Base path to search for executables.
    :param party_count: Number of compute parties.
    :param prefix: Prefix for the server names; e.g., "spdz" produces "spdz-offline-0" etc.
    :param config: Path to the config file. Uses "config/compose-{SERVERS}-{CLIENTS}.mpc.yaml" if `compose` is given.
    :param setup: Run the `setup` utility to generate certificates etc.
    :param compose: Use `docker compose` to run the parties as services. Uses "config/compose.yaml" as compose file or `compose` interpreted as string.
    :param delay: Network delay in milliseconds.
    :param bandwidth: Network delay in mbit (if given as int or float) or network delay given with units, e.g., "1gbit".
    """
    parties = list(range(party_count))
    if compose and isinstance(compose, bool):
        if gpu:
            compose = "config/cuda/compose.yaml"
        else:
            compose = "config/compose.yaml"

    repeats = list(range(repeats))
    if isinstance(counts, tuple):
        counts = range(*counts)
    elif isinstance(counts, list):
        counts = counts
    else:
        counts = [counts]

    if gpu:
        processors = -1
    else:
        processors = 0

    if all and isinstance(all, bool):
        assert file and file != "--"
        dir = os.path.dirname(file)
        if dir:
            os.makedirs(dir, exist_ok=True)
        all = f"{file}-all.log"
        all = open(all, "tw")
        all.write(f"```bash\n# generated by\n{sys.executable} {shlex.join(sys.argv)}\n```\n\n")

    if file == "--" or file is None:
        file = sys.stdout
    else:
        dir = os.path.dirname(file)
        if dir: # if we are in the current directory, we do not have to make parents
            os.makedirs(dir, exist_ok=True)
        file = open(file, "tw")

    results = {}

    with Compose(compose, server=party_count) as compose, tqdm(total=len(counts) * len(repeats) + (1 if setup else 0), leave=False) as progress:
        if setup:
            progress.set_description("Setup")
            _setup(compose, config, compute_party_count=party_count, input_party_count=2, all_party_count=party_count)
            progress.update()
        if compose:
            env = dict(HMPC_CONFIG=f"config/compose-{party_count}-2.mpc.yaml")
        else:
            env = None

        if delay or bandwidth:
            compose.simulate_network(delay, bandwidth)
            if all:
                all.write(f"# delay {delay}ms, bandwidth {bandwidth}")
                if isinstance(bandwidth, (int, float)):
                    all.write("mbit")
                all.write("\n\n")

        if prefix:
            prefix = f"{prefix}-"
        else:
            prefix = ""

        for count in counts:
            args = [count, processors]
            for repeat in repeats:
                progress.set_description(f"{count=},{repeat=}")
                processes = {}
                for party in parties:
                    processes[(name, party)] = custom_server(name, compose, path, prefix, party, *args, env=env)

                for party, stdout in wait(processes):
                    if all:
                        party_type, party_id = party
                        all.write(f"# {party_type} {party_id} (count {count}, processors {processors}, repeat {repeat})\n\n{stdout}\n")
                        all.flush()
                    collect(results, party, count, stdout)
                progress.update()

        tsv(results, file)

def plot(*files, plot="reports/secure-aggregation/plot.pdf", element_size=1, relative=False, aggregation="median+10percentile", names=None, styles=None, legend=False, grid=False, figsize=(4,2), verbose=False):
    """
    :param aggregation:
        Either "mean+error" (to plot mean and error bars ranging from min to max) or
        "mean+{COUNT}std" (to plot mean and error bars ranging from +- {COUNT} standard deviations) or
        "median+{PERCENTILE}percentile" (to plot media and error bars ranging from the {PERCENTILE}th percentile to the (100 - {PERCENTILE})th percentile, e.g., for {PERCENTILE}=10 the error bars go from the 10th to the 90th percentile)
    """

    # plt.rcParams["font.family"] = "serif"

    data = []
    for f in files:
        with open(f) as f:
            tsv = read_tsv(f)

        parties = list(tsv.keys())

        partitioned_data = {}
        counts = numpy.array(list(tsv[parties[0]].keys()))
        for party in parties:
            assert numpy.all(numpy.array(list(tsv[party].keys())) == counts)

            partitioned_data[party] = numpy.array([tsv[party][count] for count in counts])

        counts = counts * element_size
        if relative:
            for party in parties:
                partitioned_data[party] = partitioned_data[party] / numpy.expand_dims(counts, -1)

        if aggregation == "mean+error":
            for party in parties:
                party_mean = partitioned_data[party].mean(axis=-1)
                party_max = partitioned_data[party].max(axis=-1)
                party_min = partitioned_data[party].min(axis=-1)
                party_error = party_mean - party_min, party_max - party_mean

                data.append((counts, party_mean, party_error))
        elif match := re.match(r"mean\+(?P<count>\d)std", aggregation):
            count = int(match.group("count"))
            for party in parties:
                party_mean = partitioned_data[party].mean(axis=-1)
                party_std = partitioned_data[party].std(axis=-1, ddof=1)

                data.append((counts, party_mean, count * party_std))
        elif match := re.match(r"median\+(?P<percentile>\d+)percentile", aggregation):
            percentile = int(match.group("percentile"))
            for party in parties:
                party_median = numpy.median(partitioned_data[party], axis=-1)
                party_lower = numpy.percentile(partitioned_data[party], percentile, axis=-1)
                party_upper = numpy.percentile(partitioned_data[party], 100 - percentile, axis=-1)
                party_error = party_median - party_lower, party_upper - party_median

                data.append((counts, party_median, party_error))
        elif aggregation == "mean":
            for party in parties:
                party_mean = partitioned_data[party].mean(axis=-1)
                data.append((counts, party_mean))
        elif aggregation == "median":
            for party in parties:
                party_median = numpy.median(partitioned_data[party], axis=-1)
                data.append((counts, party_median))
        else:
            raise ValueError(f"Invalid aggregation type: {aggregation}")

    if names is None:
        names = []
        for file in files:
            for party in parties:
                names.append(f"{party}: {file}")
    else:
        assert len(names) == len(data)

    if styles is None:
        styles = []
        for _ in files:
            for _ in parties:
                styles.append(dict())
    else:
        assert len(styles) == len(data)

    fig = plt.figure(figsize=figsize)
    plt.style.use("tableau-colorblind10")

    if aggregation == "mean+error" or re.match(r"mean\+\dstd", aggregation) or re.match(r"median\+\d+percentile", aggregation):
        for name, (x, mean, error), style in zip(names, data, styles):
            if name is None:
                continue
            plt.errorbar(x, mean, error, label=name, **style)
            if verbose:
                for x, y, (upper, lower) in zip(x, mean, error):
                    print(f"{name}: ({x},{lower},{y},{upper})")
    elif aggregation == "mean" or aggregation == "median":
        for name, (x, mean), style in zip(names, data, styles):
            if name is None:
                continue
            plt.plot(x, mean, label=name, **style)
            if verbose:
                for x, y in zip(x, mean):
                    print(f"{name}: ({x},{y})")
    else:
        raise ValueError(f"Invalid aggregation type: {aggregation}")

    if legend:
        legend = plt.legend()
        for line in legend.get_lines():
            line.set_linestyle("solid")
    if grid:
        plt.grid()

    plt.ylim(bottom=0)
    plt.tight_layout(pad=0, h_pad=0, w_pad=0)
    plt.savefig(plot)

if __name__ == "__main__":
    import fire
    fire.Fire()
