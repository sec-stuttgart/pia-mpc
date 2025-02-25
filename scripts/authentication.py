from subprocess import check_output
from datetime import datetime, timezone
from tqdm import tqdm
from itertools import product
from csv import writer, QUOTE_NONE
from numpy import mean
from os import makedirs
from os.path import dirname

def run(binary, count, processor):
    if processor > 1:
        output = check_output(["taskset", "-c", f"0-{processor-1}", binary, str(count), str(processor)], text=True)
    elif processor == 1:
        output = check_output(["taskset", "1", binary, str(count), str(processor)], text=True)
    else:
        output = check_output([binary, str(count), str(processor)], text=True)
    return output.split()

def experiment(prefix, p, count, processor):
    binary = prefix + f"-{p}"
    return (binary, count, processor), run(binary, count, processor)

now = f"{datetime.now(timezone.utc).astimezone():%Y-%m-%d-%H%M%S}"

def main(*counts, prefix="build/Release/drowning-bgv", primes=[64, 128], repeats=10, processors=0, data=f"reports/{now}-authentication.tsv"):
    assert len(counts) > 0
    while len(counts) < len(primes):
        counts += [counts[-1]]

    makedirs(dirname(data), exist_ok=True)

    results = dict()
    with open(data, "tw") as file:
        tsv = writer(file, delimiter="\t", quoting=QUOTE_NONE)
        for (p, count), repeat in tqdm(product(zip(primes, counts), range(repeats)), total=len(primes) * repeats):
            (binary, count, processor), output = experiment(prefix, p, count, processors)
            tsv.writerow([f"{binary} {count} {processor}", " ".join(output)])
            count, time = output
            count = int(count)
            time = float(time)
            old_count, times = results.get(p, (count, []))
            assert old_count == count
            times.append(time)
            results[p] = (count, times)

    for p in primes:
        count, times = results[p]
        time = mean(times) / count
        print(f"{p}\t{time}")

if __name__ == "__main__":
    import fire
    fire.Fire(main)
