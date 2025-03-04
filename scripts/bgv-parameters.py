import math
import sympy
import random

def ntt_prime(log_m, bits):
    m = 2**log_m
    p = 0
    is_prime = False
    while p % m != 1 or not is_prime:
        p = random.randint(2**(bits - log_m - 1), 2**(bits - log_m)-1) << log_m
        p += 1
        is_prime = sympy.ntheory.isprime(p)
    return p

class Norm:
    """Infinity norm"""
    def __init__(self, max_value, dim=1):
        self.max_value = max_value
        self.dim = dim

    def __add__(self, other):
        if isinstance(other, Norm):
            if self.dim == 1:
                return Norm(self.max_value + other.max_value, other.dim)
            elif other.dim == 1:
                return Norm(self.max_value + other.max_value, self.dim)
            elif self.dim == other.dim:
                return Norm(self.max_value + other.max_value, self.dim)
        return NotImplemented
    __radd__ = __add__
    __sub__ = __add__
    __rsub__ = __add__

    def __mul__(self, other):
        if isinstance(other, Norm):
            if self.dim == 1:
                return Norm(self.max_value * other.max_value, other.dim)
            elif other.dim == 1:
                return Norm(self.max_value * other.max_value, self.dim)
            elif self.dim == other.dim:
                return Norm(self.max_value * other.max_value * self.dim, self.dim)
        return NotImplemented
    __rmul__ = __mul__

    def __truediv__(self, by):
        return Norm(math.ceil(self.max_value / by), self.dim)


class BGVKey:
    def __init__(self, plaintext_modulus, private_key, noise):
        self.plaintext_modulus = plaintext_modulus
        self.private_key = private_key
        self.noise = noise

    @property
    def N(self):
        assert self.plaintext_modulus.dim == 1
        assert self.private_key.dim == self.noise.dim
        return self.private_key.dim

    @property
    def p(self):
        return self.plaintext_modulus


class BGVNoise:
    def __init__(self, plaintext_norm, randomness_norm_0, randomness_norm_1, randomness_norm_2):
        self.plaintext = plaintext_norm
        self.randomness = (randomness_norm_0, randomness_norm_1, randomness_norm_2)

    def __add__(self, other):
        assert len(self.randomness) == 3
        if isinstance(other, Norm):
            return BGVNoise(self.plaintext + other, *self.randomness)
        if isinstance(other, BGVNoise):
            assert len(other.randomness) == 3
            return BGVNoise(self.plaintext + other.plaintext, *[r + s for r, s in zip(self.randomness, other.randomness)])
        return NotImplemented
    __radd__ = __add__
    __sub__ = __add__
    __rsub__ = __add__

    def __mul__(self, other):
        assert len(self.randomness) == 3
        if isinstance(other, Norm):
            return BGVNoise(self.plaintext * other, *[r * other for r in self.randomness])
        return NotImplemented
    __rmul__ = __mul__

    @classmethod
    def encrypt(cls, p, N):
        return cls(Norm(p // 2, N), Norm(1, N), Norm(20, N), Norm(20, N))

    def noise(self, key):
        assert len(self.randomness) == 3
        return self.plaintext + key.p * key.noise * self.randomness[0] + key.p * self.randomness[1] - key.p * self.randomness[2] * key.private_key

def zk_noise(p, N, U, V, sec):
    """Noise of 2 * C"""
    inputs = BGVNoise.encrypt(p, N)

    assert U <= 2**sec
    checked_cyphertexts = Norm(2**(sec + 1)) * inputs

    return checked_cyphertexts - checked_cyphertexts

def bits(x):
    return math.ceil(math.log2(x))

def drowned_multiplication(p=9930515109164351489, N=2**14, zeroknowledge_sec=80, soundness_sec=128, statistical_sec=None, U_factor=2, verbose=False):
    if statistical_sec is None:
        statistical_sec = zeroknowledge_sec
    V = math.ceil((soundness_sec + 2) / math.log2(2 * N + 1))
    U = U_factor * V
    if verbose:
        print(f"""Inputs:
    p = {p} ({bits(p)} bits)
    N = {N} = 2^{bits(N)}
    sec (zero knowledge) = {zeroknowledge_sec}
    sec (statistical)    = {statistical_sec}
    sec (soundness)      = {soundness_sec}
Parameters:
    V = {V}
    U = {U}""")

    key = BGVKey(Norm(p), Norm(1, N), Norm(20, N))
    inputs = zk_noise(p, N, U, V, zeroknowledge_sec)

    ciphertext = Norm(p // 2) * inputs

    mask = BGVNoise.encrypt(p, N)
    randomness_0, _, randomness_2 = mask.randomness
    bound = ciphertext.noise(key) / p + randomness_0 * key.noise + randomness_2 * key.private_key
    drown_bound = Norm(2**statistical_sec) * bound
    mask = BGVNoise(mask.plaintext, randomness_0, drown_bound, randomness_2)

    masked = ciphertext + mask

    noise = masked.noise(key)
    if verbose:
        print(f"""Output:
    bound (pre drown) = {bound.max_value} ({bits(bound.max_value)} bits)
    drown bound       = {drown_bound.max_value} ({bits(drown_bound.max_value)} bits)
    final noise       = {noise.max_value} ({bits(noise.max_value)} bits)""")

    result = {
        "U" : U,
        "V" : V,
        "bound" : bound,
        "drown_bound" : drown_bound,
        "noise" : noise
    }
    return result

def table(seed=42):
    params = [
        dict(log_p=64, log_n=16, zeroknowledge_sec=64, soundness_sec=128),
        dict(log_p=128, log_n=16, zeroknowledge_sec=80, soundness_sec=128),
        dict(log_p=128, log_n=16, zeroknowledge_sec=128, soundness_sec=128),
    ]

    print(r"\begin{tabular}{c c c c c c c}")
    print(r"\toprule")
    print(r"log-p & log-n & sec-zk & sec-sound & U & V & log-q \\")
    print(r"\midrule")
    for param in params:
        random.seed(seed)
        log_p = param["log_p"]
        log_n = param["log_n"]
        N = 2**log_n
        zeroknowledge_sec = param["zeroknowledge_sec"]
        soundness_sec = param["soundness_sec"]

        p = ntt_prime(log_n+1, log_p)
        results = drowned_multiplication(p, N, zeroknowledge_sec, soundness_sec)

        U = results["U"]
        V = results["V"]
        bound = results["bound"].max_value
        drown_bound = results["drown_bound"].max_value
        noise = results["noise"].max_value

        log_q = bits(4 * noise)
        q = ntt_prime(log_n+1, log_q)


        print(f"% p = {p} & N = {N} & ZK & soundness & U (value) & V (value) & q = {q} % bound = {bound} & drown_bound = {drown_bound} & noise = {noise}")
        print(f"{log_p} & {log_n} & {zeroknowledge_sec} & {soundness_sec} & {U} & {V} & {log_q} \\\\")
    print(r"\bottomrule")
    print(r"\end{tabular}")

if __name__ == "__main__":
    import fire
    fire.Fire()
