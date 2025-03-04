import sympy
import sys
import shlex
try:
    from typing import Self
except ImportError:
    from typing import Any
    Self = Any

SETUP_PHASE = "setup"
OFFLINE_PHASE = "offline"
ONLINE_PHASE = "online"
INPUT_PHASE = "online"
VERIFICATION_PHASE = "verification"

COMPUTE_PARTY = "compute_party"
INPUT_PARTY = "input_party"
OUTPUT_PARTY = "output_party"
BULLETIN_BOARD = "bulletin_board"
ANY_PARTY = "any_party"

COMPUTE_PARTY_COUNT = sympy.Symbol("n")
INPUT_PARTY_COUNT = sympy.Symbol("nI")
OUTPUT_PARTY_COUNT = sympy.Symbol("nO")
INPUT_COUNT = sympy.Symbol("I")
ADDITION_COUNT = sympy.Symbol("A")
SCALAR_MULTIPLICATION_COUNT = sympy.Symbol("S")
MULTIPLICATION_COUNT = sympy.Symbol("M", positive=True)
PUBLIC_OUTPUT_COUNT = sympy.Symbol("publicO", positive=True)
PRIVATE_OUTPUT_COUNT = sympy.Symbol("privateO", positive=True)

BOOLEAN_ELEMENT = sympy.Symbol("bool")
FIELD_ELEMENT = sympy.Symbol("field")
CIPHERTEXT_FIELD_ELEMENT = sympy.Symbol("ciphertext_field")
CIPHERTEXT_ELEMENT = sympy.Symbol("ciphertext")
COMMITMENT_ELEMENT = sympy.Symbol("commitment")

DECOMMITMENT = sympy.Symbol("decommitment")

PRF_EVALUATION = sympy.Symbol("PRF")
ENCRYPTION_EVALUATION = sympy.Symbol("Enc")
DROWNING_ENCRYPTION_EVALUATION = sympy.Symbol("Enc_drown")
DECRYPTION_EVALUATION = sympy.Symbol("Dec")
DISTRIBUTED_DECRYPTION = sympy.Symbol("DDec")
ZK = sympy.Symbol("ZK")
ZK_VERIFICATION = sympy.Symbol("ZK_verify")
PUBLIC_KEY_ZK = sympy.Symbol("public_ZK")
COMMITMENT_ZK = sympy.Symbol("commitment_ZK")


def conditional(choice, true=1, false=0):
    return sympy.Piecewise((true, choice), (false, True))


class Communication:
    def __init__(self, source, destination, amount):
        self.source = source
        self.destination = destination
        try:
            assert amount.expr == 0
            self.amount = amount.count * amount.what
        except AttributeError:
            self.amount = amount

        assert isinstance(self.amount, (sympy.Expr, int)), type(self.amount)


class CommunicationComplexity:
    def __init__(self):
        self.communication = {}

    def __iadd__(self, communication : Communication) -> Self:
        try:
            self.communication[(communication.source, communication.destination)] += communication.amount
        except LookupError:
            self.communication[(communication.source, communication.destination)] = communication.amount
            setattr(CommunicationComplexity, communication.source + "_to_" + communication.destination, property(lambda x: sympy.simplify(x.communication.get((communication.source, communication.destination), 0))))

        return self

    def update(self, other : Self):
        for (source, destination), amount in other.communication.items():
            self += Communication(source, destination, amount)

    def summary(self):
        return { f"{source}_to_{destination}" : sympy.simplify(v) for (source, destination), v in self.communication.items() }

    def total(self):
        return sympy.simplify(sympy.Add(*self.communication.values()))


class Computation:
    def __init__(self, location, amount):
        self.location = location
        try:
            self.amount = amount.count * amount.expr
        except AttributeError:
            self.amount = amount

        assert isinstance(self.amount, (sympy.Expr, int)), type(self.amount)


class ComputationComplexity:
    def __init__(self):
        self.computation = {}

    def __iadd__(self, computation : Computation) -> Self:
        try:
            self.computation[computation.location] += computation.amount
        except LookupError:
            self.computation[computation.location] = computation.amount
            setattr(ComputationComplexity, computation.location, property(lambda x: sympy.simplify(x.computation.get(computation.location, 0))))

        return self

    def update(self, other : Self):
        for location, amount in other.computation.items():
            self += Computation(location, amount)

    def summary(self):
        return { k : sympy.simplify(v) for k, v in self.computation.items() }

    def total(self):
        return sympy.simplify(sympy.Add(*self.computation.values()))


class Arithmetic:
    def __init__(self, expr=0, count=1):
        self.expr = expr
        self.count = count

    def add(self, other : Self, result):
        assert self.count == other.count
        if self.what == other.what:
            return result(self.expr + other.expr + sympy.var(f"{self.what}_addition"), self.count)
        else:
            return result(self.expr + other.expr + sympy.var(f"{self.what}_{other.what}_addition"), self.count)

    sub = add

    def sum(self, count):
        return type(self)(self.expr + (count - 1) * sympy.var(f"{self.what}_addition"), self.count)

    def mul(self, other, result):
        try:
            if self.what == other.what:
                assert self.count == other.count
                return result(self.expr + other.expr + sympy.var(f"{self.what}_multiplication"), self.count)
            else:
                assert self.count == other.count
                return result(self.expr + other.expr + sympy.var(f"{self.what}_{other.what}_multiplication"), self.count)
        except AttributeError:
            if self.expr == 0:
                return result(self.expr, other * self.count)
            else:
                return result(other * self.expr, self.count)

    def __eq__(self, other):
        assert self.count == other.count
        assert self.what == other.what
        return Boolean(self.expr + other.expr + sympy.var(f"{self.what}_equality"), self.count)
    __ne__ = __eq__

    def sample(self):
        return type(self)(sympy.Symbol(f"{self.what}_sampling"), self.count)


class Boolean(Arithmetic):
    what = BOOLEAN_ELEMENT

    def __mul__(self, other):
        if isinstance(other, (sympy.Expr, int)):
            return super().mul(other, Boolean)
        else:
            return NotImplemented
    __rmul__ = __mul__

BOOLEAN = Boolean()


class Field(Arithmetic):
    what = FIELD_ELEMENT
    def __add__(self, other):
        if isinstance(other, Field):
            return super().add(other, Field)
        else:
            return NotImplemented
    __radd__ = __add__
    __sub__ = __add__
    __rsub__ = __sub__

    def __mul__(self, other):
        if isinstance(other, (Field, sympy.Expr, int)):
            return super().mul(other, Field)
        else:
            return NotImplemented
    __rmul__ = __mul__

FIELD = Field()


class CiphertextField(Arithmetic):
    what = CIPHERTEXT_FIELD_ELEMENT
    def __add__(self, other):
        if isinstance(other, CiphertextField):
            return super().add(other, CiphertextField)
        else:
            return NotImplemented
    __radd__ = __add__
    __sub__ = __add__
    __rsub__ = __sub__

    def __mul__(self, other):
        if isinstance(other, (CiphertextField, Field, sympy.Expr, int)):
            return super().mul(other, CiphertextField)
        else:
            return NotImplemented
    __rmul__ = __mul__

    def __mod__(self, other):
        assert isinstance(other, Field)
        assert self.count == other.count
        return Field(self.expr + other.expr + sympy.var(f"{self.what}_mod_{other.what}"), self.count)

CIPHERTEXT_FIELD = CiphertextField()


class Ciphertext(Arithmetic):
    what = CIPHERTEXT_ELEMENT

    def __add__(self, other):
        if isinstance(other, (Ciphertext, Field)):
            return super().add(other, Ciphertext)
        else:
            return NotImplemented
    __radd__ = __add__
    __sub__ = __add__
    __rsub__ = __sub__

    def __mul__(self, other):
        if isinstance(other, (Ciphertext, Field, sympy.Expr, int)):
            return super().mul(other, Ciphertext)
        else:
            return NotImplemented
    __rmul__ = __mul__

CIPHERTEXT = Ciphertext()


class Commitment(Arithmetic):
    what = COMMITMENT_ELEMENT

    def __add__(self, other):
        if isinstance(other, (Commitment, Field)):
            return super().add(other, Ciphertext)
        else:
            return NotImplemented
    __radd__ = __add__
    __sub__ = __add__
    __rsub__ = __sub__

    def __mul__(self, other):
        if isinstance(other, (Field, sympy.Expr, int)):
            return super().mul(other, Commitment)
        else:
            return NotImplemented
    __rmul__ = __mul__

COMMITMENT = Commitment()


class Complexity:
    def __init__(self):
        self.communication = CommunicationComplexity()
        self.computation = ComputationComplexity()

    def __iadd__(self, complexity : Communication | Computation) -> Self:
        if isinstance(complexity, Communication):
            self.communication += complexity
        elif isinstance(complexity, Computation):
            self.computation += complexity
        else:
            raise ValueError(f"Not a valid complexity object (type: {type(complexity)}): {complexity}")

        return self

    def update(self, other : Self):
        self.communication.update(other.communication)
        self.computation.update(other.computation)


class CombinedManager:
    def __init__(self, *managers):
        self.managers = list(managers)

    def __enter__(self):
        for manager in self.managers:
            manager.__enter__()

    def __exit__(self, exc_type, exc_value, traceback):
        return any(manager.__exit__(exc_type, exc_value, traceback) for manager in self.managers)

combine = CombinedManager


class Protocol:
    def __init__(self):
        self.phases = {}
        self.current_phase = None
        self.current_party = None
        self.factor = 1

    @property
    def phase(self):
        return self.phases.get(self.current_phase, None)
    @phase.setter
    def phase(self, value):
        self.phases[self.current_phase] = value
    @property
    def party(self):
        return self.current_party

    def communicate(self, destination, amount, factor=1):
        assert self.party is not None
        self.phase += Communication(self.party, destination, self.factor * amount * factor)

    def compute(self, amount, factor=1):
        assert self.party is not None
        self.phase += Computation(self.party, self.factor * amount * factor)

    def in_phase(self, phase):
        try:
            self.phases[phase]
        except LookupError:
            self.phases[phase] = Complexity()
        return ProtocolPhaseManager(phase, self)

    def at_party(self, party):
        return ProtocolPartyManager(party, self)

    def at_each_party(self, party, party_count):
        return combine(ProtocolPartyManager(party, self), ProtocolFactorManager(party_count, self))

    def for_each(self, *what):
        return ProtocolFactorManager(sympy.Mul(*what), self)

    def if_conditionally(self, condition, true=1, false=0):
        return ProtocolFactorManager(conditional(condition, true, false), self)

    def else_conditionally(self, condition, false=1, true=0):
        return ProtocolFactorManager(conditional(not condition, false, true), self)

    def rand(self, what, factor=1):
        assert self.party is None
        try:
            what = what.what
        except AttributeError:
            pass
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(sympy.Symbol(f"public_random_{what}"), factor=self.parties + factor) # compute something yourself and (paries-1) things after receiving from broadcast; then compute one thing for each output
            self.broadcast(sympy.Symbol(f"public_random_{what}"))

    def encrypt(self, factor=1):
        self.compute(ENCRYPTION_EVALUATION, factor=factor)

    def verifiable(self, what):
        assert self.party is COMPUTE_PARTY
        self.compute(what)
        self.broadcast(what)
        with self.for_each(self.parties - 1):
            self.compute(sympy.Symbol(f"{what}_verify"))

    def zk(self):
        self.verifiable(ZK)

    def encrypt_drowning(self):
        self.compute(DROWNING_ENCRYPTION_EVALUATION)

    def decrypt_distributed(self):
        assert self.party is COMPUTE_PARTY
        self.compute(CIPHERTEXT_FIELD.sample())
        self.decrypt()
        self.broadcast(CIPHERTEXT_FIELD)
        self.compute(CIPHERTEXT_FIELD.sum(self.parties))
        self.compute(CIPHERTEXT_FIELD % FIELD)

    def decrypt_distributed_shares(self):
        assert self.party is COMPUTE_PARTY
        self.compute(CIPHERTEXT_FIELD.sample())
        self.decrypt()
        self.broadcast(CIPHERTEXT_FIELD)
        # one party: self.compute(CIPHERTEXT_FIELD.sum(self.parties) + CIPHERTEXT_FIELD)

    def decrypt_distributed_verifiably(self):
        self.verifiable(DISTRIBUTED_DECRYPTION)

    def decrypt(self, factor=1):
        self.compute(DECRYPTION_EVALUATION, factor=factor)

    def broadcast(self, amount, factor=1):
        self.communicate(BULLETIN_BOARD, amount, factor=factor)

    def commit(self, factor=1):
        assert self.party is COMPUTE_PARTY
        self.compute(COMMITMENT, factor=factor)
        self.broadcast(COMMITMENT, factor=factor)

    def decommit(self, factor=1):
        assert self.party is COMPUTE_PARTY
        self.broadcast(DECOMMITMENT, factor=factor)
        with self.for_each(self.parties - 1):
            self.compute(COMMITMENT, factor=factor)
            self.compute(COMMITMENT == COMMITMENT, factor=factor)


class ProtocolPhaseManager:
    def __init__(self, phase, protocol : Protocol):
        self.phase = phase
        self.protocol = protocol

    def __enter__(self):
        try:
            self.previous_phase
            raise RuntimeError("Cannot use the same manager again")
        except AttributeError:
            pass

        self.previous_phase = self.protocol.current_phase
        self.protocol.current_phase = self.phase

    def __exit__(self, exc_type, exc_value, traceback):
        self.protocol.current_phase = self.previous_phase
        del self.previous_phase


class ProtocolPartyManager:
    def __init__(self, party, protocol : Protocol):
        self.party = party
        self.protocol = protocol

    def __enter__(self):
        try:
            self.previous_party
            raise RuntimeError("Cannot use the same manager again")
        except AttributeError:
            pass

        self.previous_party = self.protocol.current_party
        self.protocol.current_party = self.party

    def __exit__(self, exc_type, exc_value, traceback):
        self.protocol.current_party = self.previous_party
        del self.previous_party


class ProtocolFactorManager:
    def __init__(self, factor, protocol : Protocol):
        self.factor = factor
        self.protocol = protocol

    def __enter__(self):
        try:
            self.previous_factor
            raise RuntimeError("Cannot use the same manager again")
        except AttributeError:
            pass

        self.previous_factor = self.protocol.factor
        self.protocol.factor *= self.factor

    def __exit__(self, exc_type, exc_value, traceback):
        self.protocol.factor = self.previous_factor
        del self.previous_factor


class SPDZLike(Protocol):
    def AddShare(self):
        assert self.party is COMPUTE_PARTY
        self.compute(FIELD + FIELD, 2) # adjust share and MAC share

    def AddCShare(self):
        assert self.party is COMPUTE_PARTY
        # one party adds constant to share
        self.compute(FIELD + FIELD * FIELD) # adjust MAC share

    SubShare = AddShare

    def MulShare(self):
        assert self.party is COMPUTE_PARTY
        self.compute(FIELD * FIELD, 2) # adjust share and MAC share

    def Open(self):
        """KellerPastroRotaru2017: Fig. 4"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.broadcast(FIELD)
            self.compute(FIELD.sum(self.parties))

    def Check(self, count):
        """KellerPastroRotaru2017: Fig. 4"""
        assert self.party is None
        self.rand(FIELD, count)
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD * FIELD, 2 * count)
            self.compute(FIELD.sum(count), 2)
        self.MACCheck()

    def MACCheck(self):
        """KellerPastroRotaru2017: Fig. 5"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD - FIELD * FIELD)
            self.commit()
            self.decommit()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD.sum(self.parties) != FIELD)

OurProtocol_delayed_output=True
class OurProtocol(Protocol):
    def prf(self):
        self.compute(PRF_EVALUATION)

    def public_zk(self):
        self.verifiable(PUBLIC_KEY_ZK)

    def mac_check(self):
        if self.party != COMPUTE_PARTY: # compute parties already computed the PRF in the offline verification
            with self.for_each(self.parties):
                self.prf()
            self.compute(FIELD.sum(self.parties))
        self.compute(FIELD * FIELD + FIELD)
        self.compute(FIELD == FIELD)

    def authenticate(self):
        assert self.party is COMPUTE_PARTY
        with self.for_each(self.parties):
            self.prf()
        with self.for_each(self.parties - 1):
            self.encrypt_drowning()
            self.compute(FIELD * CIPHERTEXT + CIPHERTEXT)
            self.communicate(COMPUTE_PARTY, CIPHERTEXT)
            self.decrypt()
        self.compute(FIELD * FIELD + FIELD)
        self.compute(FIELD.sum(self.parties))

    def verify_authenticate(self):
        assert self.party is COMPUTE_PARTY
        with self.for_each(self.parties - 1):
            self.prf()
            self.encrypt_drowning()
            self.compute(FIELD * CIPHERTEXT + CIPHERTEXT)
            self.compute(CIPHERTEXT == CIPHERTEXT)
        self.compute(FIELD.sum(self.parties)) # compute the "global" PRF (used later in the MAC check)

    def open(self, encrypted=False):
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            if encrypted:
                self.encrypt(2)
                self.broadcast(CIPHERTEXT, 2)
            else:
                self.broadcast(FIELD, 2)
                self.compute(FIELD.sum(self.parties))

    def finish_open(self, encrypted=False):
        assert self.party is None
        if encrypted:
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.decrypt(2 * self.parties)
                self.compute(FIELD.sum(self.parties))

    def verify_open(self):
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            with self.for_each(self.parties - 1):
                self.mac_check()

    def open_to(self, recipient, encrypted=False):
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            if encrypted:
                self.encrypt(2)
                self.communicate(recipient, CIPHERTEXT, 2)
            else:
                self.communicate(recipient, FIELD, 2)
        if not encrypted:
            with self.at_party(recipient):
                self.compute(FIELD.sum(self.parties))

    def finish_open_to(self, recipient, encrypted=False):
        assert self.party is None
        if encrypted:
            with self.at_party(recipient):
                self.decrypt(2 * self.parties)
                self.compute(FIELD.sum(self.parties))

    def verify_open_to(self, recipient):
        assert self.party is None
        with self.at_party(recipient):
            with self.for_each(self.parties):
                self.mac_check()

    def prepare_input(self):
        assert self.party is None
        if INPUT_PARTY == COMPUTE_PARTY:
            with self.at_party(COMPUTE_PARTY):
                with self.for_each(self.parties):
                    self.compute(FIELD.sample())
                    self.zk()
                self.compute(FIELD.sum(self.parties))
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.authenticate()
        else:
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD.sample())
                self.zk()
                self.authenticate()

    def prepare_multiplication(self):
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            with self.for_each(3):
                self.compute(FIELD.sample())
                self.public_zk()
            self.compute(CIPHERTEXT * CIPHERTEXT - CIPHERTEXT)
            self.decrypt_distributed_verifiably()
            self.compute(FIELD + FIELD) # for all but one party
            with self.for_each(self.parties):
                self.compute(CIPHERTEXT + CIPHERTEXT)
            with self.for_each(3):
                self.authenticate()

    def prepare_output(self):
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD.sample())
            self.zk()
            with self.for_each(2):
                self.authenticate()

    def input(self):
        assert self.party is None
        if INPUT_PARTY != COMPUTE_PARTY:
            self.open_to(INPUT_PARTY)

        with self.at_party(INPUT_PARTY):
            self.compute(FIELD - FIELD)
            self.broadcast(FIELD)
        with self.at_party(COMPUTE_PARTY): # only one party has to add the mask to their share
            self.compute(FIELD + FIELD)

    def verify_input(self):
        assert self.party is None
        self.verify_open_to(INPUT_PARTY)

    def multiply(self):
        assert self.party is None
        with self.for_each(2): # for a, b of the triple
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD - FIELD, 2) # for each component of the authenticated share
            self.open()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD * FIELD, 4) # [[a]] * v, u * [[b]]
            self.compute(FIELD + FIELD, 4) # [[c]] + [[a]] * v + u * [[b]]
        with self.at_party(COMPUTE_PARTY): # only one party has to add u * v to one part of the share
            self.compute(FIELD * FIELD)
            self.compute(FIELD + FIELD)

    def verify_multiply(self):
        assert self.party is None
        with self.for_each(2): # for a, b of the triple
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                with self.for_each(self.parties - 1):
                    self.compute(FIELD - FIELD) # for the tag component of the authenticated share
            self.verify_open()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            with self.for_each(self.parties - 1):
                 # for the tag component of the authenticated share
                self.compute(FIELD * FIELD, 2) # [[a]] * v, u * [[b]]
                self.compute(FIELD + FIELD, 2) # [[c]] + [[a]] * v + u * [[b]]
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1): # only one party has to add u * v to one part of the share, one party already did this
            self.compute(FIELD * FIELD)
            self.compute(FIELD + FIELD)

    def public_output(self):
        assert self.party is None
        with self.if_conditionally(self.is_non_linear): # open(x - r) for non-linear circuits
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD - FIELD, 2) # for each component of the authenticated share
        self.open()
        if OurProtocol_delayed_output:
            with self.if_conditionally(self.is_non_linear):
                self.open(encrypted=True)

    def finish_public_output(self):
        assert self.party is None
        self.verify_open()
        with self.if_conditionally(self.is_non_linear):
            if OurProtocol_delayed_output:
                self.finish_open(encrypted=True)
            else:
                self.open()
            self.verify_open()
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD + FIELD)

    def private_output(self):
        assert self.party is None
        with self.if_conditionally(self.is_non_linear): # open(x - r) for non-linear circuits
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD - FIELD, 2) # for each component of the authenticated share
            self.open()
            if OurProtocol_delayed_output:
                self.open_to(OUTPUT_PARTY, encrypted=True)
        with self.else_conditionally(self.is_non_linear): # directly open for linear circuits
            self.open_to(OUTPUT_PARTY)

    def finish_private_output(self):
        assert self.party is None
        with self.if_conditionally(self.is_non_linear): # open(x - r) for non-linear circuits
            self.verify_open()
            if OurProtocol_delayed_output:
                self.finish_open_to(OUTPUT_PARTY, encrypted=True)
            else:
                self.open_to(OUTPUT_PARTY)
        self.verify_open_to(OUTPUT_PARTY)
        with self.if_conditionally(self.is_non_linear):
            with self.at_party(OUTPUT_PARTY):
                self.compute(FIELD + FIELD)

    def __init__(self, parties=COMPUTE_PARTY_COUNT, input_parties=INPUT_PARTY_COUNT, output_parties=OUTPUT_PARTY_COUNT, inputs=INPUT_COUNT, additions=ADDITION_COUNT, scalar_multiplications=SCALAR_MULTIPLICATION_COUNT, multiplications=MULTIPLICATION_COUNT, public_outputs=PUBLIC_OUTPUT_COUNT, private_outputs=PRIVATE_OUTPUT_COUNT):
        super().__init__()
        self.parties = sympy.simplify(parties)
        self.input_parties = sympy.simplify(input_parties)
        self.output_parties = sympy.simplify(output_parties)
        self.inputs = sympy.simplify(inputs)
        self.additions = sympy.simplify(additions)
        self.scalar_multiplications = sympy.simplify(scalar_multiplications)
        self.multiplications = sympy.simplify(multiplications)
        self.public_outputs = sympy.simplify(public_outputs)
        self.private_outputs = sympy.simplify(private_outputs)
        self.is_non_linear = (self.multiplications > 0)

        with combine(self.in_phase(SETUP_PHASE), self.at_each_party(COMPUTE_PARTY, self.parties)):
            # TODO: setup for public key cryptography, signatures, etc.
            # 3: MAC key share, PRF key, PRNG key
            self.compute(FIELD.sample(), 3)
            self.commit(3)
            with self.if_conditionally(self.is_non_linear):
                self.compute(FIELD.sample(), 3)
                self.commit(3)

        with self.in_phase(OFFLINE_PHASE):
            with self.for_each(self.inputs):
                self.prepare_input()
            with self.if_conditionally(self.is_non_linear):
                with self.for_each(self.multiplications):
                    self.prepare_multiplication()
                with self.for_each(self.private_outputs + self.public_outputs):
                    self.prepare_output()

        with self.in_phase(ONLINE_PHASE):
            # inputs
            with self.for_each(self.inputs):
                self.input()
            # linear operations
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                with self.for_each(self.additions):
                    self.compute(FIELD + FIELD, 2) # for each component of the authenticated share
                with self.for_each(self.scalar_multiplications):
                    self.compute(FIELD * FIELD, 2) # for each component of the authenticated share
            # multiplications
            with self.for_each(self.multiplications):
                self.multiply()
            # outputs
            with self.for_each(self.private_outputs):
                self.private_output()
            with self.for_each(self.public_outputs):
                self.public_output()

        with self.in_phase(VERIFICATION_PHASE):
            # open setup keys
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.decommit(3) # MAC key share, PRF key, PRNG key

            # verify offline phase
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                # inputs
                with self.for_each(self.inputs):
                    self.verify_authenticate()
                with self.if_conditionally(self.is_non_linear):
                    # multiplications
                    with self.for_each(self.multiplications, 3):
                        self.verify_authenticate()
                    # outputs
                    with self.for_each(self.private_outputs + self.public_outputs):
                        self.verify_authenticate()

            # verify inputs
            with self.for_each(self.inputs):
                self.verify_input()
            # verify linear operations
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                with self.for_each(self.parties - 1):
                    with self.for_each(self.additions):
                        self.compute(FIELD + FIELD) # for the tag component of the authenticated share
                    with self.for_each(self.scalar_multiplications):
                        self.compute(FIELD * FIELD) # for the tag component of the authenticated share
            # verify multiplications
            with self.for_each(self.multiplications):
                self.verify_multiply()

            if OurProtocol_delayed_output: # send decryption keys
                with self.if_conditionally(self.public_outputs > 0):
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.broadcast(FIELD)
                with self.if_conditionally(self.private_outputs > 0):
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.communicate(OUTPUT_PARTY, FIELD)

            # verify outputs
            with self.if_conditionally(self.is_non_linear):
                with self.at_each_party(COMPUTE_PARTY, self.parties):
                    self.decommit(3) # MAC key share, PRF key, PRNG key
                    # verify second part of the offline phase
                    with self.for_each(self.private_outputs + self.public_outputs):
                        self.verify_authenticate()
            with self.for_each(self.private_outputs):
                self.finish_private_output()
            with self.for_each(self.public_outputs):
                self.finish_public_output()
            # finalize
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.broadcast(BOOLEAN)
            with self.at_each_party(INPUT_PARTY, self.input_parties):
                self.broadcast(BOOLEAN)
            with self.at_each_party(OUTPUT_PARTY, self.output_parties):
                self.broadcast(BOOLEAN)

Ours = OurProtocol

BaumOrsiniScholl2016_batched_MAC_check = True
BaumOrsiniScholl2016_distinct_setup_phase = True
class BaumOrsiniScholl2016(Protocol):
    """
    Title: Efficient Secure Multiparty Computation with Identifiable Abort
    Authors: Carsten Baum, Emmanuela Orsini, Peter Scholl
    Paper: https://eprint.iacr.org/2016/187.pdf
    """

    def RandShCtxt(self):
        """Fig. 10"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD.sample())
            self.zk()

    def ShareDec(self, new_ctxt):
        """Fig. 10"""
        assert self.party is None
        self.RandShCtxt()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT.sum(self.parties + 1)) # sum up self.parties ciphertexts and one input ciphertext
            self.decrypt_distributed_verifiably()
            self.compute(FIELD - FIELD) # one party computes decryption_result - r_i, others compute -r_i
            if new_ctxt:
                self.compute(CIPHERTEXT - FIELD)

    def PrivateDec(self):
        """Fig. 10"""
        assert self.party is None
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD.sample())
            self.zk()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT + CIPHERTEXT)
            self.decrypt_distributed_verifiably()
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD - FIELD)

    def Setup(self):
        """Fig. 11"""
        assert self.party is None
        assert self.phase is None
        w = self.parties * (self.multiplications + self.inputs)

        with self.in_phase(SETUP_PHASE):
            pass # TODO: KeyGen

        def SETUP():
            if BaumOrsiniScholl2016_distinct_setup_phase:
                return self.in_phase(SETUP_PHASE)
            else:
                return self.in_phase(OFFLINE_PHASE)
        def OFFLINE():
            return self.in_phase(OFFLINE_PHASE)

        with SETUP():
            with self.for_each(2 * self.parties):
                self.RandShCtxt()
        with OFFLINE():
            with self.for_each(w):
                self.RandShCtxt()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            # compute alpha hat and beta hat
            with SETUP():
                with self.for_each(self.parties):
                    self.compute(CIPHERTEXT.sum(self.parties))
            with OFFLINE():
                with self.for_each(self.parties, w):
                    self.compute(CIPHERTEXT.sum(self.parties))
            # compute alpha and beta
            with SETUP():
                with self.for_each(self.parties):
                    with self.for_each(self.parties):
                        self.compute(CIPHERTEXT * CIPHERTEXT)
                    self.compute(CIPHERTEXT.sum(self.parties))
            with OFFLINE():
                with self.for_each(self.parties, w):
                    with self.for_each(self.parties):
                        self.compute(CIPHERTEXT * CIPHERTEXT)
                    self.compute(CIPHERTEXT.sum(self.parties))
        # compute verification keys
        with SETUP():
            with self.for_each(self.parties):
                self.PrivateDec()
        with OFFLINE():
            with self.for_each(self.parties, w):
                self.PrivateDec()

    def Auth(self):
        """Fig. 12"""
        assert self.party is None

        with self.at_each_party(COMPUTE_PARTY, self.parties):
            with self.for_each(self.parties):
                self.compute(CIPHERTEXT * CIPHERTEXT + CIPHERTEXT)
        with self.for_each(self.parties):
            self.PrivateDec()

    def Triple(self):
        """Fig. 12"""
        assert self.party is None

        with self.for_each(2):
            self.RandShCtxt()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT.sum(self.parties) * CIPHERTEXT.sum(self.parties))
        self.ShareDec(True)
        with self.for_each(self.parties, 3):
            self.Auth()

    def Input(self):
        """Fig. 12"""
        assert self.party is None

        self.RandShCtxt()
        with self.for_each(self.parties):
            self.Auth()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT.sum(self.parties))
        self.PrivateDec()

    def Open(self, check=None):
        """Fig. 3"""
        assert self.party is None
        if check is None:
            if BaumOrsiniScholl2016_batched_MAC_check:
                check = False
            else:
                check = True

        if check:
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.broadcast(FIELD)
                self.compute(FIELD.sum(self.parties))
        else:
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.broadcast(FIELD, self.parties + 1) # share and signature of size self.parties
                with self.for_each(self.parties - 1):
                    self.Verify()
                self.compute(FIELD.sum(self.parties))

    def Output(self):
        """Fig. 6"""
        assert self.party is None
        if BaumOrsiniScholl2016_batched_MAC_check:
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.broadcast(FIELD)
                self.compute(FIELD.sum(self.parties))
            # rest is done in OutputCheck
        else:
            self.Open(check=True)

    def OutputCheck(self, count):
        """Fig. 6"""
        assert self.party is None
        if BaumOrsiniScholl2016_batched_MAC_check:
            self.rand(FIELD, count) # a_1, ...
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                with self.for_each(self.parties): # sum a_j sigma_j
                    self.compute(FIELD * FIELD, count)
                    self.compute(FIELD.sum(count))
                self.broadcast(FIELD, self.parties) # one signature
                with self.for_each(self.parties - 1):
                    self.Verify(multiplications=count)
        else:
            pass # everything is already verified

    def Verify(self, multiplications=0, constant=False):
        """Sec. 4"""
        assert self.party is not None
        if multiplications:
            self.compute(FIELD * FIELD, multiplications)
            self.compute(FIELD.sum(multiplications))
        if constant:
            self.compute(FIELD - FIELD * FIELD)
        self.compute(FIELD + FIELD * FIELD)
        with self.for_each(self.parties):
            self.compute(FIELD * FIELD)
        self.compute(FIELD.sum(self.parties))
        self.compute(FIELD == FIELD)

    def AddShare(self):
        """Sec. 5"""
        assert self.party is not None
        with self.for_each(self.parties - 1):
            self.compute(FIELD + FIELD) # operation on beta
        self.compute(FIELD + FIELD) # operation on share
        with self.for_each(self.parties):
            self.compute(FIELD + FIELD) # operation on part of signature

    def AddCShare(self):
        assert self.party is not None
        self.compute(FIELD - FIELD * FIELD) # operation on beta
        # one party has to add the constant to the share

    SubShare = AddShare

    def MulShare(self):
        assert self.party is not None
        with self.for_each(self.parties - 1):
            self.compute(FIELD * FIELD) # operation on beta
        self.compute(FIELD * FIELD) # operation on share
        with self.for_each(self.parties):
            self.compute(FIELD * FIELD) # operation on part of signature

    def __init__(self, parties=COMPUTE_PARTY_COUNT, input_parties=INPUT_PARTY_COUNT, output_parties=OUTPUT_PARTY_COUNT, inputs=INPUT_COUNT, additions=ADDITION_COUNT, scalar_multiplications=SCALAR_MULTIPLICATION_COUNT, multiplications=MULTIPLICATION_COUNT, public_outputs=PUBLIC_OUTPUT_COUNT, private_outputs=PRIVATE_OUTPUT_COUNT):
        super().__init__()
        self.parties = sympy.simplify(parties)
        self.input_parties = sympy.simplify(input_parties)
        self.output_parties = sympy.simplify(output_parties)
        self.inputs = sympy.simplify(inputs)
        self.additions = sympy.simplify(additions)
        self.scalar_multiplications = sympy.simplify(scalar_multiplications)
        self.multiplications = sympy.simplify(multiplications)
        self.public_outputs = sympy.simplify(public_outputs)
        self.private_outputs = sympy.simplify(private_outputs)

        # TODO: handle public verifiability
        # TODO: handle input parties that are not compute parties

        self.Setup()

        with self.in_phase(OFFLINE_PHASE):
            with self.for_each(self.inputs):
                self.Input()
            with self.for_each(self.multiplications):
                self.Triple()

        with self.in_phase(ONLINE_PHASE):
            # inputs
            with self.for_each(self.inputs):
                with self.at_party(COMPUTE_PARTY):
                    self.compute(FIELD - FIELD)
                    self.broadcast(FIELD)
                with self.at_each_party(COMPUTE_PARTY, self.parties):
                    self.SubShare()
            # linear operations
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                with self.for_each(self.additions):
                    self.AddShare()
                with self.for_each(self.scalar_multiplications):
                    self.MulShare()
            # multiplications
            with self.for_each(self.multiplications):
                with self.for_each(2): # a,b of the triple
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.SubShare()
                    self.Open()
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.MulShare()
                        self.AddShare()
                with self.at_party(COMPUTE_PARTY):
                    self.compute(FIELD * FIELD)
                    self.AddCShare()
            # outputs
            with self.for_each(self.public_outputs + self.private_outputs): # TODO: handle private outputs
                self.Output()

        with self.in_phase(VERIFICATION_PHASE):
            self.OutputCheck(2 * self.multiplications + self.public_outputs + self.private_outputs)

SpiniFehr2016_input_parties_known = True
class SpiniFehr2016(SPDZLike):
    """
    Title: Cheater Detection in SPDZ Multiparty Computation
    Authors: Gabriele Spini, Serge Fehr
    Paper: https://ir.cwi.nl/pub/25035/25035.pdf
    """

    def Open(self):
        """Sec. 2.3"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
            self.communicate(COMPUTE_PARTY, FIELD) # send to king player
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD.sum(self.parties)) # reconstruct
            with self.for_each(self.parties - 1):
                self.communicate(COMPUTE_PARTY, FIELD) # send to other players

    def Check(self, count):
        assert False # override

    def MACCheck(self):
        assert False # override

    def PublicOpening(self):
        """Appendix A"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.broadcast(FIELD) # every party broadcasts their share
        with self.at_party(COMPUTE_PARTY):
            with self.for_each(self.parties):
                self.broadcast(FIELD) # king player broadcasts shares of all parties
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            with self.for_each(self.parties):
                self.compute(FIELD == FIELD) # compute the above shares

            self.compute(FIELD.sum(self.parties)) # compute the result
            self.broadcast(FIELD) # broadcast what was received from king player
            with self.for_each(self.parties):
                self.compute(FIELD == FIELD) # check that reconstruction is the same

    def BlockCheck(self, count):
        """Appendix A"""
        assert self.party is None
        self.rand(FIELD) # e
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            with self.for_each(count):
                self.compute(FIELD * FIELD) # powers of e
                self.MulShare() # e^h * [[z_h]]
            with self.for_each(count - 1):
                self.AddCShare() # sum_h e^h [[z_h]]
        self.PublicOpening()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD - FIELD * FIELD) # MAC(z) - z [alpha]
        self.ZeroTest()

    def ZeroTest(self):
        """Appendix A.1"""
        assert self.party is None

        # multiplication:
        with self.for_each(2): # a,b of the triple
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.SubShare()
            SPDZLike.Open(self) # with broadcast opening
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.MulShare()
                self.AddShare()
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD * FIELD)
            self.AddCShare()

        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.commit()
            self.decommit()
            self.compute(FIELD.sum(self.parties) == FIELD) # zero check r * x

    def InputShare(self):
        """Appendix C"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties - 2):
            self.communicate(COMPUTE_PARTY, FIELD, 2) # send values to king player
        with self.at_party(COMPUTE_PARTY):
            with self.for_each(self.parties - 1):
                self.communicate(COMPUTE_PARTY, FIELD, 2) # forward to input party
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD.sum(self.parties)) # r
            self.compute((FIELD * FIELD - FIELD.sum(self.parties)) == FIELD) # r beta_i - sum_j gamma_j == 0
            self.compute(FIELD - FIELD) # x - r
            self.broadcast(FIELD)
            self.AddCShare()

    RandShCtxt = BaumOrsiniScholl2016.RandShCtxt
    Reshare = BaumOrsiniScholl2016.ShareDec
    """equivalent to SPDZ, Fig. 4"""

    def PBracket(self, for_each_party=True):
        """SPDZ, Fig. 5"""
        assert self.party is None
        with self.for_each(self.parties if for_each_party else 1):
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(CIPHERTEXT * CIPHERTEXT)
            self.Reshare(False)

    def PAngle(self):
        """SPDZ, Fig. 6"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT * CIPHERTEXT)
        self.Reshare(False)

    def RandomShare(self):
        """NOT IN PROTOCOL. A shortened version of Pair seems appropriate."""
        self.RandShCtxt()
        self.PAngle()

    def Pair(self):
        """SPDZ, Fig. 7"""
        assert self.party is None
        self.RandShCtxt()
        self.PBracket(not SpiniFehr2016_input_parties_known)
        self.PAngle()

    def Triple(self):
        """SPDZ, Fig. 7"""
        assert self.party is None
        with self.for_each(2):
            self.RandShCtxt()
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(CIPHERTEXT.sum(self.parties))
            self.PAngle()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT * CIPHERTEXT)
        self.Reshare(True)
        self.PAngle()

    def Output(self):
        """Appendix C. First part of OutputCheck"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.broadcast(FIELD)
            self.compute(FIELD.sum(self.parties))

    def OutputCheck(self):
        """Appendix C. Rest of OutputCheck"""
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD - FIELD * FIELD) # input to zero test
        self.ZeroTest()

    def Setup(self):
        """SPDZ, Fig. 7"""
        # TODO: KeyGen
        with self.for_each(2): # alpha, beta
            self.RandShCtxt()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT.sum(self.parties))
        # don't need PBracket on alpha as we use different MAC checking

    def __init__(self, parties=COMPUTE_PARTY_COUNT, input_parties=INPUT_PARTY_COUNT, output_parties=OUTPUT_PARTY_COUNT, inputs=INPUT_COUNT, additions=ADDITION_COUNT, scalar_multiplications=SCALAR_MULTIPLICATION_COUNT, multiplications=MULTIPLICATION_COUNT, public_outputs=PUBLIC_OUTPUT_COUNT, private_outputs=PRIVATE_OUTPUT_COUNT):
        super().__init__()
        self.parties = sympy.simplify(parties)
        self.input_parties = sympy.simplify(input_parties)
        self.output_parties = sympy.simplify(output_parties)
        self.inputs = sympy.simplify(inputs)
        self.additions = sympy.simplify(additions)
        self.scalar_multiplications = sympy.simplify(scalar_multiplications)
        self.multiplications = sympy.simplify(multiplications)
        self.public_outputs = sympy.simplify(public_outputs)
        self.private_outputs = sympy.simplify(private_outputs)

        # TODO: sacrificing
        block_size = 2 * self.multiplications / self.parties # two values per multiplication are opened in the online phase
        block_count = self.parties
        output_count = self.public_outputs + self.private_outputs # TODO: handle private output
        zero_tests = block_count + output_count

        with self.in_phase(SETUP_PHASE):
            self.Setup()

        with self.in_phase(OFFLINE_PHASE):
            with self.for_each(self.inputs + zero_tests):
                self.Pair()
            with self.for_each(self.multiplications + zero_tests):
                self.Triple()

        with self.in_phase(ONLINE_PHASE):
            # inputs
            with self.for_each(self.inputs):
                self.InputShare()
            # linear operations
            with self.for_each(self.additions):
                with self.at_each_party(COMPUTE_PARTY, self.parties):
                    self.AddShare()
            with self.for_each(self.scalar_multiplications):
                with self.at_each_party(COMPUTE_PARTY, self.parties):
                    self.MulShare()
            # multiplications
            with self.for_each(self.multiplications):
                with self.for_each(2): # a,b of the triple
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.SubShare()
                    self.Open()
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.MulShare()
                        self.AddShare()
                with self.at_party(COMPUTE_PARTY):
                    self.compute(FIELD * FIELD)
                    self.AddCShare()
            with self.for_each(block_count):
                self.BlockCheck(block_size)
            # outputs
            with self.for_each(output_count):
                self.Output()

        with self.in_phase(VERIFICATION_PHASE):
            with self.for_each(output_count):
                self.OutputCheck()


CunninghamFullerYakoubov2016_batched_MAC_check = True
class CunninghamFullerYakoubov2016(Protocol):
    """
    Title: Catching MPC Cheaters: Identification and Openability
    Authors: Robert Cunningham, Benjamin Fuller, Sophia Yakoubov
    Paper: https://eprint.iacr.org/2016/611.pdf
    """

    # some subprotocols are equivalent to subprotocols in BaumOrsiniScholl2016
    RandShCtxt = BaumOrsiniScholl2016.RandShCtxt
    ShareDec = BaumOrsiniScholl2016.ShareDec

    def CHESSRec(self):
        """Fig. 3"""
        assert self.party is COMPUTE_PARTY
        with self.for_each(self.parties - 1):
            self.compute(COMMITMENT)
            self.compute(COMMITMENT == COMMITMENT)
        self.compute(FIELD.sum(self.parties))

    def CHESSPrivOpen(self):
        """Fig. 4"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(ZK, 2) # one ZKP for encrypting [x]_i and r_i
            # not mentioned explicitly but we should broadcast the proofs, otherwise we could not verify them at all parties:
            self.broadcast(ZK, 2)

    def CHESSPrivRec(self):
        """Fig. 4"""
        assert self.party is None
        # not mentioned explicitly but we should call CHESSPrivOpen:
        self.CHESSPrivOpen()

        with self.at_each_party(COMPUTE_PARTY, self.parties):
            with self.for_each(self.parties):
                self.compute(ZK_VERIFICATION)
        with self.at_party(COMPUTE_PARTY):
            with self.for_each(self.parties):
                self.compute(DECRYPTION_EVALUATION)
            self.compute(FIELD.sum(self.parties))

    def MACCheck(self):
        """Fig. 5"""
        assert self.party is None
        self.rand(FIELD)
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD * FIELD) # a = rx
            self.compute(FIELD * FIELD) # b_i = r MAC(x)_i
            self.compute(FIELD - FIELD * FIELD) # f_i = b_i - alpha_i * a
            self.commit()
            self.decommit()
            self.compute(FIELD.sum(self.parties) == FIELD) # f = 0?

    def CHESSMACRec(self):
        """Fig. 6"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.broadcast(FIELD, 2)
            self.compute(FIELD.sum(self.parties))
        if CunninghamFullerYakoubov2016_batched_MAC_check:
            pass # do MAC check later
        else:
            self.MACCheck()
        # TODO: in worst case: self.CHESSRec()

    Open = CHESSMACRec # seems what is meant by opening in the paper

    def AddShare(self):
        """Sec. 4.2"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD + FIELD, 2) # adjust share and randomness
            with self.for_each(self.parties):
                self.compute(COMMITMENT + COMMITMENT) # adjust all commitments
            self.compute(FIELD + FIELD) # adjust MAC share

    def AddCShare(self):
        """Sec. 4.2"""
        assert self.party is None
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD + FIELD) # one party adds constant to share
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(COMMITMENT + FIELD) # adjust one commitment
            self.compute(FIELD + FIELD * FIELD) # adjust MAC share

    SubShare = AddShare

    def MulShare(self):
        """Sec. 4.2"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD * FIELD, 2) # adjust share and randomness
            with self.for_each(self.parties):
                self.compute(COMMITMENT * FIELD) # adjust all commitments
            self.compute(FIELD * FIELD) # adjust MAC share

    def Multiply(self):
        """Sec. 4.2"""
        assert self.party is None
        with self.for_each(2): # a,b of the triple
            self.SubShare()
            self.Open()
            self.MulShare()
            self.AddShare()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD * FIELD)
        self.AddCShare()

    def Input(self):
        """Fig. 7"""
        assert self.party is None
        self.CHESSPrivRec()
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD - FIELD)
            self.broadcast(FIELD)
        self.AddCShare()

    def Output(self):
        """Fig. 7"""
        assert self.party is None
        self.CHESSMACRec()

    def AdditiveReshare(self):
        """Fig. 9"""
        assert self.party is None
        BaumOrsiniScholl2016.ShareDec(self, False)

    def DistMACKeyGen(self):
        """Fig. 10"""
        assert self.party is None
        BaumOrsiniScholl2016.RandShCtxt(self)
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT.sum(self.parties)) # compute encryption of MAC key

    def Reshare(self):
        """Fig. 11"""
        assert self.party is None
        BaumOrsiniScholl2016.ShareDec(self, False)
        # TODO: not everyone has their share; commitments are missing
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.verifiable(COMMITMENT_ZK)
            self.compute(FIELD - FIELD) # compute own randomness
            self.compute(FIELD - COMMITMENT) # compute commitment of one party
            with self.for_each(self.parties - 1): # compute commitment of other parties
                self.compute(COMMITMENT - COMMITMENT)

            self.compute(CIPHERTEXT * CIPHERTEXT) # compute encryption of MAC tag
        self.AdditiveReshare()

    def PickSecretSharedRandom(self):
        """Fig. 12"""
        assert self.party is None
        BaumOrsiniScholl2016.RandShCtxt(self)
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT.sum(self.parties)) # compute encryption of shared value
        self.Reshare()

    def MultSecretSharedValues(self):
        """Fig. 13"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            with self.for_each(2): # a,b of the triple
                self.verifiable(ZK)
                self.verifiable(COMMITMENT_ZK)
                self.compute(CIPHERTEXT.sum(self.parties))
            self.compute(CIPHERTEXT * CIPHERTEXT)
        self.Reshare()

    def PickSecretSharedBeaverTriple(self):
        """Fig. 14"""
        assert self.party is None
        self.PickSecretSharedRandom()
        self.PickSecretSharedRandom()
        self.MultSecretSharedValues()

    def Setup(self):
        """Fig. 15"""
        assert self.party is None
        # TODO: key generation
        self.DistMACKeyGen()

    def Check(self, count):
        if CunninghamFullerYakoubov2016_batched_MAC_check:
            # do an amortized SPDZ MAC check
            SPDZLike.Check(self, count)
        else:
            pass # already did MAC check in Open

    def __init__(self, parties=COMPUTE_PARTY_COUNT, input_parties=INPUT_PARTY_COUNT, output_parties=OUTPUT_PARTY_COUNT, inputs=INPUT_COUNT, additions=ADDITION_COUNT, scalar_multiplications=SCALAR_MULTIPLICATION_COUNT, multiplications=MULTIPLICATION_COUNT, public_outputs=PUBLIC_OUTPUT_COUNT, private_outputs=PRIVATE_OUTPUT_COUNT):
        super().__init__()
        self.parties = sympy.simplify(parties)
        self.input_parties = sympy.simplify(input_parties)
        self.output_parties = sympy.simplify(output_parties)
        self.inputs = sympy.simplify(inputs)
        self.additions = sympy.simplify(additions)
        self.scalar_multiplications = sympy.simplify(scalar_multiplications)
        self.multiplications = sympy.simplify(multiplications)
        self.public_outputs = sympy.simplify(public_outputs)
        self.private_outputs = sympy.simplify(private_outputs)

        # we ignore the "openable" protocol (Fig. 8) and just focus on identifiable abort
        # TODO: batched MAC check
        # TODO: handle input parties that are not compute parties

        with self.in_phase(SETUP_PHASE):
            self.Setup()

        with self.in_phase(OFFLINE_PHASE):
            with self.for_each(self.inputs):
                self.PickSecretSharedRandom()
            with self.for_each(self.multiplications):
                self.PickSecretSharedBeaverTriple()

        with self.in_phase(ONLINE_PHASE):
            # inputs
            with self.for_each(self.inputs):
                self.Input()
            # linear operations
            with self.for_each(self.additions):
                self.AddShare()
            with self.for_each(self.scalar_multiplications):
                self.MulShare()
            # multiplications
            with self.for_each(self.multiplications):
                self.Multiply()
            # outputs
            with self.for_each(self.public_outputs + self.private_outputs): # TODO: handle private output
                self.Output()

        with self.in_phase(VERIFICATION_PHASE):
            self.Check(2 * self.multiplications + self.public_outputs + self.private_outputs)


class KellerPastroRotaru2017(SPDZLike):
    """
    Title: Overdrive: Making SPDZ Great Again
    Authors: Marcel Keller, Valerio Pastro, Dragos Rotaru
    Paper: https://eprint.iacr.org/2017/1230.pdf

    We only use LowGear from that paper, for the HighGear variant, see BaumCozzoSmart2019 instead
    """

    def Initialize(self):
        """Fig. 4"""
        assert self.party is None
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD.sample())
            with self.for_each(self.parties - 1): # these are "diagonal" ZKPs
                self.compute(ZK)
                self.communicate(COMPUTE_PARTY, ZK)
                self.compute(ZK_VERIFICATION)

    def Input(self, count):
        """Fig. 4"""
        assert self.party is None
        m = count + 1
        with self.at_party(COMPUTE_PARTY):
            with self.for_each(count):
                with self.for_each(self.parties - 1):
                    self.compute(FIELD.sample())
                    self.communicate(COMPUTE_PARTY, FIELD)
                self.compute(FIELD - FIELD.sum(self.parties - 1))
            with self.for_each(m):
                with self.for_each(self.parties - 1):
                    self.compute(FIELD.sample())
                    self.encrypt_drowning()
                    self.compute(FIELD * CIPHERTEXT - CIPHERTEXT)
                    self.communicate(COMPUTE_PARTY, CIPHERTEXT)
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
            self.compute(DECRYPTION_EVALUATION, m)
        self.rand(FIELD, m)
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD * FIELD, m) # rho
            self.compute(FIELD.sum(m)) # rho
            with self.for_each(self.parties - 1):
                self.compute(FIELD * FIELD, m) # sigma
                self.compute(FIELD.sum(m)) # sigma
                self.communicate(COMPUTE_PARTY, FIELD, 2)
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
            self.compute(FIELD * FIELD, m)
            self.compute((FIELD * FIELD - FIELD - FIELD.sum(m)) == FIELD)
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD.sum(self.parties - 1) + FIELD * FIELD, count) # final MAC share

    def Multiply(self, count):
        """Fig. 7"""
        assert self.party is None
        with self.for_each(count):
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD.sample(), 3)
                with self.for_each(self.parties - 1):
                    self.compute(ZK) # a
                    self.communicate(COMPUTE_PARTY, ZK)
                    self.compute(ZK_VERIFICATION)
                    with self.for_each(2): # b, b hat
                        self.compute(FIELD.sample()) # e, e hat
                        self.encrypt_drowning()
                        self.compute(FIELD * CIPHERTEXT - CIPHERTEXT)
                        self.decrypt() # d, d hat
                with self.for_each(2): # c, c hat
                    self.compute(FIELD * FIELD + FIELD.sum(self.parties - 1) + FIELD.sum(self.parties - 1))

    def AuthenticateTriple(self, count):
        """Fig. 7 (simply called Authenticate)"""
        assert self.party is None
        self.Input(5 * count * self.parties)

    def Sacrifice(self, count):
        """Fig. 7"""
        assert self.party is None
        self.rand(FIELD)
        with self.for_each(count):
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.MulShare()
                self.SubShare()
            self.Open()
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.MulShare()
                self.SubShare()
                self.MulShare()
                self.SubShare()
            self.Open()
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD != FIELD)
        self.Check(2 * count)

    def __init__(self, parties=COMPUTE_PARTY_COUNT, input_parties=INPUT_PARTY_COUNT, output_parties=OUTPUT_PARTY_COUNT, inputs=INPUT_COUNT, additions=ADDITION_COUNT, scalar_multiplications=SCALAR_MULTIPLICATION_COUNT, multiplications=MULTIPLICATION_COUNT, public_outputs=PUBLIC_OUTPUT_COUNT, private_outputs=PRIVATE_OUTPUT_COUNT):
        super().__init__()
        self.parties = sympy.simplify(parties)
        self.input_parties = sympy.simplify(input_parties)
        self.output_parties = sympy.simplify(output_parties)
        self.inputs = sympy.simplify(inputs)
        self.additions = sympy.simplify(additions)
        self.scalar_multiplications = sympy.simplify(scalar_multiplications)
        self.multiplications = sympy.simplify(multiplications)
        self.public_outputs = sympy.simplify(public_outputs)
        self.private_outputs = sympy.simplify(private_outputs)

        # TODO: handle inputs not in the online phase
        # TODO: handle input parties that are not compute parties

        with self.in_phase(SETUP_PHASE):
            self.Initialize()

        with self.in_phase(OFFLINE_PHASE):
            self.Multiply(self.multiplications)
            self.AuthenticateTriple(self.multiplications)
            self.Sacrifice(self.multiplications)

        with self.in_phase(ONLINE_PHASE):
            # inputs
            self.Input(self.inputs)
            # linear operations
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                with self.for_each(self.additions):
                    self.AddShare()
                with self.for_each(self.scalar_multiplications):
                    self.MulShare()
            # multiplications
            with self.for_each(self.multiplications):
                with self.for_each(2): # a,b of the triple
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.SubShare()
                    self.Open()
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.MulShare()
                        self.AddShare()
                with self.at_party(COMPUTE_PARTY):
                    self.compute(FIELD * FIELD)
                    self.AddCShare()
            # outputs: not really described
            with self.for_each(self.public_outputs + self.private_outputs): # TODO: handle private outputs
                self.Open()

        with self.in_phase(VERIFICATION_PHASE):
            self.Check(2 * self.multiplications + self.public_outputs + self.private_outputs) # values opened in the online phase are during multiplication and opening # TODO: change when adapting input phase

LowGear = KellerPastroRotaru2017

class BaumCozzoSmart2019(SPDZLike):
    """
    Title: Using TopGear in Overdrive: A more efficient ZKPoK for SPDZ
    Authors: Carsten Baum, Daniele Cozzo, Nigel Smart
    Paper: https://eprint.iacr.org/2019/035.pdf
    """

    def zk(self):
        assert self.party is None
        # Samp
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(FIELD.sample())
            self.encrypt()
            self.commit()
            self.decommit()
            # Comm
            self.compute(CIPHERTEXT_FIELD.sample()) # not uniformly random
            self.encrypt()
            self.broadcast(CIPHERTEXT)
        # Chall
        self.rand(FIELD) # matrix
        # Resp
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT_FIELD + FIELD * CIPHERTEXT_FIELD, 1 + 3) # y + W m, S + W R
            self.broadcast(CIPHERTEXT_FIELD, 1 + 3) # z, T
            # Verify
            self.encrypt()
            self.compute(CIPHERTEXT.sum(self.parties), 3) # A, C, D
            self.compute(CIPHERTEXT_FIELD.sum(self.parties), 3 + 1) # T, z
            self.compute((CIPHERTEXT + FIELD * CIPHERTEXT) == CIPHERTEXT)

    def Init(self):
        """Fig. 3."""
        assert self.party is None
        self.zk()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT.sum(self.parties))

    def Input(self):
        """NOT IN PAPER. Seems like a version of the input preparation with low overhead."""
        assert self.party is None
        self.zk() # Enc(r_i) and r_i
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            self.compute(CIPHERTEXT.sum(self.parties)) # Enc(r) = sum Enc(r_i)
            self.compute(CIPHERTEXT + CIPHERTEXT) # Enc(r) = 2 Enc(r)
            self.compute(CIPHERTEXT * CIPHERTEXT) # Enc(r * alpha) = encrypted MAC
            self.decrypt_distributed_shares() # everyone gets a share of the MAC
            self.compute(FIELD + FIELD) # r_i = 2 r_i
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
            self.communicate(COMPUTE_PARTY, FIELD) # send r_i to input party
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD.sum(self.parties)) # r = sum r_i

    def Triples(self):
        """Fig. 3."""
        assert self.party is None
        with self.for_each(3): # a hat, b hat, f hat
            self.zk()
        with self.at_each_party(COMPUTE_PARTY, self.parties):
            # for a, b, f
            self.compute(CIPHERTEXT.sum(self.parties), 3)
            self.compute(CIPHERTEXT + CIPHERTEXT, 3)

            self.compute(CIPHERTEXT * CIPHERTEXT)
            self.compute(CIPHERTEXT + CIPHERTEXT)
            self.decrypt_distributed()
            self.compute(FIELD + FIELD) # f = 2 f hat
            self.compute(FIELD - FIELD) # one party computes delta - f, others -f
            self.compute(FIELD - CIPHERTEXT)
            self.compute(CIPHERTEXT * CIPHERTEXT, 3) # encrypted MAC of a, b, c
            with self.for_each(3): # MAC shares of a, b, c
                self.decrypt_distributed_shares()
            self.compute(FIELD + FIELD, 2) # shares of a and b have to be doubled

    def __init__(self, parties=COMPUTE_PARTY_COUNT, input_parties=INPUT_PARTY_COUNT, output_parties=OUTPUT_PARTY_COUNT, inputs=INPUT_COUNT, additions=ADDITION_COUNT, scalar_multiplications=SCALAR_MULTIPLICATION_COUNT, multiplications=MULTIPLICATION_COUNT, public_outputs=PUBLIC_OUTPUT_COUNT, private_outputs=PRIVATE_OUTPUT_COUNT):
        super().__init__()
        self.parties = sympy.simplify(parties)
        self.input_parties = sympy.simplify(input_parties)
        self.output_parties = sympy.simplify(output_parties)
        self.inputs = sympy.simplify(inputs)
        self.additions = sympy.simplify(additions)
        self.scalar_multiplications = sympy.simplify(scalar_multiplications)
        self.multiplications = sympy.simplify(multiplications)
        self.public_outputs = sympy.simplify(public_outputs)
        self.private_outputs = sympy.simplify(private_outputs)

        # TODO: sacrificing is not mentioned for TopGear
        # TODO: handle input parties that are not compute parties

        with self.in_phase(SETUP_PHASE):
            self.Init()

        with self.in_phase(OFFLINE_PHASE):
            with self.for_each(self.multiplications):
                self.Triples()
            with self.for_each(self.inputs):
                self.Input()

        with self.in_phase(ONLINE_PHASE):
            # inputs
            with self.for_each(self.inputs):
                with self.at_party(COMPUTE_PARTY):
                    self.compute(FIELD - FIELD)
                    self.broadcast(FIELD)
                    self.AddCShare()
            # linear operations
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                with self.for_each(self.additions):
                    self.AddShare()
                with self.for_each(self.scalar_multiplications):
                    self.MulShare()
            # multiplications
            with self.for_each(self.multiplications):
                with self.for_each(2): # a,b of the triple
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.SubShare()
                    self.Open()
                    with self.at_each_party(COMPUTE_PARTY, self.parties):
                        self.MulShare()
                        self.AddShare()
                with self.at_party(COMPUTE_PARTY):
                    self.compute(FIELD * FIELD)
                    self.AddCShare()
            # outputs: not really described
            with self.for_each(self.public_outputs + self.private_outputs): # TODO: handle private outputs
                self.Open()

        with self.in_phase(VERIFICATION_PHASE):
            self.Check(2 * self.multiplications + self.public_outputs + self.private_outputs) # values opened in the online phase are during multiplication and opening # TODO: change when adapting input phase

TopGear = BaumCozzoSmart2019

class CohenDoernerKondiShelat2023(Protocol):
    """
    Title: Secure Multiparty Computation with Identifiable Abort from Vindicating Release
    Authors: Ran Cohen, Jack Doerner, Yashvanth Kondi, Abhi Shelat
    Paper: https://eprint.iacr.org/2023/1136.pdf

    Offline phase is roughly n times MASCOT
    Online phase is the same as BDOZ
    """

    def random_OT(self, count):
        """Should call CVOLE-IRIA from Cohen et al."""
        """Using the protocol 5.3 from the old eprint: https://eprint.iacr.org/archive/2023/1136/1690026705.pdf"""

        def SCOT_correlation(size):
            pass
        def SCOT_vector(size):
            pass

        SCOT_correlation(count) # Bob sends O(|Field|) bits to the SCOT
        self.compute(FIELD + FIELD, count) # Alice computes an encoding of the inputs
        SCOT_vector(count)

        ## challenge can be replaced with RO
        # self.compute(FIELD.sample(), count) # Bob samples challenge and broadcasts
        # self.broadcast(FIELD, count) #

        self.compute(FIELD * FIELD + FIELD, 2 * count) # Alice computes u,v
        self.broadcast(FIELD, count + 1) # and broadcasts u, RO(v)

        self.compute(FIELD * FIELD - FIELD * FIELD - FIELD, count) # Bob computes v'
        self.compute(FIELD == FIELD) # should be (v == RO(v'))
        self.compute(FIELD * FIELD, count)

        self.compute(BOOLEAN) # OK

        pass

    def correlated_OT(self, count):
        """Should call SCELOV from Cohen et al."""
        pass

    def MASCOT_Offline(self, multiplications):
        """2016/505.pdf (mostly Protocol 4)"""
        assert self.party is None

        def MAC_check():
            """Protocol 2"""
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD - FIELD * FIELD)
                self.commit()
                self.decommit()
                self.compute(FIELD.sum(self.parties) == FIELD)

        def check(count):
            """Protocol 3"""
            self.rand(FIELD, count)
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD * FIELD, count * 2)
            MAC_check()

        def open():
            """Protocol 3"""
            self.broadcast(FIELD)
            self.compute(FIELD.sum(self.parties))

        def input(count):
            with self.at_party(COMPUTE_PARTY):
                self.compute(FIELD.sample(), count)
                with self.for_each(self.parties - 1):
                    self.correlated_OT(count)
                self.compute(FIELD * FIELD + FIELD.sum(self.parties - 1), count)
            self.rand(FIELD, count + 1)
            with self.at_party(COMPUTE_PARTY):
                self.compute(FIELD * FIELD, count)
                self.compute(FIELD.sum(count))
                self.broadcast(FIELD)
            with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
                self.compute(FIELD * FIELD, count)
                self.compute(FIELD.sum(count))
            MAC_check()

        def authenticate(count):
            """Protocol 3 (Input)"""
            input(count * self.parties)


        def sacrifice(count):
            self.rand(FIELD, count)
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                with self.for_each(count):
                    self.compute(FIELD * FIELD - FIELD)
                    open()
                    self.compute(FIELD * FIELD - FIELD - FIELD * FIELD)
            check(count)

        def combine(count):
            self.rand(FIELD, 2 * count)
            pass # TODO

        def multiply(count):
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD.sample(), 2 * count) # shares of a and b
                with self.for_each(self.parties - 1): # for every other party
                    self.random_OT(count)
                    self.compute(FIELD - FIELD + FIELD, count) # d = q0 - q1 + b
                    self.compute(FIELD + FIELD * FIELD, count) # t = s + a * d
                    # TODO: some local scalar multiplications
                self.compute(FIELD + FIELD, count * (self.parties - 1)) # c ij + c ji
                self.compute(FIELD * FIELD + FIELD.sum(self.parties - 1), count)

        multiply(multiplications)

        combine(multiplications)

        authenticate(5 * multiplications) # a, b, c, a hat, c hat

        sacrifice(multiplications)

    def BDOZ_Online(self):
        def open_to(party=COMPUTE_PARTY):
            with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
                self.communicate(party, FIELD)
            with self.at_party(party):
                with self.for_each(self.parties - 1):
                    self.compute((FIELD * FIELD + FIELD) == FIELD)
                self.compute(FIELD.sum(self.parties))

        def open():
            with self.for_each(self.parties):
                open_to()

        def add():
            with self.at_party(COMPUTE_PARTY):
                with self.for_each(self.parties): # for i
                    self.compute(FIELD + FIELD) # share
                    with self.for_each(self.parties): # for j
                        self.compute(FIELD + FIELD) # key
                        self.compute(FIELD + FIELD) # MAC

        def mul_constant():
            with self.at_party(COMPUTE_PARTY):
                with self.for_each(self.parties): # for i
                    self.compute(FIELD * FIELD) # share
                    with self.for_each(self.parties): # for j
                        self.compute(FIELD * FIELD) # key
                        self.compute(FIELD * FIELD) # MAC

        def add_constant():
            with self.at_party(COMPUTE_PARTY):
                self.compute(FIELD * FIELD) # share of P1
                with self.for_each(self.parties): # for j
                    self.compute(FIELD - FIELD * FIELD) # key

        # TODO: inputs

        # linear operations
        with self.for_each(self.additions):
            add()
        with self.for_each(self.scalar_multiplications):
            mul_constant()
        # multiplications
        with self.for_each(self.multiplications):
            with self.for_each(2): # for a, b of the triple
                add() # mask each component of the authenticated share
                open()
                mul_constant() # [[a]] * v, u * [[b]]
                add() # [[c]] + [[a]] * v + u * [[b]]
            add_constant()

        # TODO: outputs


    def __init__(self, parties=COMPUTE_PARTY_COUNT, input_parties=INPUT_PARTY_COUNT, output_parties=OUTPUT_PARTY_COUNT, inputs=INPUT_COUNT, additions=ADDITION_COUNT, scalar_multiplications=SCALAR_MULTIPLICATION_COUNT, multiplications=MULTIPLICATION_COUNT, public_outputs=PUBLIC_OUTPUT_COUNT, private_outputs=PRIVATE_OUTPUT_COUNT):
        super().__init__()
        self.parties = sympy.simplify(parties)
        self.input_parties = sympy.simplify(input_parties)
        self.output_parties = sympy.simplify(output_parties)
        self.inputs = sympy.simplify(inputs)
        self.additions = sympy.simplify(additions)
        self.scalar_multiplications = sympy.simplify(scalar_multiplications)
        self.multiplications = sympy.simplify(multiplications)
        self.public_outputs = sympy.simplify(public_outputs)
        self.private_outputs = sympy.simplify(private_outputs)

        # TODO: handle public verifiability
        # TODO: handle inputs

        with self.in_phase(SETUP_PHASE):
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                # rough estimate of the setup: Sample keys and broadcast
                self.compute(FIELD.sample())
                self.broadcast(FIELD)

        with self.in_phase(OFFLINE_PHASE):
            self.MASCOT_Offline(self.multiplications * self.parties) # rough overhead to MASCOT is number of parties

        with self.in_phase(ONLINE_PHASE):
            self.BDOZ_Online()

        with self.in_phase(VERIFICATION_PHASE):
            pass # TODO


class BaumMelissarisRachuriScholl2023(Protocol):
    """
    Title: Cheater Identification on a Budget: MPC with Identifiable Abort from Pairwise MACs
    Authors: Carsten Baum, Nikolas Melissaris, Rahul Rachuri, Peter Scholl
    Paper: https://eprint.iacr.org/2023/1548.pdf
    """

    def Output(self):
        """Fig. 2"""
        assert self.party is None
        with self.at_party(COMPUTE_PARTY):
            with self.for_each(self.parties - 1):
                self.communicate(COMPUTE_PARTY, FIELD, 2)
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
                self.compute((FIELD * FIELD + FIELD) == FIELD)

    def Open(self):
        with self.for_each(self.parties):
            self.Output()

    def AddShare(self):
        assert self.party is None
        with self.for_each(self.parties):
            self.AddAngle()

    def AddCShare(self):
        assert self.party is None
        with self.for_each(self.parties):
            self.AddCAngle()

    SubShare = AddShare

    def MulShare(self):
        assert self.party is None
        with self.for_each(self.parties):
            self.MulAngle()

    def AddAngle(self):
        """Sec. 4"""
        assert self.party is None
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD + FIELD, 1 + (self.parties - 1)) # sender
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
            self.compute(FIELD + FIELD) # receiver

    def MulAngle(self):
        """Sec. 4 (not explicitly mentioned)"""
        assert self.party is None
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD * FIELD, 1 + (self.parties - 1)) # sender
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
            self.compute(FIELD * FIELD) # receiver

    def AddCAngle(self):
        """Sec. 4"""
        assert self.party is None
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD + FIELD) # sender
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
            self.compute(FIELD - FIELD * FIELD) # receiver

    def VOLEExtend(self, count, seed):
        assert self.party is None
        # seed==None indicates receiving party
        with self.at_party(COMPUTE_PARTY): # sender and receiver; just approximate values
            if count != 0: # avoid log(0)
                self.communicate(COMPUTE_PARTY, FIELD, sympy.log(count))
                self.compute(FIELD + FIELD, count)
                self.compute(FIELD * FIELD, count)

    def HComRandom(self, count):
        """Fig. 2"""
        assert self.party is None
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD.sample())
        with self.for_each(self.parties - 1):
            self.VOLEExtend(count, True) # sender
            self.VOLEExtend(count, None) # receiver
        self.rand(FIELD, count)
        with self.for_each(count):
            self.MulAngle() # xi_i * l_i
            self.AddAngle() # sum x_i * l_i + l_m+1
        with self.at_party(COMPUTE_PARTY):
            self.broadcast(FIELD)
            with self.for_each(self.parties - 1):
                self.communicate(COMPUTE_PARTY, FIELD, 1)
        with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
            self.compute((FIELD * FIELD + FIELD) == FIELD)


    def HComInput(self, count):
        """Fig. 2"""
        assert self.party is None
        self.HComRandom(count)
        with self.for_each(count):
            with self.at_party(COMPUTE_PARTY):
                self.compute(FIELD - FIELD)
                self.broadcast(FIELD)
            with self.at_each_party(COMPUTE_PARTY, self.parties - 1):
                self.compute(FIELD - FIELD * FIELD)

    def HComPrivOpen(self, count):
        """Fig. 2"""
        assert self.party is None
        with self.for_each(count):
            with self.at_party(COMPUTE_PARTY):
                self.communicate(COMPUTE_PARTY, FIELD, 2) # sender
                self.compute((FIELD * FIELD + FIELD) == FIELD) # receiver

    def Trip(self, count):
        pass # TODO

    def RandInput(self, count):
        """Fig. 13"""
        assert self.party is None
        with self.for_each(self.parties):
            self.HComRandom(count)
            self.HComPrivOpen(count)
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD.sum(self.parties), count)

    def TripleGeneration(self, count):
        """Fig. 14"""
        assert self.party is None
        self.Trip(2 * count)
        with self.for_each(self.parties):
            self.HComInput(2 * count * 3)
        self.rand(FIELD, count)
        with self.for_each(count):
            self.MulShare() # t_i * a
            self.AddShare() # t_i * a + a'
            self.AddShare() # b + b'
            self.Open() # alpha
            self.Open() # beta
            self.MulShare() # t_i * c
            self.SubShare() # - c'
            self.AddShare() # +
            self.MulShare() # alpha * b
            self.AddShare() # +
            self.MulShare() # beta * a'
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                self.compute(FIELD * FIELD) # alpha * beta
            self.AddCShare() # - alpha * beta
        with self.for_each(count):
            self.MulShare() # xi_i * d
        with self.for_each(count - 1):
            self.AddShare() # sigma = sum...
        self.Open()

    def Input(self):
        """Fig. 19"""
        assert self.party is None
        with self.at_party(COMPUTE_PARTY):
            self.compute(FIELD - FIELD)
            self.broadcast(FIELD)
        self.AddCShare()

    def __init__(self, parties=COMPUTE_PARTY_COUNT, input_parties=INPUT_PARTY_COUNT, output_parties=OUTPUT_PARTY_COUNT, inputs=INPUT_COUNT, additions=ADDITION_COUNT, scalar_multiplications=SCALAR_MULTIPLICATION_COUNT, multiplications=MULTIPLICATION_COUNT, public_outputs=PUBLIC_OUTPUT_COUNT, private_outputs=PRIVATE_OUTPUT_COUNT):
        super().__init__()
        self.parties = sympy.simplify(parties)
        self.input_parties = sympy.simplify(input_parties)
        self.output_parties = sympy.simplify(output_parties)
        self.inputs = sympy.simplify(inputs)
        self.additions = sympy.simplify(additions)
        self.scalar_multiplications = sympy.simplify(scalar_multiplications)
        self.multiplications = sympy.simplify(multiplications)
        self.public_outputs = sympy.simplify(public_outputs)
        self.private_outputs = sympy.simplify(private_outputs)

        # TODO: Generate correlated randomness

        with self.in_phase(SETUP_PHASE):
            with self.at_each_party(COMPUTE_PARTY, self.parties):
                # rough estimate of the setup: Sample keys and send to other party
                with self.for_each(self.parties - 1):
                    self.compute(FIELD.sample())
                    self.communicate(COMPUTE_PARTY, FIELD)

        with self.in_phase(OFFLINE_PHASE):
            self.TripleGeneration(self.multiplications)
            self.RandInput(self.inputs)

        with self.in_phase(ONLINE_PHASE):
            # inputs
            with self.for_each(self.inputs):
                self.Input()
            # linear operations
            with self.for_each(self.additions):
                self.AddShare()
            with self.for_each(self.scalar_multiplications):
                self.MulShare()
            # multiplications
            with self.for_each(self.multiplications):
                with self.for_each(2): # a,b of the triple
                    self.SubShare()
                    self.Open()
                    self.MulShare()
                    self.AddShare()
                with self.at_each_party(COMPUTE_PARTY, self.parties):
                    self.compute(FIELD * FIELD)
                self.AddCShare()
            with self.for_each(self.public_outputs):
                self.Output()
            with self.for_each(self.private_outputs):
                self.HComPrivOpen(1)


def table(*protocols, communication=False, computation=False, phases=[SETUP_PHASE, OFFLINE_PHASE, ONLINE_PHASE, VERIFICATION_PHASE], parties=[COMPUTE_PARTY, INPUT_PARTY, OUTPUT_PARTY], collapse=False, midrules=False, O_notation=False, zero=None, input_party=INPUT_PARTY, output_party=OUTPUT_PARTY, **kwargs):
    assert communication or computation
    print("% generated by:")
    print("% python", shlex.join(sys.argv))

    global INPUT_PARTY
    if input_party != INPUT_PARTY:
        INPUT_PARTY = input_party

    global OUTPUT_PARTY
    if output_party != OUTPUT_PARTY:
        OUTPUT_PARTY = output_party

    if collapse is False:
        collapse = 0
    if collapse is True:
        collapse = 1

    if isinstance(O_notation, str):
        O_notation = O_notation.upper().replace("-", "_")

    protocols = [globals()[protocol](**kwargs) for protocol in protocols]

    senders = parties
    receivers = parties + [BULLETIN_BOARD]

    def strip_constants(value):
        orig_vars = [COMPUTE_PARTY_COUNT, INPUT_PARTY_COUNT, OUTPUT_PARTY_COUNT, INPUT_COUNT, ADDITION_COUNT, SCALAR_MULTIPLICATION_COUNT, MULTIPLICATION_COUNT, PUBLIC_OUTPUT_COUNT, PRIVATE_OUTPUT_COUNT]
        log_vars = [sympy.log(x) for x in orig_vars]
        vars = orig_vars + log_vars
        p = sympy.Poly(value, *vars)
        result = 0

        def orig_exponents(exponents):
            return exponents[:len(orig_vars)]
        def log_exponents(exponents):
            return exponents[len(orig_vars):]
        def combined_exponents(exponents):
            return [(x, y) for x, y in zip(orig_exponents(exponents), log_exponents(exponents))]

        combined_vars = combined_exponents(vars)

        all_exponents = list(sorted(map(combined_exponents, p.as_dict().keys())))

        for i, exponents in enumerate(all_exponents):
            if any(all(y >= x for x, y in zip(exponents, other)) for other in all_exponents[i+1:]):
                continue

            y = 1
            for (var, log_var), (exponent, log_exponent) in zip(combined_vars, exponents):
                y *= var ** exponent
                y *= log_var ** log_exponent
            result += y
        return result


    def latex(*args, **kwargs):
        print(*args, **kwargs, sep = " & ", end="")
    def endl(*args, **kwargs):
        print(*args, **kwargs, sep = " & ", end=r" \\" + "\n")
    def latex_zero(prefix=""):
        if zero is None:
            latex(prefix)
        else:
            latex(prefix + str(zero))
    def format(value, var=COMPUTE_PARTY_COUNT):
        if O_notation == "KEEP_FACTORS":
            COMMUNICATION = [BOOLEAN_ELEMENT, FIELD_ELEMENT, CIPHERTEXT_FIELD_ELEMENT, CIPHERTEXT_ELEMENT, COMMITMENT_ELEMENT, DECOMMITMENT, DISTRIBUTED_DECRYPTION, ZK, PUBLIC_KEY_ZK, COMMITMENT_ZK]
            COMMUNICATION += [sympy.Symbol(f"public_random_{x}") for x in COMMUNICATION]
            COMPUTATION = []
            value = sympy.simplify(value)
            value = value.subs([(x, 1) for x in COMMUNICATION + COMPUTATION])
            value = strip_constants(value)
            # p = sympy.Poly(value, var)
            # assert all(len(exponent) == 1 for exponent in p.as_dict().keys())
            # max_exponent = 0
            # max_factor = 0
            # for (exponent,), factor in p.as_dict().items():
            #     if exponent > max_exponent:
            #         max_factor = factor
            #         max_exponent = exponent
            # if max_exponent > 0:
            #     value = max_factor * var ** max_exponent
            # else:
            #     value = 0
        elif O_notation:
            p = sympy.Poly(value, var)
            exponents = p.as_dict().keys()
            assert all(len(exponent) == 1 for exponent in exponents)
            exponent = max([exponent[0] for exponent in exponents] + [0])
            if exponent > 0:
                value = var ** exponent
            else:
                value = 0
        if value == 0 or value == 1:
            latex_zero()
        else:
            latex(f"${sympy.latex(value)}$")

    def header(columns, *headings):
        assert len(headings) == columns
        print(r"\begin{tabular}{" + " ".join("c" for _ in range(columns + 1)) + "}")
        print(r"\toprule")
        endl("phase", *headings)
        print(r"\midrule")

    def phase_header(columns, rows, phase, row=-1):
        if midrules and row !=0:
            if midrules is True:
                print(r"\cmidrule{1-" + str(columns+1) + "}")
            else:
                print(r"\cmidrule(rl){1-" + str(columns+1) + "}")
        latex(r"\multirow{" + str(rows) + "}*{" + phase + "} ")

    def footer():
        print(r"\bottomrule")
        print(r"\end{tabular}")

    if communication and collapse == 0:
        columns = 2 + len(protocols)
        header(columns, "sender", "receiver", *[protocol.__class__.__name__ for protocol in protocols])
        for row, phase in enumerate(phases):
            phase_header(columns, len(senders)*len(receivers), phase, row=row)
            for sender in senders:
                for receiver in receivers:
                    latex("& ")
                    latex(sender, receiver)
                    for protocol in protocols:
                        try:
                            x = protocol.phases[phase].communication.communication[(sender, receiver)]
                        except KeyError:
                            x = 0
                        latex(" & ")
                        format(x)
                    endl()
        footer()
    elif communication and collapse == 1:
        columns = 2 + len(protocols)
        header(columns, "sender", "receiver", *[protocol.__class__.__name__ for protocol in protocols])
        for row, phase in enumerate(phases):
            phase_header(columns, 2, phase, row=row)
            for sender in senders:
                receiver = ANY_PARTY
                latex("& ")
                latex(sender, receiver)
                for protocol in protocols:
                    x = 0
                    for receiver in senders:
                        try:
                            y = protocol.phases[phase].communication.communication[(sender, receiver)]
                            x += y
                        except KeyError:
                            pass
                    latex(" & ")
                    format(x)
                endl()
                receiver = BULLETIN_BOARD
                latex("& ")
                latex(sender, receiver)
                for protocol in protocols:
                    try:
                        x = protocol.phases[phase].communication.communication[(sender, receiver)]
                    except KeyError:
                        x = 0
                    latex(" & ")
                    format(x)
                endl()
        footer()
    elif communication and collapse == 2:
        columns = 1 + len(protocols)
        header(columns, "sender", *[protocol.__class__.__name__ for protocol in protocols])
        for row, phase in enumerate(phases):
            phase_header(columns, len(senders), phase, row=row)
            for sender in senders:
                latex("& ")
                latex(sender)
                for protocol in protocols:
                    x = 0
                    for receiver in receivers:
                        try:
                            y = protocol.phases[phase].communication.communication[(sender, receiver)]
                            x += y
                        except KeyError:
                            pass
                    latex(" & ")
                    format(x)
                endl()
        footer()
    elif communication and collapse == 3:
        columns = 1 + len(protocols)
        header(columns, "receiver", *[protocol.__class__.__name__ for protocol in protocols])
        for row, phase in enumerate(phases):
            phase_header(columns, 2, phase, row=row)
            receiver = ANY_PARTY
            latex("& ")
            latex(receiver)
            for protocol in protocols:
                x = 0
                for sender in senders:
                    for receiver in senders:
                        try:
                            y = protocol.phases[phase].communication.communication[(sender, receiver)]
                            x += y
                        except KeyError:
                            pass
                latex(" & ")
                format(x)
            endl()
            receiver = BULLETIN_BOARD
            latex("& ")
            latex(receiver)
            for protocol in protocols:
                x = 0
                for sender in senders:
                    try:
                        y = protocol.phases[phase].communication.communication[(sender, receiver)]
                        x += y
                    except KeyError:
                        pass
                latex(" & ")
                format(x)
            endl()
        footer()
    elif communication and collapse == 4:
        pass # TODO
    elif communication:
        raise ValueError("--collapse should be 0 (all information), 1 (receiver collapsed to Some/All), 2 (receiver collapsed to Any), 3 (sender collapsed, receiver collapsed to Some/All), or 4 (sender collapsed, receiver collapsed to Any)")

    if communication and computation:
        print()

    if computation and collapse == 0:
        columns = 1 + len(protocols)
        header(columns, "party", *[protocol.__class__.__name__ for protocol in protocols])
        for row, phase in enumerate(phases):
            phase_header(columns, len(parties), phase, row=row)
            for party in parties:
                latex("& ")
                latex(party)
                for protocol in protocols:
                    try:
                        x = protocol.phases[phase].computation.computation[party]
                    except KeyError:
                        x = 0
                    latex(" & ")
                    format(x)
                endl()
        footer()
    elif computation and collapse == 1:
        columns = len(protocols)
        header(columns, *[protocol.__class__.__name__ for protocol in protocols])
        for row, phase in enumerate(phases):
            phase_header(columns, 1, phase, row=row)
            latex("& ")
            for protocol_id, protocol in enumerate(protocols):
                x = 0
                for party in parties:
                    try:
                        y = protocol.phases[phase].computation.computation[party]
                        x += y
                    except KeyError:
                        pass
                if protocol_id != 0:
                    latex(" & ")
                format(x)
            endl()
        footer()
    elif computation:
        raise ValueError("--collapse should be 0 (all information), or 1 (compute party collapsed)")

if __name__ == "__main__":
    import fire
    fire.Fire()
