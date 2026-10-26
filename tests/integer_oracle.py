"""Independent integer micro-USD oracle. No production accounting imports."""
from dataclasses import dataclass


def micros(text):
    value = str(text)
    whole, _, fraction = value.partition(".")
    if not whole.isdigit() or not fraction.isdigit() and fraction or len(fraction) > 6:
        raise ValueError("noncanonical micro-USD")
    return int(whole) * 1_000_000 + int(fraction.ljust(6, "0") or "0")


@dataclass(frozen=True)
class State:
    reserved: int
    future: int = 0
    active: int = 0
    released: int = 0
    known: int = 0
    unknown: int = 0
    excess: int = 0
    uncovered: int = 0

    def verify(self):
        assert all(type(x) is int and x >= 0 for x in vars(self).values())
        assert self.reserved + self.excess == self.future + self.active + self.released + self.known + self.unknown

    @property
    def exposure(self):
        return self.known + self.future + self.active + self.unknown + self.uncovered


def expected(reserved, phase, charge=None, late=None):
    if phase == "future":
        return State(reserved, future=reserved)
    if phase == "active":
        return State(reserved, active=reserved)
    if phase == "cancelled":
        return State(reserved, released=reserved)
    if phase == "unknown":
        return State(reserved, unknown=reserved, uncovered=max((late or 0) - reserved, 0))
    if phase == "known":
        return State(reserved, known=charge, released=max(reserved-charge, 0), excess=max(charge-reserved, 0))
    raise ValueError(phase)
