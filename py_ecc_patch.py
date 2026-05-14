"""
py_ecc_patch.py
===============
Monkey-patches py_ecc.fields.field_elements.FQP.__pow__ to use ITERATIVE
square-and-multiply instead of the recursive implementation that ships with
py_ecc.

The shipped version recurses once per bit of the exponent. BN128's final
exponentiation uses an exponent of ~2800 bits, which needs ~2800 stack frames
per pairing. Python's default recursion limit (1000) and Windows' default
thread C stack (~1 MB) both blow up well before that.

Import this module ONCE, before any other py_ecc code runs, and the problem
goes away with zero performance loss (iterative is actually faster — no
function-call overhead per bit).
"""
from py_ecc.fields.field_elements import FQP


def _iterative_pow(self, other):
    # Identity element for this FQP (coefficients [1, 0, 0, ..., 0])
    result = type(self)([1] + [0] * (self.degree - 1))
    base = self
    e = int(other)
    if e < 0:
        # Negative exponent: invert first, then raise to abs(e)
        base = base.inv()
        e = -e
    while e > 0:
        if e & 1:
            result = result * base
        e >>= 1
        if e > 0:
            base = base * base
    return result


# Patch the base class — all FQP subclasses (FQ2, FQ6, FQ12) inherit it.
FQP.__pow__ = _iterative_pow
