"""Native LLM adapters, router, doctor, and gates (M2).

Mirrors how `verifier/`, `chain/`, and `driver/` are already organized:
this package holds the M2 machinery, while the data shapes it passes
around (`ModelProfile`, `StackPolicy`) live in `core.models` alongside
`Witness`, `Scope`, and the rest, per the existing convention.
"""