# Phase 0: Unit Testing

This phase validates the CTL extension implementation before running anu evalutation testing/experiments.

Main goal is to make sure each layer of the CTL pipeline works independently and that the full verification path behaves correctly on small synthetic examples.

The tested pipeline is:

P-LLM generated code
    ↓
cast.py
    ↓
state_machine.py
    ↓
json2nuxmv.py
    ↓
nuxmv_runner.py
    ↓
verification_integration.py
    ↓
repair / block / execute


## Test Location

All Phase 0 CTL tests can be found under:

```bash
tests/test_ctl

test_cast.py
test_state_machine.py
test_state_machine_structure.py
test_nuxmv_runner.py
test_verification_integration.py
test_repair_loop.py
test_verification_state.py
test_verification_all.py

# To run all the tests:
pytest -q tests/test_ctl

each: pytest -q tests/test_ctl
