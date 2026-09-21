PYTHON ?= python3

.PHONY: setup test lint schemas schemas-generate doctor doctor-free terms-check tools-update tools-verify cheatcode-catalog policy-test m0-acceptance m1a-acceptance m1b-acceptance audit-m0-m1b

setup:
	uv sync --locked --extra dev

test:
	uv run --locked pytest tests

schemas:
	uv run --locked python -c "from pathlib import Path; from l0vi0x.core.schema_gen import check_schema_drift; p=Path('schemas'); drift=check_schema_drift(p); import sys; sys.exit('schema drift: '+', '.join(drift) if drift else 0)"

schemas-generate:
	uv run --locked python -c "from pathlib import Path; from l0vi0x.core.schema_gen import generate_schemas; generate_schemas(Path('schemas'))"

lint:
	uv run --locked ruff check src tests
	uv run --locked mypy src

doctor:
	@echo 'M0 doctor: core dependencies and policy configuration are checked by make test'

doctor-free:
	@echo 'Free-provider probes are M2; no network probes are performed by M0'

terms-check:
	@echo 'Provider terms/pricing freshness is an M2 concern'

tools-update:
	uv run --locked python tools_update.py

tools-verify:
	uv run --locked python -c "from l0vi0x.tools.lock import verify_binary_lock; p=verify_binary_lock('config/tools.lock.yaml'); import sys; print('tool lock: PASS' if not p else '\n'.join(p)); sys.exit(0 if not p else 2)"

cheatcode-catalog:
	uv run --locked python -c "from pathlib import Path; import yaml; p=Path('config/policy/cheatcode_categories.yaml'); d=yaml.safe_load(p.read_text()); print('cheatcodes:', len(d.get('categories', {})))"

policy-test:
	uv run --locked pytest tests/test_sandbox_fs.py tests/test_policy.py

m0-acceptance:
	uv sync --locked --extra dev && uv run --locked pytest tests && uv run --locked pytest tests/test_sandbox_fs.py tests/test_policy.py && uv run --locked python -c "from pathlib import Path; from l0vi0x.core.schema_gen import check_schema_drift; p=Path('schemas'); drift=check_schema_drift(p); import sys; sys.exit('schema drift: '+', '.join(drift) if drift else 0)" && uv run --locked python -c "from pathlib import Path; import yaml; p=Path('config/policy/cheatcode_categories.yaml'); d=yaml.safe_load(p.read_text()); print('cheatcodes:', len(d.get('categories', {})))"


m1a-acceptance:
	PYTHONPATH=src uv run --locked python -m l0vi0x.driver.m1a_acceptance


m1b-acceptance:
	PYTHONPATH=src uv run --locked pytest tests/test_m1b_verifier.py

audit-m0-m1b:
	PYTHONPATH=src uv run --locked pytest tests && uv run --locked pytest tests/test_sandbox_fs.py tests/test_policy.py && uv run --locked python -c "from pathlib import Path; from l0vi0x.core.schema_gen import check_schema_drift; d=check_schema_drift(Path('schemas')); import sys; sys.exit('schema drift: '+', '.join(d) if d else 0)" && PYTHONPATH=src uv run --locked pytest tests/test_m1b_verifier.py
