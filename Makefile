PYTHON ?= python3
COMPOSE_M1A := docker compose -f docker/compose.yaml
COMPOSE_M1B := docker compose -f docker/compose.m1b.yaml

.PHONY: setup test lint schemas schemas-generate doctor doctor-free terms-check tools-update tools-verify cheatcode-catalog policy-test m0-acceptance m1a-acceptance m1b-unit m1b-acceptance audit-m0-m1b docker-clean

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
	uv run --locked python -c "from l0vi0x.tools.lock import verify_binary_lock; p=verify_binary_lock('config/tools.lock.yaml'); import sys; print('tool lock: PASS' if not p else '\\n'.join(p)); sys.exit(0 if not p else 2)"

cheatcode-catalog:
	uv run --locked python -c "from pathlib import Path; import yaml; p=Path('config/policy/cheatcode_categories.yaml'); d=yaml.safe_load(p.read_text()); print('cheatcodes:', len(d.get('categories', {})))"

policy-test:
	uv run --locked pytest tests/test_sandbox_fs.py tests/test_policy.py

m0-acceptance:
	uv sync --locked --extra dev && uv run --locked pytest tests && uv run --locked pytest tests/test_sandbox_fs.py tests/test_policy.py && uv run --locked python -c "from pathlib import Path; from l0vi0x.core.schema_gen import check_schema_drift; p=Path('schemas'); drift=check_schema_drift(p); import sys; sys.exit('schema drift: '+', '.join(drift) if drift else 0)" && uv run --locked python -c "from pathlib import Path; import yaml; p=Path('config/policy/cheatcode_categories.yaml'); d=yaml.safe_load(p.read_text()); print('cheatcodes:', len(d.get('categories', {})))"

m1a-acceptance: tools-verify
	@set -eu; mkdir -p eval/private/m1a-acceptance/rpc-gate; chmod 1777 eval/private/m1a-acceptance/rpc-gate; chmod 1777 eval/private/m1a-acceptance eval/private/m1a-acceptance/rpc-gate; rm -f eval/private/m1a-acceptance/host-replay.key; GATE_AGENT_TOKEN=$${GATE_AGENT_TOKEN:-m1a-agent-token}; GATE_UPSTREAM_TOKEN=$${GATE_UPSTREAM_TOKEN:-m1a-upstream-token}; SANDBOX_TASK_DIR=$$(pwd)/eval/private/m1a-acceptance; REPO_ROOT=$$(pwd); export GATE_AGENT_TOKEN GATE_UPSTREAM_TOKEN SANDBOX_TASK_DIR REPO_ROOT; \
	$(COMPOSE_M1A) down --remove-orphans -v; \
	$(COMPOSE_M1A) up -d --build --wait --wait-timeout 60 m1a_upstream rpc_gate; \
	$(COMPOSE_M1A) build sandbox; \
	$(COMPOSE_M1A) run --rm sandbox python3 -m l0vi0x.driver.m1a_acceptance --phase collect; \
	PYTHONPATH=src uv run --locked python -m l0vi0x.driver.m1a_acceptance --phase certify; \
	$(COMPOSE_M1A) down --remove-orphans -v

m1b-unit:
	PYTHONPATH=src uv run --locked pytest tests/test_m1b_verifier.py tests/test_m1b_acceptance.py tests/test_tools_lock.py

m1b-acceptance: tools-verify m1b-unit
	@set -eu; mkdir -p eval/private/m1b-acceptance/rpc-gate; chmod 1777 eval/private/m1b-acceptance eval/private/m1b-acceptance/rpc-gate; GATE_AGENT_TOKEN=$${GATE_AGENT_TOKEN:-m1b-agent-token}; GATE_UPSTREAM_TOKEN=$${GATE_UPSTREAM_TOKEN:-m1b-upstream-token}; RPC_GATE_HOST_PORT=$${RPC_GATE_HOST_PORT:-8545}; SANDBOX_TASK_DIR=$$(pwd)/eval/private/m1b-acceptance; REPO_ROOT=$$(pwd); export GATE_AGENT_TOKEN GATE_UPSTREAM_TOKEN RPC_GATE_HOST_PORT SANDBOX_TASK_DIR REPO_ROOT; $(COMPOSE_M1B) down --remove-orphans -v; $(COMPOSE_M1B) up -d --build --wait --wait-timeout 60 gate_anvil rpc_gate; $(COMPOSE_M1B) build sandbox; $(COMPOSE_M1B) run --rm sandbox python3 -m l0vi0x.driver.m1b_acceptance --phase collect; PYTHONPATH=src uv run --locked python -m l0vi0x.driver.m1b_acceptance --phase certify; GATE_URL="http://agent:$${GATE_AGENT_TOKEN}@127.0.0.1:$${RPC_GATE_HOST_PORT}/agent" PYTHONPATH=src uv run --locked python -m l0vi0x.driver.m1b_acceptance --phase probes; $(COMPOSE_M1B) down --remove-orphans -v

audit-m0-m1b: m0-acceptance m1a-acceptance m1b-acceptance

docker-clean:
	$(COMPOSE_M1A) down --remove-orphans -v || true
	$(COMPOSE_M1B) down --remove-orphans -v || true