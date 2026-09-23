lovisticsdev@Mobilith:~/projects/l0vi0x$ git log
commit 64a97e4e2fe7454532c3ba2e5bd613dfe5ed3026 (HEAD -> development, origin/development)
Author: Lovice Ochieng <lovisticsdev@gmail.com>
Date:   Wed Sep 23 21:45:37 2026 +0300

    fix: complete M1a Foundry acceptance and M1b integration

commit 0315cb5fe8054d221596bf32615f3f757084e265
Author: Lovice Ochieng <lovisticsdev@gmail.com>
Date:   Mon Sep 21 14:06:39 2026 +0300

    candidate baseline for M0-M1b

commit 4f8e9306225c38ec458c8faf6df556db7c3c39a6
Author: Lovice Ochieng <lovisticsdev@gmail.com>
Date:   Mon Sep 21 13:13:40 2026 +0300

    feat: implement M0-M1b security research foundation
    
    Add lifecycle, policy, schemas, tooling, Foundry fixtures, M1a replay infrastructure, and M1b verification pipeline.

commit e403d9e502cb5f7fe53e43994d73a7d13d7446b8
Author: Lovice Ochieng <lovisticsdev@gmail.com>
Date:   Sun Sep 20 15:37:30 2026 +0300

    chore: initial l0vi0x project scaffold
lovisticsdev@Mobilith:~/projects/l0vi0x$ git status
On branch development
Your branch is up to date with 'origin/development'.

Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)

        modified:   src/l0vi0x/core/models.py
        modified:   src/l0vi0x/core/schema_gen.py
        modified:   tests/test_schema_generation.py

Untracked files:
  (use "git add <file>..." to include in what will be committed)
        tests/test_m2_schemas.py

no changes added to commit (use "git add" and/or "git commit -a")
(l0vi0x) lovisticsdev@Mobilith:~/projects/l0vi0x$ uv sync --locked --extra dev
warning: `VIRTUAL_ENV=/mnt/c/Users/odong/Downloads/ethereum-mastery/l0vi0x/.venv` does not match the project environment path `.venv` and will be ignored; use `--active` to target the active environment instead
Resolved 26 packages in 5ms
Checked 25 packages in 1ms
(l0vi0x) lovisticsdev@Mobilith:~/projects/l0vi0x$ PYTHONPATH=src uv run --locked pytest tests/test_m2_schemas.py tests/test_m2_adapters.py -v
warning: `VIRTUAL_ENV=/mnt/c/Users/odong/Downloads/ethereum-mastery/l0vi0x/.venv` does not match the project environment path `.venv` and will be ignored; use `--active` to target the active environment instead
================================================================================================================================================ test session starts =================================================================================================================================================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/lovisticsdev/projects/l0vi0x
configfile: pyproject.toml
plugins: hypothesis-6.168.0, asyncio-1.4.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 17 items                                                                                                                                                                                                                                                                                                   

tests/test_m2_schemas.py .....                                                                                                                                                                                                                                                                                 [ 29%]
tests/test_m2_adapters.py ............                                                                                                                                                                                                                                                                         [100%]

================================================================================================================================================= 17 passed in 5.73s =================================================================================================================================================
(l0vi0x) lovisticsdev@Mobilith:~/projects/l0vi0x$ 


For M2.0 - M2.12 we implement everything upto where a test is needed to proceed. we'll proceed like that until M2.12

This is useful — existing scaffold already anticipates several M2 concepts, we build against rather than duplicate:

- `core/events.py` already registers `model_unavailable`, `quota_switch`, `refusal_logged`, `skeptic_family_exhausted`/`skeptic_unavailable`/`skeptic_second_opinion` as event kinds
- `Task.exclude_families` and `WorkerResult.model_used`/`usage` already exist — the router's contract is partly pre-defined
- `Scope.confidentiality: "public"|"private"` is almost certainly what "a private audit cannot select a dev stack" (M2.6) refers to

**M2.0 done — 88/88 passing.** Quick summary of what landed:

- `ModelProfile` and `StackPolicy` added to `core/models.py`, matching the existing `Strict` convention. `ModelProfile.family` reuses the same naming `Task.exclude_families`/`Finding.skeptic_families_excluded` already use — so M2.9's exclusion logic will key off the same field name across the codebase, not a parallel concept.
- Both registered in `schema_gen.py`, generated into `schemas/model_profile.schema.json` and `schemas/stack_policy.schema.json`, confirmed stable across regeneration (`check_schema_drift` clean, twice).
- The "prod stack cannot allow free/shadow-priced models" rule is enforced *at construction time* on `StackPolicy` itself (invalid config can't even be built) — belt-and-suspenders with the runtime gate that'll also check it in M2.6.
- Fixed a pre-existing test (`test_schema_generation.py`) that hard-codes the total schema count — correctly caught the addition and needed a deliberate bump, unlike the earlier M1b bugs where tests were wrongly silent.

One thing worth flagging before you move to M2.1: "a private audit cannot select a dev stack" (M2.6) will key off `Scope.confidentiality`, which already exists — I didn't need to add anything for that half of the rule, `StackPolicy.kind` plus the existing `Scope` field is enough. Wire the actual check in M2.6, not now.

We need to move to **M2.1 — fake adapter, then `openai_compat`**.