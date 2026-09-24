lovisticsdev@Mobilith:~/projects/l0vi0x$ git log --oneline
7df4b9e (HEAD -> development) M2.1 — Fake adapter first, then openai_compat
2290656 M2.0 — Model/config schemas
64a97e4 (origin/development) fix: complete M1a Foundry acceptance and M1b integration
0315cb5 candidate baseline for M0-M1b
4f8e930 feat: implement M0-M1b security research foundation
e403d9e chore: initial l0vi0x project scaffold
lovisticsdev@Mobilith:~/projects/l0vi0x$ make test
uv run --locked pytest tests
........................................s.....................................................F.....                                                                                                                                                                                                           [100%]
====================================================================================================================================================== FAILURES ======================================================================================================================================================
_____________________________________________________________________________________________________________________________ test_all_plan_schemas_exist_and_are_generated_from_models ______________________________________________________________________________________________________________________________

tmp_path = PosixPath('/tmp/pytest-of-lovisticsdev/pytest-3/test_all_plan_schemas_exist_an0')

    def test_all_plan_schemas_exist_and_are_generated_from_models(tmp_path):
        root = Path(__file__).resolve().parents[1]
        schema_dir = tmp_path / "schemas"
        written = generate_schemas(schema_dir)
        assert len(written) == 20
        assert check_schema_drift(schema_dir) == []
>       assert check_schema_drift(root / "schemas") == []
E       AssertionError: assert ['model_profi....schema.json'] == []
E         
E         Left contains 2 more items, first extra item: 'model_profile.schema.json'
E         Use -v to get more diff

tests/test_schema_generation.py:16: AssertionError
============================================================================================================================================== short test summary info ===============================================================================================================================================
FAILED tests/test_schema_generation.py::test_all_plan_schemas_exist_and_are_generated_from_models - AssertionError: assert ['model_profi....schema.json'] == []
1 failed, 98 passed, 1 skipped in 17.20s
make: *** [Makefile:11: test] Error 1
lovisticsdev@Mobilith:~/projects/l0vi0x$ make schemas-generate
make schemas
uv run --locked python -c "from pathlib import Path; from l0vi0x.core.schema_gen import generate_schemas; generate_schemas(Path('schemas'))"
uv run --locked python -c "from pathlib import Path; from l0vi0x.core.schema_gen import check_schema_drift; p=Path('schemas'); drift=check_schema_drift(p); import sys; sys.exit('schema drift: '+', '.join(drift) if drift else 0)"
lovisticsdev@Mobilith:~/projects/l0vi0x$ git status
On branch development
Your branch is ahead of 'origin/development' by 2 commits.
  (use "git push" to publish your local commits)

Untracked files:
  (use "git add <file>..." to include in what will be committed)
        schemas/model_profile.schema.json
        schemas/stack_policy.schema.json

nothing added to commit but untracked files present (use "git add" to track)
lovisticsdev@Mobilith:~/projects/l0vi0x$ git add schemas/model_profile.schema.json schemas/stack_policy.schema.json
git commit --amend --no-edit
[development 75cc156] M2.1 — Fake adapter first, then openai_compat
 Date: Wed Sep 23 23:11:25 2026 +0300
 11 files changed, 716 insertions(+), 1 deletion(-)
 create mode 100644 schemas/model_profile.schema.json
 create mode 100644 schemas/stack_policy.schema.json
 create mode 100644 src/l0vi0x/models/__init__.py
 create mode 100644 src/l0vi0x/models/adapters/__init__.py
 create mode 100644 src/l0vi0x/models/adapters/base.py
 create mode 100644 src/l0vi0x/models/adapters/fake.py
 create mode 100644 src/l0vi0x/models/adapters/openai_compat.py
 create mode 100644 tests/test_m2_adapters.py
 delete mode 100644 updated.zip
lovisticsdev@Mobilith:~/projects/l0vi0x$ make test
uv run --locked pytest tests
........................................s...........................................................                                                                                                                                                                                                           [100%]
99 passed, 1 skipped in 12.86s
lovisticsdev@Mobilith:~/projects/l0vi0x$ 