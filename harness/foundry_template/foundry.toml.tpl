[profile.default]
ffi = false
fs_permissions = []
always_use_create_2_factory = true
optimizer = true
optimizer_runs = 200
solc_version = "{{ SOLC_VERSION }}"
evm_version = "{{ EVM_VERSION }}"

[profile.default.fuzz]
runs = {{ FUZZ_RUNS }}
seed = {{ FUZZ_SEED }}

[rpc_endpoints]
l0vi0x_gate = "{{ GATE_URL }}"
