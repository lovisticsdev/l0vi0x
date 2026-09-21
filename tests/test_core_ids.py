from l0vi0x.core.ids import AuditCounter, next_id


def test_next_id_uses_sequence_prefix():
    counter = AuditCounter("H")
    assert next_id("H", counter) == "H-001"
    assert next_id("H", counter) == "H-002"


def test_next_id_respects_other_prefixes():
    task_counter = AuditCounter("T")
    assert next_id("T", task_counter) == "T-001"
