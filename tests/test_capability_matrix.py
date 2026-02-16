from sentinel_x_defense_suite.core.capability_matrix import default_capability_matrix, summarize_matrix


def test_default_capability_matrix_not_empty() -> None:
    matrix = default_capability_matrix()
    assert matrix
    assert any(item.name == "Visibilidad en tiempo real" for item in matrix)


def test_summary_has_expected_keys() -> None:
    summary = summarize_matrix(default_capability_matrix())
    assert set(summary.keys()) == {"sentinel_avg", "reference_avg", "delta"}
    assert summary["sentinel_avg"] >= summary["reference_avg"]
