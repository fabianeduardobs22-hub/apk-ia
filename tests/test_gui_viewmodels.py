from sentinel_x_defense_suite.gui.viewmodels import RowMetrics, compute_dashboard_metrics


def test_compute_dashboard_metrics_levels_and_lines() -> None:
    rows = [
        RowMetrics("10.0.0.1", "8.8.8.8", "tcp", "low", "AR"),
        RowMetrics("10.0.0.2", "8.8.4.4", "udp", "high", "US"),
        RowMetrics("10.0.0.2", "8.8.4.4", "udp", "critical", "US"),
    ]
    metrics = compute_dashboard_metrics(rows)
    assert metrics.threat_level == "CRITICAL"
    assert any("TCP" in line for line in metrics.protocol_lines)
    assert any("US" in line for line in metrics.geo_lines)
    assert any("10.0.0.2 -> 8.8.4.4" in line for line in metrics.topology_lines)


def test_compute_dashboard_metrics_empty() -> None:
    metrics = compute_dashboard_metrics([])
    assert metrics.threat_level == "LOW"
    assert any("Sin datos" in line for line in metrics.geo_lines)
