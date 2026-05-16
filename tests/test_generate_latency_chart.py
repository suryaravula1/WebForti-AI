from __future__ import annotations

from benchmarks.generate_latency_chart import (
    CveLatencyPoint,
    ModelLatencyPoint,
    build_synthetic_model_cve_matrix,
    extract_per_cve_tables,
    select_per_cve_table,
)


def test_extracts_latest_per_cve_table_by_default() -> None:
    markdown = """
## 2026-05-08: OpenRouter Qwen + Docker

Per-CVE results:

| CVE | Status | Verification | Time |
| --- | --- | --- | ---: |
| CVE-2021-41773 | completed | pass | 21.0342s |

## 2026-05-09: Mock Planner + Docker

Per-CVE results:

| CVE | Status | Verification | Time |
| --- | --- | --- | ---: |
| CVE-2020-5902 | completed | pass | 17.7483s |
"""

    heading, rows = select_per_cve_table(extract_per_cve_tables(markdown))

    assert heading == "2026-05-09: Mock Planner + Docker"
    assert len(rows) == 1
    assert rows[0].cve_id == "CVE-2020-5902"
    assert rows[0].seconds == 17.7483


def test_selects_matching_section_filter() -> None:
    markdown = """
## 2026-05-08: OpenRouter Qwen + Docker

Per-CVE results:

| CVE | Status | Verification | Time |
| --- | --- | --- | ---: |
| CVE-2021-41773 | completed | pass | 21.0342s |
| CVE-2022-22965 | completed | pass | 26.2133s |

## 2026-05-09: Mock Planner + Docker

Per-CVE results:

| CVE | Status | Verification | Time |
| --- | --- | --- | ---: |
| CVE-2020-5902 | completed | pass | 17.7483s |
"""

    heading, rows = select_per_cve_table(extract_per_cve_tables(markdown), section_filter="Qwen")

    assert heading == "2026-05-08: OpenRouter Qwen + Docker"
    assert [row.cve_id for row in rows] == ["CVE-2021-41773", "CVE-2022-22965"]


def test_builds_synthetic_model_cve_matrix_from_cve_profile() -> None:
    cve_rows = [
        CveLatencyPoint("CVE-1", "completed", "pass", 20.0),
        CveLatencyPoint("CVE-2", "completed", "pass", 30.0),
    ]
    model_rows = [
        ModelLatencyPoint("GPT-5.4", 10.0),
        ModelLatencyPoint("Gemini 2.5 Pro", 20.0),
    ]

    matrix = build_synthetic_model_cve_matrix(cve_rows, model_rows)

    assert matrix["cve_labels"] == ["CVE-1", "CVE-2"]
    assert matrix["model_labels"] == ["GPT-5.4", "Gemini 2.5 Pro"]
    assert matrix["values"] == [[8.0, 16.0], [12.0, 24.0]]
