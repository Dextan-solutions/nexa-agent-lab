from __future__ import annotations

from pathlib import Path

from config.security_loader import get_agent_security_config, load_security_levels


def test_security_levels_yaml_parses_and_contains_expected_gap_keys() -> None:
    # In-container, tests live at `/app/tests/*` and config is at `/app/config/*`.
    data = load_security_levels(Path(__file__).resolve().parents[1] / "config" / "security_levels.yaml")

    expected: dict[str, dict[str, set[str]]] = {
        "max": {
            "low": {
                "monitoring_interval_seconds",
                "narration_field_trusted",
                "memo_field_trusted",
                "max_autonomous_actions_per_run",
                "alert_before_action",
            },
            "medium": {
                "monitoring_interval_seconds",
                "narration_field_trusted",
                "memo_field_trusted",
                "max_autonomous_actions_per_run",
                "alert_before_action",
            },
            "hard": {
                "monitoring_interval_seconds",
                "narration_field_trusted",
                "memo_field_trusted",
                "max_autonomous_actions_per_run",
                "alert_before_action",
            },
            "secure": {
                "monitoring_interval_seconds",
                "narration_field_trusted",
                "memo_field_trusted",
                "max_autonomous_actions_per_run",
                "alert_before_action",
            },
        },
        "vera": {
            "low": {
                "invisible_text_detection",
                "metadata_fields_written_to_embedding",
                "retrieval_source_validation",
                "document_ownership_check",
            },
            "medium": {
                "invisible_text_detection",
                "metadata_fields_written_to_embedding",
                "retrieval_source_validation",
                "document_ownership_check",
            },
            "hard": {
                "invisible_text_detection",
                "metadata_fields_written_to_embedding",
                "retrieval_source_validation",
                "document_ownership_check",
            },
            "secure": {
                "invisible_text_detection",
                "metadata_fields_written_to_embedding",
                "retrieval_source_validation",
                "document_ownership_check",
            },
        },
        "finn": {
            "low": {"session_memory_turns", "system_prompt_in_every_turn", "rag_source_attribution"},
            "medium": {"session_memory_turns", "system_prompt_in_every_turn", "rag_source_attribution"},
            "hard": {"session_memory_turns", "system_prompt_in_every_turn", "rag_source_attribution"},
            "secure": {"session_memory_turns", "system_prompt_in_every_turn", "rag_source_attribution"},
        },
        "ops": {
            "low": {
                "system_prompt_contains_token_format",
                "system_prompt_contains_network_topology",
                "system_prompt_contains_system_names",
                "employee_lookup_scope",
            },
            "medium": {
                "system_prompt_contains_token_format",
                "system_prompt_contains_network_topology",
                "system_prompt_contains_system_names",
                "employee_lookup_scope",
            },
            "hard": {
                "system_prompt_contains_token_format",
                "system_prompt_contains_network_topology",
                "system_prompt_contains_system_names",
                "employee_lookup_scope",
            },
            "secure": {
                "system_prompt_contains_token_format",
                "system_prompt_contains_network_topology",
                "system_prompt_contains_system_names",
                "employee_lookup_scope",
            },
        },
    }

    for agent, levels in expected.items():
        for level, keys in levels.items():
            cfg = get_agent_security_config(data=data, agent=agent, level=level).config
            for k in keys:
                assert k in cfg, f"Missing {agent}.{level}.{k}"

