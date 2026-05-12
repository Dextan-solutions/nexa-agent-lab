# Agent Module Template (NexaBank Agent Security Lab)

This file documents how to add a new agent module that can be triggered by NexaBank workflows.

> Scaffold state: Step 1. The `AGENT_MODULE` interface will be implemented in Step 2.

## Where to put it

- `backend/agents/<agent_name>/`
  - `agent.py`
  - `prompts.py`
  - `tools.py`
  - `vulnerabilities.py`

## Requirements

- Agent must implement the common base agent interface (`backend/agents/base_agent.py`).
- Agent must read security-level behavior from `backend/config/security_levels.yaml`.

