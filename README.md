# Prompt Guard Injection Sanitizer Skill for Autonomous Agents

[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-blue.svg)](https://modelcontextprotocol.io)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-brightgreen.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-zero-success.svg)](requirements.txt)

Enterprise-grade defensive input firewall for LLM autonomous agents. Inspects, filters, and neutralizes prompt injections, indirect jailbreaks, and instructions override exploits before passing untrusted text into prompts.

## Key Features
- **Exploit & Jailbreak Detection**: Flags attempts to override system prompts or bypass ethical boundary instructions.
- **Neutralization**: Replaces hostile command sequences with safe sanitized placeholders.
- **Zero Overhead**: Blazing fast regex and heuristic matching using the Python Standard Library.

## MCP Server Integration
```bash
python mcp_server.py
```

### Available MCP Tools
- `sanitize_prompt`: Analyze and cleanse text of malicious injection attacks.
- `inspect_threats`: Scan text and list identified security threat patterns.
