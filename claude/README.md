# Claude Code Integration

This folder contains Claude Code specific configuration for the network sandbox.

## Files

- `CLAUDE.md` - Context file for Claude Code to understand it's running in a sandbox
- `settings.json` - Claude Code settings that enforce sandbox mode
- `policy-extra.txt` - Additional policy rules for Anthropic API access

## Setup

1. Append the extra policy rules to the main policy:
   ```bash
   cat claude/policy-extra.txt >> policy.txt
   ```

2. Copy settings to your Claude config:
   ```bash
   cp claude/settings.json ~/.claude/settings.json
   # Or for project-specific:
   cp claude/settings.json .claude/settings.json
   ```

3. Copy CLAUDE.md to your project root:
   ```bash
   cp claude/CLAUDE.md ./CLAUDE.md
   ```

4. Start the sandbox and run Claude:
   ```bash
   sudo ./sandbox.sh claude
   ```
