# Agents

Guidance for any coding agent working in this repository.

Agent contract: [CLAUDE.md](CLAUDE.md). Estate contract (labels, traps, conventions): https://github.com/JorisJonkers-dev/workspace/blob/main/CLAUDE.md

This repository is the `jorisjonkers-commons` Rust crate, shared code for estate services. Sources are in `src` and tests in `tests`.

## Build and test

Tasks are defined in `Taskfile.yml`:

```bash
task check        # everything CI runs on a pull request: lint, test, secrets
task lint         # rustfmt, clippy, rustdoc, actionlint
task test         # tests with a 95% line coverage gate
task fix          # apply formatters and autofixes
```
