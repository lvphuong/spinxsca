---
name: command-injection
description: "OS command injection: input reaching a shell or a process argument list."
allowed_tools: [read_file, search_code]
categories: [COMMAND_INJECTION, CODE_INJECTION]
---
# OS command injection: input reaching a shell or a process argument list.

1. Sinks: `child_process.exec`/`execSync`, `spawn` with `shell: true`, `os.system`, `subprocess.*(shell=True)`, `Runtime.exec(String)`, backticks, `eval`/`Function`/`exec` for code injection.
2. `spawn`/`execFile`/`subprocess.run([...])` with an argument array and no shell is not shell injection, but check for argument injection (a value starting with `-` passed to `git`, `tar`, `curl`, `ssh`).
3. Trace the command string to request data, filenames, environment set by users, or stored values.
4. Controls that count: no shell plus an allow-list of commands and arguments, `--` before user arguments, strict validation of the full value. Quoting by hand is not a control.
5. A command executed as a privileged user or in a container with secrets is CRITICAL when reachable unauthenticated.
