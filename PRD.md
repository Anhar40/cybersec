# MASTER PROMPT

# AUTONOMOUS CYBER SECURITY TERMINAL AGENT

## 1. CORE CONCEPT

Build an AI-powered Cyber Security Terminal Agent using Python.

This application is NOT merely a vulnerability scanner.

It must behave like an AI coding agent / autonomous terminal agent, but specialized in authorized cyber security and web penetration testing.

The user interacts with the application through a normal conversational terminal interface.

The AI should understand natural language instructions, reason about the task, inspect the environment, execute approved security commands, analyze command output, diagnose errors, fix environment problems when possible, retry failed operations, and continue working until the requested task is completed or blocked by safety/scope constraints.

The experience should feel similar to:

* Claude Code
* OpenCode
* terminal coding agents
* autonomous coding assistants

but specialized for:

* Web security
* Web penetration testing
* Security assessment
* Reconnaissance
* Vulnerability analysis
* Security tooling
* Defensive security research

---

# 2. USER EXPERIENCE

The application should open into a conversational terminal.

Example:

```text
╭──────────────────────────────────────────────────────╮
│              CYBERSEC AI AGENT                       │
│        Autonomous Web Security Assistant             │
╰──────────────────────────────────────────────────────╯

CyberSec Agent v1.0

Type your security task.

You >
```

The user should be able to write natural language.

Examples:

```text
You > cek keamanan website saya https://example.com

You > lakukan reconnaissance pada target ini

You > cek apakah ada security misconfiguration

You > analisis endpoint API yang ditemukan

You > kenapa nuclei saya error?

You > install tools yang dibutuhkan untuk assessment ini

You > scan target ini menggunakan tools yang tersedia

You > analisis hasil scan tadi

You > buatkan laporan penetration testing
```

The user must NOT be required to remember complicated CLI commands.

The AI interprets the natural language request.

---

# 3. PERSONALITY

The AI should behave like a senior cyber security engineer with approximately 10 years of professional experience.

Personality:

* calm
* analytical
* technical
* systematic
* honest
* patient
* practical
* explains important decisions
* does not pretend a vulnerability exists without evidence
* does not pretend a command succeeded when it failed

The AI should communicate naturally.

Example:

```text
You >
install nuclei

Agent >
Baik. Sebelum menginstalnya saya akan mengecek environment
terlebih dahulu agar saya menggunakan metode instalasi yang sesuai
dengan OS kamu.

Saya akan mengecek:

• Operating system
• Architecture
• Go
• PATH
• Existing nuclei installation
• Package manager

```

---

# 4. MOST IMPORTANT FEATURE

The AI must be able to operate a controlled terminal.

The LLM is the reasoning brain.

Python is the execution layer.

Architecture:

```text
                 USER
                   │
                   ▼
          Conversation Interface
                   │
                   ▼
             AI REASONING
                   │
          ┌────────┴────────┐
          │                 │
       Planning         Analysis
          │                 │
          └────────┬────────┘
                   ▼
             TOOL REQUEST
                   │
                   ▼
             SAFETY GATE
                   │
          ┌────────┴────────┐
          │                 │
       Allowed            Blocked
          │                 │
          ▼                 ▼
      TERMINAL          Explain why
       EXECUTOR
          │
          ▼
       COMMAND
          │
          ▼
       OUTPUT
          │
          ▼
      AI ANALYSIS
          │
          ▼
       NEXT ACTION
```

---

# 5. IMPORTANT DISTINCTION

DO NOT build the application as:

```text
User
 ↓
Fixed scanner pipeline
 ↓
Report
```

Instead build:

```text
User
 ↓
AI Agent
 ↓
Observe
 ↓
Think
 ↓
Plan
 ↓
Execute
 ↓
Observe result
 ↓
Diagnose
 ↓
Fix
 ↓
Retry
 ↓
Analyze
 ↓
Continue
```

The AI should dynamically decide what to do next based on the actual environment and command results.

---

# 6. TERMINAL TOOL

Create a controlled terminal execution subsystem.

Example API:

```python
class TerminalTool:

    def execute(
        self,
        command: list[str],
        timeout: int = 30
    ):
        ...
```

The terminal tool should return:

```json
{
  "command": "nmap -sV example.com",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "duration": 12.4
}
```

The AI receives the result and determines what to do next.

---

# 7. NEVER GIVE THE LLM DIRECT SHELL ACCESS

DO NOT implement:

```python
os.system(ai_generated_command)
```

DO NOT implement:

```python
subprocess.run(ai_text, shell=True)
```

The AI must request an operation through a structured tool interface.

Example:

```json
{
  "tool": "terminal",
  "command": [
    "nmap",
    "-sV",
    "example.com"
  ],
  "reason": "Determine exposed services and versions"
}
```

Python validates the request before execution.

---

# 8. COMMAND VALIDATION

The terminal layer must validate:

* command executable
* arguments
* target
* scope
* dangerous operations
* timeout
* request rate
* privilege requirements

Use:

```python
shell=False
```

whenever possible.

Commands should be executed as argument arrays.

Example:

```python
subprocess.run(
    ["nmap", "-sV", "example.com"],
    shell=False,
    capture_output=True,
    text=True,
    timeout=60
)
```

---

# 9. AGENT LOOP

The most important component is the Agent Loop.

Pseudo architecture:

```python
while not task_finished:

    user_request = get_user_message()

    context = collect_context()

    decision = ask_ai(context)

    action = validate_action(decision)

    if action.requires_confirmation:
        ask_user()

    result = execute(action)

    add_result_to_context(result)

    continue
```

However, do not blindly repeat forever.

Implement:

```text
MAX_ITERATIONS
MAX_RUNTIME
MAX_COMMANDS
MAX_NETWORK_REQUESTS
```

---

# 10. ERROR RECOVERY

This is one of the MOST IMPORTANT features.

The AI must behave like an experienced engineer when something fails.

Example:

```text
You >
install nuclei
```

Agent:

```text
> which nuclei

Command failed:
nuclei not found
```

The AI should NOT simply tell the user:

```text
"Please install nuclei manually."
```

Instead it should investigate.

Example:

```text
Agent >

nuclei is not installed.

I will inspect the environment first.

> uname -a
> which go
> go version
> which apt
> which brew
> which winget
```

Then reason:

```text
Go is available.

The recommended installation path is therefore
through the Go toolchain.
```

Then:

```text
> install nuclei
```

If that fails:

```text
ERROR:
go: command not found
```

The AI should analyze:

```text
Go is unavailable.

I will check whether another supported installation
method is available.
```

Then:

```text
> which apt
> apt-cache search nuclei
```

If all methods fail:

```text
Agent >

I tested the available installation paths.

Result:
• Go: unavailable
• apt package: unavailable
• existing binary: unavailable

I cannot safely install nuclei automatically in this environment.

Reason:
No supported installation method is available.

The task is blocked.
```

The important behavior is:

```text
ERROR
 ↓
ANALYZE
 ↓
HYPOTHESIS
 ↓
CHECK
 ↓
FIX
 ↓
RETRY
 ↓
VERIFY
```

---

# 11. SELF-DIAGNOSTIC CAPABILITY

When a command fails, the AI should analyze:

* exit code
* stderr
* stdout
* OS
* package manager
* permissions
* PATH
* dependencies
* network
* DNS
* Python environment
* Go environment
* Node environment
* executable availability

Example:

```text
Command:
nuclei

Error:
command not found

Possible causes:

1. Not installed
2. PATH incorrect
3. Installation incomplete
4. Binary located elsewhere

The agent should test these hypotheses.
```

---

# 12. OPERATING SYSTEM DETECTION

The agent should automatically detect:

```text
Windows
Linux
macOS
WSL
Docker
VM environments where detectable
```

Collect:

```text
OS
Distribution
Version
Architecture
Kernel
Shell
Python
Git
Go
Node
Package manager
Current user
Privilege status
PATH
```

Example:

```text
Environment:

OS           : Ubuntu 24.04
Architecture : x86_64
Shell        : bash
Python       : 3.12
Go           : 1.24
Node         : 22
Git          : 2.45
Package      : apt
User         : anhar
Privilege    : standard user
```

---

# 13. TOOL DISCOVERY

The AI should be able to check whether a tool exists.

Examples:

```text
nmap
nuclei
nikto
ffuf
httpx
curl
wget
dig
openssl
whatweb
git
python
pip
go
node
npm
```

The AI should not assume tools exist.

Use:

```text
which
where
command -v
```

depending on OS.

---

# 14. TOOL INSTALLATION

The agent can install missing tools when:

1. The tool is known.
2. The installation source is trusted.
3. The package manager is recognized.
4. The action is allowed.
5. The user has appropriate permissions.

Before installation:

```text
Agent >

The task requires Nmap.

Nmap is not installed.

Detected environment:
Ubuntu 24.04
Package manager:
apt

Proposed action:

apt install nmap

This modifies the local environment.

Proceed? [Y/n]
```

For low-risk developer tooling, optionally support automatic approval through configuration.

For privileged operations, always ask.

---

# 15. INSTALLATION VERIFICATION

Installation is NOT considered successful merely because the installer exited with code 0.

After installation:

```text
nmap --version
```

Then verify:

```text
which nmap
```

The agent must confirm:

```text
✓ Installation successful
✓ Executable available
✓ Version detected
```

---

# 16. PATH REPAIR

If installation succeeds but the command cannot be found:

```text
Installation completed.

However:

nuclei: command not found
```

The agent should investigate:

```text
Go binary location
PATH
shell environment
user profile
```

Then explain the problem.

Do not silently modify shell startup files without confirmation.

---

# 17. PYTHON ENVIRONMENT

The agent should detect:

```text
system Python
virtualenv
venv
pip
pipx
poetry
uv
```

Avoid breaking the system Python.

When possible, prefer:

```text
venv
pipx
uv
```

for Python security tools.

If Python reports:

```text
externally-managed-environment
```

the AI should recognize what this means and propose a virtual environment instead of repeatedly executing the same failed command.

---

# 18. NETWORK DIAGNOSTICS

When a tool fails because of network problems, the AI should diagnose.

Possible checks:

```text
DNS
Internet connectivity
HTTP connectivity
HTTPS connectivity
proxy
firewall
certificate
```

Example:

```text
nuclei download failed.

I will determine whether this is:

1. DNS failure
2. Network failure
3. TLS failure
4. Repository unavailable
5. Proxy issue
```

Then test safely.

---

# 19. CONVERSATIONAL MEMORY

The agent should maintain context during the session.

Example:

```text
You >
scan example.com

Agent >
...

You >
gunakan nuclei juga

Agent >
Baik. Target yang sedang kita gunakan adalah:

example.com

Saya akan menggunakan nuclei pada target tersebut.
```

The user should not need to repeat the target.

---

# 20. SESSION STATE

Maintain:

```text
current_target
authorized_scope
current_task
completed_actions
failed_actions
installed_tools
environment
findings
evidence
conversation_history
```

Store session state locally.

---

# 21. SECURITY ASSESSMENT MODE

When the user asks:

```text
scan website saya
```

the agent should dynamically plan.

Example:

```text
Agent >

Saya akan melakukan assessment bertahap:

1. Target validation
2. Environment check
3. Tool availability
4. Passive reconnaissance
5. HTTP analysis
6. Technology fingerprinting
7. Endpoint discovery
8. Security configuration analysis
9. Controlled vulnerability assessment
10. Evidence verification
11. Report generation
```

The AI may modify the plan based on evidence.

---

# 22. WEB SECURITY SPECIALIZATION

The agent should understand:

* HTTP
* HTTPS
* DNS
* TLS
* cookies
* sessions
* authentication
* authorization
* REST API
* GraphQL
* JWT
* CORS
* CSP
* CSRF
* XSS
* SQL injection
* command injection
* SSRF
* IDOR/BOLA
* file upload security
* path traversal
* security misconfiguration
* information disclosure
* exposed services
* outdated components
* rate limiting
* access control
* API security

The AI should understand the concepts, but testing must remain controlled and authorized.

---

# 23. TARGET SCOPE

Every assessment must have an explicit scope.

Example:

```text
Target:
https://example.com

Allowed:
example.com

Excluded:
admin.example.com
payments.example.com
external-service.com
```

If an action targets something outside the scope:

```text
ACTION BLOCKED

Target is outside the authorized scope.
```

---

# 24. HUMAN CONFIRMATION

The AI should NOT ask for confirmation for every harmless operation.

Use risk levels.

### LOW RISK

Examples:

```text
uname
whoami
python --version
which nmap
curl -I target
```

Can execute automatically.

### MEDIUM RISK

Examples:

```text
active endpoint discovery
directory enumeration
moderate scanning
```

May require confirmation depending on configuration.

### HIGH RISK

Examples:

```text
exploitation
actions that modify application state
authenticated testing
potentially destructive payloads
```

Always require explicit confirmation.

---

# 25. NO DESTRUCTIVE AUTONOMY

The agent must NEVER autonomously:

* destroy data
* delete files on target systems
* modify production databases
* create persistence
* install malware
* deploy web shells
* steal credentials
* dump secrets
* exfiltrate sensitive information
* perform denial of service
* bypass safety controls
* attack unrelated systems

If the user requests such an operation, the agent should explain the boundary and stop or offer a safe diagnostic alternative.

---

# 26. SECURITY TOOL EXECUTION

Tools are capabilities, not the AI itself.

Create tools such as:

```text
TerminalTool
HttpTool
DnsTool
TlsTool
PortScannerTool
WebReconTool
TechnologyDetectionTool
HeaderAnalyzerTool
DirectoryDiscoveryTool
VulnerabilityScannerTool
ReportTool
```

Each tool must have:

```text
name
description
input schema
validation
execution
output schema
risk level
```

---

# 27. TOOL REGISTRY

Example:

```python
TOOLS = {
    "terminal": TerminalTool(),
    "http": HttpTool(),
    "dns": DnsTool(),
    "tls": TlsTool(),
    "recon": WebReconTool(),
}
```

The AI should only be able to call registered tools.

---

# 28. AI TOOL CALL FORMAT

The LLM should return structured tool calls.

Example:

```json
{
  "type": "tool_call",
  "tool": "terminal",
  "arguments": {
    "command": [
      "nmap",
      "-sV",
      "example.com"
    ]
  },
  "reason": "Identify exposed services"
}
```

Python validates this.

Never execute raw AI text.

---

# 29. THINKING / REASONING DISPLAY

Do NOT expose private chain-of-thought.

Instead show concise action reasoning.

Example:

```text
Agent >

I found that Nmap is unavailable.

Reason:
The next step is to determine whether it is missing entirely
or simply unavailable through PATH.

Action:
Checking Nmap installation and PATH...
```

Never display hidden chain-of-thought.

---

# 30. REAL-TIME EXECUTION UI

While executing:

```text
╭─────────────────────────────────────────────╮
│ TOOL EXECUTION                              │
├─────────────────────────────────────────────┤
│ Tool       : terminal                       │
│ Command    : nmap -sV example.com            │
│ Risk       : LOW                             │
│ Status     : RUNNING                         │
╰─────────────────────────────────────────────╯
```

Then:

```text
✓ Command completed
Exit code: 0
Duration: 12.4s
```

For errors:

```text
✗ Command failed
Exit code: 127

The AI will analyze the error.
```

---

# 31. AGENT ERROR LOOP

Implement:

```text
EXECUTE
   ↓
SUCCESS?
 ┌─┴─┐
YES  NO
 │    │
 ▼    ▼
NEXT  ANALYZE ERROR
      │
      ▼
   DIAGNOSE
      │
      ▼
   PROPOSE FIX
      │
      ▼
   VALIDATE FIX
      │
      ▼
     RETRY
```

Maximum retries:

```text
MAX_RETRIES_PER_ACTION=3
```

Do not repeatedly execute the same failed command.

---

# 32. EXAMPLE ERROR RECOVERY

If:

```text
pip install something
```

returns:

```text
externally-managed-environment
```

The AI should understand the error and switch strategy.

Example response:

```text
Agent >

The system Python environment is externally managed.

Repeating pip install against the system interpreter would
produce the same error.

I will use an isolated virtual environment instead.
```

Then:

```text
python -m venv .venv
```

Verify:

```text
.venv/bin/python
```

Then install.

---

# 33. OPENROUTER

Use OpenRouter as the AI provider.

Configuration:

```env
OPENROUTER_API_KEY=
OPENROUTER_MODEL=
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
```

The model must be configurable.

Do not hardcode a model.

The AI client must support:

* retries
* timeout
* malformed JSON recovery
* rate limit handling
* connection errors
* model errors

---

# 34. AI FAILURE RECOVERY

If OpenRouter returns an error:

```text
401
429
500
timeout
invalid JSON
```

The application should diagnose the problem.

Example:

```text
OpenRouter returned HTTP 429.

Possible cause:
rate limit.

The agent will wait and retry according to the configured
backoff strategy.
```

Do not loop indefinitely.

---

# 35. COMMAND HISTORY

Maintain:

```text
command history
tool history
errors
successful commands
```

Example:

```text
[001] uname -a
[002] which nmap
[003] nmap --version
[004] nmap -sV example.com
```

The AI can use previous results.

---

# 36. FILE OPERATIONS

The agent may inspect and modify its own project files when necessary.

For example:

```text
You >
perbaiki error pada agent.py
```

The AI should be able to:

1. Read file
2. Understand error
3. Modify code
4. Run tests
5. Analyze failure
6. Fix
7. Re-run
8. Confirm success

This should behave similarly to a coding agent.

However, modifications to the user's external system must remain scoped and require appropriate confirmation.

---

# 37. CYBERSECURITY MODE

Implement a mode:

```text
MODE:
WEB_SECURITY
```

Future modes may include:

```text
WEB_SECURITY
API_SECURITY
NETWORK_SECURITY
LOCAL_SECURITY
CTF
LAB
```

For the first version, focus on:

```text
WEB_SECURITY
```

---

# 38. INTERACTIVE COMMANDS

Support commands such as:

```text
/help
/status
/tools
/env
/target
/scope
/history
/findings
/report
/stop
/clear
/exit
```

But natural language should remain the primary interface.

---

# 39. EXAMPLE COMPLETE SESSION

The final experience should look approximately like this:

```text
╭──────────────────────────────────────────────────╮
│             CYBERSEC AI AGENT                    │
│       Autonomous Web Security Assistant          │
╰──────────────────────────────────────────────────╯

You > lakukan security assessment website saya
      https://example.com

Agent >

Baik.

Saya akan melakukan assessment secara bertahap dan tetap
berada dalam scope target yang diberikan.

Target:
https://example.com

Saya akan mulai dengan pemeriksaan environment.

> detecting operating system...

✓ Ubuntu 24.04
✓ x86_64
✓ Python 3.12
✓ bash

Sekarang saya mengecek tools yang tersedia.

> nmap
✓ installed

> nuclei
✗ not installed

Nuclei diperlukan untuk tahap vulnerability assessment.

Saya akan mencari metode instalasi yang sesuai dengan
environment ini.

> go version

✓ Go 1.24

Go tersedia.

Saya akan menggunakan metode instalasi yang sesuai.

> installing...

✓ installation completed

> nuclei -version

✓ nuclei available

Melanjutkan reconnaissance.

> HTTP reconnaissance...

✓ HTTPS
✓ TLS 1.3
✓ nginx detected

Technology fingerprint:

✓ Laravel
Confidence: 86%

Saya menemukan beberapa indikasi yang perlu dianalisis lebih lanjut.

[1] Missing security header
[2] Public endpoint
[3] Potential information disclosure

Saya akan melakukan validasi terhadap temuan tersebut.
```

---

# 40. IMPLEMENTATION PRIORITY

Do NOT build every scanner immediately.

The first goal is making the AGENT LOOP work.

Implement in this order:

## PHASE 1

Conversation interface.

Must support:

```text
User message
 ↓
OpenRouter
 ↓
AI response
 ↓
User
```

---

## PHASE 2

Environment tools.

Implement:

```text
OS detection
tool detection
PATH detection
package manager detection
permission detection
```

---

## PHASE 3

Terminal Tool.

Implement:

```text
command execution
stdout
stderr
exit code
timeout
logging
```

---

## PHASE 4

AI Tool Calling.

Implement:

```text
AI
 ↓
structured tool request
 ↓
validation
 ↓
terminal
 ↓
result
 ↓
AI
```

---

## PHASE 5

Error Recovery.

Implement:

```text
error detection
diagnosis
fix proposal
retry
verification
```

---

## PHASE 6

Tool Manager.

Implement:

```text
detect
install
verify
repair PATH
```

---

## PHASE 7

Web Security Tools.

Add:

```text
curl
nmap
httpx
whatweb
nikto
nuclei
ffuf
dig
openssl
```

Only after the agent loop is stable.

---

## PHASE 8

Web Reconnaissance.

---

## PHASE 9

Vulnerability Assessment.

---

## PHASE 10

Evidence and Reporting.

---

# 41. FIRST DEVELOPMENT TASK

IMPORTANT:

Do NOT implement the entire system now.

Start ONLY with:

```text
PHASE 1
```

Build a working conversational AI terminal agent.

Requirements:

```text
User
 ↓
Python application
 ↓
OpenRouter
 ↓
AI response
 ↓
User
```

Then add the first safe tool:

```text
environment
```

The AI should be able to understand:

```text
"cek OS saya"
```

and request the environment tool.

Example:

```text
You >
cek OS saya

Agent >

Saya akan memeriksa environment terlebih dahulu.

[environment tool]

OS:
Ubuntu 24.04

Architecture:
x86_64

Python:
3.12

Shell:
bash
```

Then test:

```text
You >
apakah nmap sudah terinstall?

Agent >

Saya akan mengeceknya.

[tool execution]

nmap tidak ditemukan.

Saya bisa membantu menyiapkan instalasinya.
```

DO NOT implement vulnerability exploitation yet.

DO NOT implement uncontrolled autonomous scanning yet.

DO NOT create arbitrary shell execution.

First prove that the core agent loop works correctly.

---

# 42. DEFINITION OF DONE

Phase 1 is complete only when:

* application starts successfully
* interactive chat works
* OpenRouter works
* conversation context works
* environment tool works
* AI can request the environment tool
* tool result is returned to AI
* AI understands tool result
* errors are handled
* malformed AI responses are handled
* API failures are handled
* terminal UI is clean
* no API key is hardcoded
* no arbitrary shell execution exists
* tests pass

After that, STOP.

Do not continue to Phase 2 until explicitly instructed.

END MASTER PROMPT
