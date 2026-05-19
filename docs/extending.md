# Extending Phalanx (Plugins & Parsers)

Phalanx is designed to be highly extensible. Because there are thousands of open-source security tools in the wild, we couldn't possibly support all of them out of the box. 

Instead, we built a simple Plugin Architecture that allows anyone in the community to add support for their favorite tool.

---

## 🛠️ How Tool Integrations Work

When the AI Planner decides to run a tool (e.g., `nmap`), the Execution Engine runs the raw binary in the background. However, the raw output (stdout) of security tools is usually messy, human-readable text.

To make this data useful for the AI in future steps, it needs to be parsed into structured JSON. This is where **Parsers** come in.

A Parser is simply a small Python class that takes the raw string output of a tool and returns a Python dictionary.

---

## ✍️ Writing a Custom Parser

Let's say you want to add support for a fictional tool called `sec-scanner`.

### 1. Create the Parser File
Navigate to `src/phalanx/parsers/` and create a new file called `sec_scanner.py`.

### 2. Implement the Parser Class
Your class must inherit from `BaseParser` (or simply implement the `parse` method if you prefer a lighter touch).

```python
from phalanx.parsers.base import BaseParser

class SecScannerParser(BaseParser):
    """Parser for the sec-scanner security tool."""
    
    @property
    def tool_name(self) -> str:
        return "sec-scanner"

    def parse(self, stdout: str, stderr: str = "") -> dict:
        # Here is where you write the logic to extract data from the stdout!
        results = []
        
        for line in stdout.splitlines():
            if "VULNERABILITY FOUND:" in line:
                vuln = line.split(":")[-1].strip()
                results.append({"vulnerability": vuln, "severity": "high"})
                
        return {
            "status": "success",
            "findings_count": len(results),
            "findings": results,
            "raw_output": stdout
        }
```

### 3. Register the Parser
Once your parser is written, you need to tell the Execution Engine that it exists. 

Open `src/phalanx/parsers/__init__.py` and add your new class to the global parser registry map so it can be dynamically loaded.

### 4. Test It!
Run `phalanx` and ask it to use your tool:
```bash
phalanx run "execute sec-scanner on example.com"
```
If your parser works, Phalanx will successfully parse the output into a structured table and the AI will be able to summarize the `findings_count` accurately!

---

## 🤝 Submitting Your Plugin

If you write a parser for a popular security tool, we would **love** for you to contribute it back to the community!

Just open a Pull Request (see [contributing.md](contributing.md)) and we'll happily merge it into the core project so everyone else can benefit from your hard work.
