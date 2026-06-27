"""
LLM Confirmer
=============
Uses LLM to confirm uncertain findings and reduce false positives.
"""
import os
import sys
import json
import warnings
from pathlib import Path
from typing import List, Dict, Any, Optional

warnings.filterwarnings("ignore")
os.environ["TOKENIZERS_PARALLELISM"] = "false"

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from models.ollama_client import load_model
except ImportError:
    load_model = None


class LLMConfirmer:
    """Confirms vulnerability findings using LLM reasoning."""

    def __init__(self, model_name: str = "qwen2.5-coder:14b"):
        self.model_name = model_name
        self.llm = None
        self._init_llm()

    def _init_llm(self):
        if load_model:
            try:
                self.llm = load_model(self.model_name)
            except Exception as e:
                print(f"[LLM-Confirmer] Could not load LLM: {e}")
        else:
            print("[LLM-Confirmer] No LLM client available")

    def confirm_batch(self, findings: List[Dict], source_code: str) -> List[Dict]:
        """Confirm multiple findings. Only runs on medium confidence findings."""
        if not self.llm:
            return findings

        confirmed = []
        for finding in findings:
            conf = finding.get("confidence", 0)
            if conf < 0.7 and conf > 0.3:
                # Borderline - ask LLM
                result = self._confirm_one(finding, source_code)
                if result.get("is_vulnerable", False):
                    finding["llm_confirmed"] = True
                    finding["llm_confidence"] = result.get("confidence", 0.5)
                    finding["llm_explanation"] = result.get("explanation", "")
                    finding["confidence"] = (conf * 0.4) + (result.get("confidence", 0) * 0.6)
                    confirmed.append(finding)
            else:
                # High confidence or very low - pass through
                finding["llm_confirmed"] = conf >= 0.7
                confirmed.append(finding)

        return confirmed

    def _confirm_one(self, finding: Dict, source_code: str) -> Dict:
        """Ask LLM to confirm a single finding."""
        func_name = finding.get("function", "unknown")
        vuln_type = finding.get("vuln_type", "unknown")
        description = finding.get("description", "")

        line = finding.get("line", 0)
        snippet = self._extract_snippet(source_code, line)

        prompt = self._build_prompt(vuln_type, description, func_name, snippet)

        try:
            response = self.llm.invoke(prompt)
            content = response.content if hasattr(response, "content") else str(response)
            return self._parse_response(content)
        except Exception as e:
            print(f"[LLM-Confirmer] Error: {e}")
            return {"is_vulnerable": True, "confidence": 0.5}

    def _build_prompt(self, vuln_type: str, description: str, func_name: str, snippet: str) -> str:
        return f"""You are a Solana smart contract security expert.

Analyze this potential vulnerability:

VULNERABILITY: {vuln_type}
DESCRIPTION: {description}
FUNCTION: {func_name}

CODE SNIPPET:
```rust
{snippet}
```

Answer with ONLY a JSON object:
{{
  "is_vulnerable": true or false,
  "confidence": 0.0 to 1.0,
  "explanation": "brief reason",
  "severity": "low/medium/high/critical",
  "fix_suggestion": "specific fix"
}}

Rules:
- Be strict - only flag real exploitable issues
- Missing signer/owner checks on transfers/CPI are real bugs
- Arithmetic without checked_* is a real bug
- CPI without program validation is a real bug"""

    def _extract_snippet(self, source_code: str, line: int, context: int = 10) -> str:
        lines = source_code.split("\n")
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        return "\n".join(lines[start:end])

    def _parse_response(self, text: str) -> Dict:
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(text[start:end+1])
        except Exception:
            pass
        return {"is_vulnerable": True, "confidence": 0.5}
