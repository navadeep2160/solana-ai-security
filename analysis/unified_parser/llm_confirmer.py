"""
LLM Confirmer
=============
Uses LLM to confirm and enrich vulnerability findings.
Reduces false positives by having the LLM reason about exploitability.
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
        """Initialize LLM (cached)."""
        if load_model:
            try:
                self.llm = load_model(self.model_name)
            except Exception as e:
                print(f"[LLM-Confirmer] Could not load LLM: {e}")
        else:
            print("[LLM-Confirmer] No LLM client available")
    
    def confirm_finding(self, finding: Dict[str, Any], source_code: str) -> Dict[str, Any]:
        """Confirm a finding with LLM."""
        if not self.llm:
            finding["llm_confirmed"] = False
            finding["llm_confidence"] = 0.0
            return finding
        
        func_name = finding.get("function", "unknown")
        vuln_type = finding.get("vuln_type", "unknown")
        description = finding.get("description", "")
        evidence = finding.get("evidence", "")
        
        line = finding.get("line", 0)
        code_snippet = self._extract_snippet(source_code, line)
        
        prompt = f"""You are a Solana smart contract security expert. Analyze this potential vulnerability:

VULNERABILITY: {vuln_type}
DESCRIPTION: {description}
EVIDENCE: {evidence}

CODE SNIPPET:
```rust
{code_snippet}
Answer with ONLY a JSON object:
{{
"is_vulnerable": true/false,
"confidence": 0.0-1.0,
"explanation": "brief reason",
"severity": "low/medium/high/critical",
"fix_suggestion": "specific fix"
}}
"""

    try:
        response = self.llm.invoke(prompt)
        content = response.content if hasattr(response, 'content') else str(response)
        
        json_match = self._extract_json(content)
        if json_match:
            result = json.loads(json_match)
            finding["llm_confirmed"] = result.get("is_vulnerable", False)
            finding["llm_confidence"] = result.get("confidence", 0.0)
            finding["llm_explanation"] = result.get("explanation", "")
            finding["llm_severity"] = result.get("severity", finding.get("severity", "medium"))
            finding["llm_fix"] = result.get("fix_suggestion", finding.get("fix", ""))
            
            kb_conf = finding.get("confidence", 0.5)
            llm_conf = finding["llm_confidence"]
            finding["confidence"] = (kb_conf * 0.4) + (llm_conf * 0.6)
        else:
            finding["llm_confirmed"] = False
            finding["llm_confidence"] = 0.0
            
    except Exception as e:
        print(f"[LLM-Confirmer] Confirmation failed: {e}")
        finding["llm_confirmed"] = False
        finding["llm_confidence"] = 0.0
    
    return finding

def confirm_batch(self, findings: List[Dict[str, Any]], source_code: str) -> List[Dict[str, Any]]:
    """Confirm multiple findings efficiently."""
    confirmed = []
    for finding in findings:
        confirmed.append(self.confirm_finding(finding, source_code))
    return confirmed

def _extract_snippet(self, source_code: str, line: int, context: int = 10) -> str:
    """Extract code snippet around a line."""
    lines = source_code.split('\n')
    start = max(0, line - context - 1)
    end = min(len(lines), line + context)
    return '\n'.join(lines[start:end])

def _extract_json(self, text: str) -> Optional[str]:
    """Extract JSON object from text."""
    try:
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1 and end > start:
            return text[start:end+1]
    except Exception:
        pass
    return None
