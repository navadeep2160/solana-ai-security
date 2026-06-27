# analysis/bytecode_analyzer/agents/pseudo_source_generator.py

import json
from pathlib import Path
from typing import List, Dict, Any



def _sanitize_source(source: str) -> str:
    """Remove control characters and invalid Unicode from generated Rust source."""
    # Remove ASCII control chars (0-31 except tab, newline, carriage return)
    sanitized = "".join(
        ch for ch in source 
        if ch == '\n' or ch == '\r' or ch == '\t' or (ord(ch) >= 32 and ord(ch) != 127)
    )
    # Remove other problematic Unicode control/format chars
    sanitized = "".join(
        ch for ch in sanitized 
        if not (0x80 <= ord(ch) <= 0x9F or 0x2000 <= ord(ch) <= 0x206F or ord(ch) in (0x2401,))
    )
    return sanitized

class PseudoSourceGenerator:
    """Generate pseudo-Rust source from bytecode analysis patterns for LangGraph pipeline."""

    def __init__(self, patterns: List[Dict[str, Any]], program_id: str, output_dir: str = ""):
        self.patterns = patterns
        self.program_id = program_id
        self.output_dir = output_dir  # Store it!

    def generate(self, outdir: str) -> str:
        """Generate pseudo-source and save to file."""
        outdir = Path(outdir)
        outdir.mkdir(parents=True, exist_ok=True)

        source = self._build_source()
        outpath = outdir / "pseudo_source.rs"
        outpath.write_text(_sanitize_source(source), encoding="utf-8")
        return str(outpath)

    def _build_source(self) -> str:
        """Build the complete pseudo-source file."""
        lines = []

        # Header
        lines.append(f"// AUTO-GENERATED from bytecode analysis")
        lines.append(f"// Program: {self.program_id}")
        lines.append(f"// Patterns detected: {len(self.patterns)}")
        lines.append(f"// This is pseudo-source for patch generation only")
        lines.append("")

        # Imports - ONLY anchor_lang, NO anchor_spl
        lines.append(self._imports())
        lines.append("")

        # Error codes
        lines.append(self._error_codes())
        lines.append("")

        # Account structs
        lines.append(self._account_structs())
        lines.append("")

        # Program module with functions
        lines.append(self._program_module())
        lines.append("")

        return "\n".join(lines)

    def _imports(self) -> str:
        """Generate imports. ONLY anchor_lang - no external dependencies."""
        return """use anchor_lang::prelude::*;"""

    def _error_codes(self) -> str:
        """Generate error code enum based on patterns found."""
        errors = set()

        for p in self.patterns:
            name = p.get("name", "")
            if "arithmetic" in name or "overflow" in name:
                errors.add("ArithmeticOverflow")
            if "signer" in name or "owner" in name:
                errors.add("Unauthorized")
            if "cpi" in name:
                errors.add("InvalidProgram")
            if "pda" in name:
                errors.add("InvalidPDA")
            if "reentrancy" in name:
                errors.add("ReentrancyDetected")

        # Default errors if none detected
        if not errors:
            errors = {"ArithmeticOverflow", "Unauthorized"}

        lines = ["#[error_code]"]
        lines.append("pub enum ErrorCode {")
        for err in sorted(errors):
            lines.append(f'    #[msg("{err.replace("_", " ")}")]')
            lines.append(f"    {err},")
        lines.append("}")
        return "\n".join(lines)

    def _account_structs(self) -> str:
        """Generate minimal account structs."""
        # Check what account types we need based on patterns
        has_token = any("token" in p.get("name", "") for p in self.patterns)
        has_cpi = any("cpi" in p.get("name", "") for p in self.patterns)

        lines = []
        lines.append("#[derive(Accounts)]")
        lines.append("pub struct ProcessInstruction<'info> {")
        lines.append("    pub authority: Signer<'info>,")

        if has_token or has_cpi:
            lines.append("    /// CHECK: pseudo-source account")
            lines.append("    pub token_account: AccountInfo<'info>,")
            lines.append("    /// CHECK: pseudo-source program")
            lines.append("    pub token_program: AccountInfo<'info>,")

        lines.append("    pub system_program: Program<'info, System>,")
        lines.append("}")
        return "\n".join(lines)

    def _program_module(self) -> str:
        """Generate the program module with functions."""
        # Group patterns by function
        func_patterns: Dict[str, List[Dict]] = {}
        for p in self.patterns:
            func_name = p.get("function", "process_instruction")
            func_patterns.setdefault(func_name, []).append(p)

        lines = []
        lines.append(f'declare_id!("{self.program_id}");')
        lines.append("")
        lines.append("#[program]")
        lines.append(f"pub mod analyzed_program {{")
        lines.append("    use super::*;")
        lines.append("")

        # Generate a function for each unique function name
        for func_name, patterns in func_patterns.items():
            lines.append(self._generate_function(func_name, patterns))
            lines.append("")

        lines.append("}")
        return "\n".join(lines)

    def _generate_function(self, func_name: str, patterns: List[Dict]) -> str:
        """Generate a single function with vulnerability markers."""
        lines = []

        # Function signature - NO access_control macro
        lines.append(f"    pub fn {func_name}(")
        lines.append(f"        ctx: Context<ProcessInstruction>,")
        lines.append(f"        amount: u64,")
        lines.append(f"    ) -> Result<()> {{")

        # Body with vulnerability markers
        lines.append(f"        let account = &ctx.accounts.authority;")

        for pattern in patterns:
            name = pattern.get("name", "unknown")
            desc = pattern.get("description", "")
            loc = pattern.get("location", "unknown")

            lines.append(f"")
            lines.append(f"        // VULNERABLE: {name}")
            lines.append(f"        // Location: {loc}")
            if desc:
                lines.append(f"        // Description: {desc}")

            # Generate appropriate vulnerable code marker based on pattern type
            if "arithmetic" in name or "overflow" in name:
                lines.append(f"        // VULNERABLE: Unchecked arithmetic")
                lines.append(f"        // let result = value + amount; // Should use checked_add")
                lines.append(f"        let result = value.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;")

            elif "signer" in name:
                lines.append(f"        // VULNERABLE: Missing signer check")
                lines.append(f"        // require!(ctx.accounts.authority.is_signer);")

            elif "owner" in name:
                lines.append(f"        // VULNERABLE: Missing owner validation")
                lines.append(f"        // require!(account.owner == expected_program);")

            elif "cpi" in name or "arbitrary" in name:
                lines.append(f"        // VULNERABLE: CPI to arbitrary program")
                lines.append(f"        // No program ID whitelist check")

            elif "pda" in name:
                lines.append(f"        // VULNERABLE: PDA without seed validation")
                lines.append(f"        // Should verify seeds and bump")

            elif "reentrancy" in name:
                lines.append(f"        // VULNERABLE: State update after external call")
                lines.append(f"        // State should be updated BEFORE CPI")

            else:
                lines.append(f"        // VULNERABLE: {name}")
                lines.append(f"        msg!(\"Processing with potential vulnerability\");")

        # If no patterns, add generic body
        if not patterns:
            lines.append(f"        msg!(\"Processing instruction...\");")

        lines.append(f"        Ok(())")
        lines.append(f"    }}")

        return "\n".join(lines)


def generate_pseudo_source(patterns: List[Dict[str, Any]], program_id: str, outdir: str) -> str:
    """Convenience function."""
    generator = PseudoSourceGenerator(patterns, program_id)
    return generator.generate(outdir)
# Add this at the END of pseudo_source_generator.py
def bridge_bytecode_to_pipeline(program_id: str, patterns: list, output_dir: str) -> dict:
    """Bridge entrypoint for bytecode_scanner._bridge_to_langgraph."""
    generator = PseudoSourceGenerator(patterns, program_id)
    pseudo_source = generator.generate(output_dir)
    return {"pseudo_source": pseudo_source, "output_dir": output_dir}
