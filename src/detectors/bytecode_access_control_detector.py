

from typing import List, Dict, Any, Set
from .base_detector import VulnerabilityDetector


SAFE_SELECTORS = {
    "0x4e487b71", "0x08c379a0", "0x40c10f19", "0x5c60da1b", "0x7050c9e0"
}

PUBLIC_PROTECTED = {
    "0x8da5cb5b", "0x06fdde03", "0x095ea7b3", "0x18160ddd", "0x23b872dd",
    "0x313ce567", "0x70a08231", "0x95d89b41", "0xa9059cbb", "0xdd62ed3e"
}


class BytecodeAccessControlDetector(VulnerabilityDetector):
    def __init__(self):
        super().__init__(
            name="BytecodeAccessControlDetector",
            description="Detects access control via CALLER checks"
        )
        self.critical_ops = {"SELFDESTRUCT"}  # Only SELFDESTRUCT is truly dangerous
        # SSTORE is too common in legitimate code (ERC-20 transfers, etc.)
        # CREATE/CREATE2 are factory patterns, not necessarily access control issues
        self.protected_entries: Set[int] = set()

    def detect(self, bytecode_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulnerabilities = []
        opcodes = bytecode_analysis.get("opcodes", [])
        if not opcodes:
            return vulnerabilities

        selectors = {s["selector"] for s in bytecode_analysis.get("function_selectors", [])}

        # Step 1: Find runtime bytecode start (skip constructor)
        runtime_start = self._find_runtime_start(opcodes)
        
        # Step 2: Mark protected functions
        self._mark_protected_functions(opcodes)

        # Step 3: Check critical ops (only in runtime code)
        for op in opcodes:
            if op["name"] not in self.critical_ops:
                continue
            pos = op["position"]

            # Skip operations before runtime starts (constructor)
            if pos < runtime_start:
                continue

            entry = self._find_function_entry_for_op(opcodes, pos)
            if entry and entry in self.protected_entries:
                continue

            # Critical operation without access control
            vulnerabilities.append(self._create_vulnerability(
                vuln_type="Unprotected Critical Operation",
                severity="High",
                description=f"Critical {op['name']} without access control",
                line_number=pos,
                code_snippet=f"Pos {pos}: {op['name']}",
                recommendation="Add onlyOwner check"
            ))

        # Step 3: Public functions
        for sel in selectors:
            if sel in SAFE_SELECTORS or sel in PUBLIC_PROTECTED:
                continue
            entry = self._find_function_entry_by_selector(opcodes, sel)
            if entry and entry >= 2000 and entry not in self.protected_entries:
                vulnerabilities.append(self._create_vulnerability(
                    vuln_type="Public Function Without Access Control",
                    severity="Medium",
                    description=f"Function {sel} lacks access control",
                    line_number=entry,
                    code_snippet=f"Selector: {sel}",
                    recommendation="Add onlyOwner check"
                ))

        return vulnerabilities

    def _find_runtime_start(self, opcodes: List[Dict]) -> int:
        """
        Find the start of runtime bytecode by looking for the first RETURN.
        Constructor typically ends with RETURN before runtime code begins.
        """
        # Look for the first RETURN opcode which marks end of constructor
        for op in opcodes:
            if op["name"] == "RETURN":
                # Runtime typically starts shortly after constructor RETURN
                # Add small offset to skip any metadata/prologue
                return op["position"] + 100
        
        # Fallback: if no RETURN found, assume runtime starts at position 2000
        # (original heuristic)
        return 2000

    def _mark_protected_functions(self, opcodes: List[Dict]):
        """Find function entries via JUMPI and check for onlyOwner in 300 opcodes"""
        for i in range(len(opcodes)):
            if opcodes[i]["name"] != "JUMPI":
                continue
            entry_pos = opcodes[i]["position"]
            if entry_pos < 1500:
                continue

            # Search first 300 opcodes for onlyOwner
            window = opcodes[i:min(i+300, len(opcodes))]
            has_caller = any(o["name"] == "CALLER" for o in window)
            has_sload = any(o["name"] == "SLOAD" for o in window)
            has_eq = any(o["name"] == "EQ" for o in window)
            has_jumpi = any(o["name"] == "JUMPI" for o in window[5:])
            has_revert = any(o["name"] == "REVERT" for o in window[10:])

            if has_caller and has_sload and has_eq and has_jumpi and has_revert:
                self.protected_entries.add(entry_pos)

    def _find_function_entry_for_op(self, opcodes: List[Dict], pos: int) -> int:
        """Find nearest JUMPI before pos"""
        for i in range(len(opcodes) - 1, -1, -1):
            if opcodes[i]["position"] > pos:
                continue
            if opcodes[i]["name"] == "JUMPI":
                entry_idx = i
                for j in range(entry_idx, min(entry_idx + 700, len(opcodes))):
                    if opcodes[j]["position"] >= pos:
                        return opcodes[entry_idx]["position"]
        return 0

    def _find_function_entry_by_selector(self, opcodes: List[Dict], selector: str) -> int:
        sel_int = int(selector, 16)
        for i in range(len(opcodes)):
            if (opcodes[i]["name"] == "PUSH4" and 
                opcodes[i]["arguments"] and 
                opcodes[i]["arguments"][0] == sel_int):
                for j in range(i+1, min(i+20, len(opcodes))):
                    if opcodes[j]["name"] == "JUMPI":
                        return opcodes[j]["position"]
        return 0