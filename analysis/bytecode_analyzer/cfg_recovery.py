"""
Control Flow Graph Recovery - Production Version
"""
from typing import List, Dict, Tuple, Set, Optional
from dataclasses import dataclass, field
import networkx as nx

from .disassembler import eBPFInstruction, eBPFDisassembler


@dataclass
class BasicBlock:
    """Represents a basic block in the CFG."""
    id: str
    start_offset: int
    end_offset: int = 0
    instructions: List[eBPFInstruction] = field(default_factory=list)
    
    has_cpi: bool = False
    has_syscall: bool = False
    has_panic: bool = False
    has_arithmetic: bool = False
    is_entry: bool = False
    is_exit: bool = False
    successors: List[str] = field(default_factory=list)
    predecessors: List[str] = field(default_factory=list)
    
    def add_instruction(self, instr: eBPFInstruction):
        self.instructions.append(instr)
        self.end_offset = instr.offset
        
        if instr.is_syscall and "invoke" in instr.operands:
            self.has_cpi = True
        if instr.is_syscall:
            self.has_syscall = True
        if instr.is_syscall and any(x in instr.operands for x in ["panic", "abort"]):
            self.has_panic = True
        if instr.is_arithmetic:
            self.has_arithmetic = True
        if instr.is_return:
            self.is_exit = True
    
    def __len__(self):
        return len(self.instructions)


@dataclass
class FunctionCFG:
    """CFG for a single function."""
    name: str
    entry_offset: int
    blocks: Dict[str, BasicBlock] = field(default_factory=dict)
    edges: List[Tuple[str, str, str]] = field(default_factory=list)
    
    def get_block(self, block_id: str) -> Optional[BasicBlock]:
        return self.blocks.get(block_id)


class CFGRecoverer:
    """Recovers CFG from eBPF bytecode."""
    
    def __init__(self, disassembler: eBPFDisassembler):
        self.disasm = disassembler
        self.instructions: List[eBPFInstruction] = []
        self.functions: Dict[str, FunctionCFG] = {}
        self.call_graph = nx.DiGraph()
        
    def recover(self) -> Dict[str, FunctionCFG]:
        """Main CFG recovery entry point."""
        self.instructions = self.disasm.instructions
        
        if not self.instructions:
            print("[CFG] Warning: No instructions. Creating minimal CFG.")
            func = FunctionCFG(name="entrypoint", entry_offset=0)
            block = BasicBlock(id="lbb_0", start_offset=0, end_offset=0, is_entry=True)
            func.blocks["lbb_0"] = block
            self.functions["entrypoint"] = func
            return self.functions
        
        # Find block leaders
        leaders = self._find_block_leaders()
        print(f"[CFG] Found {len(leaders)} block leaders")
        
        # Build basic blocks
        blocks = self._build_basic_blocks(leaders)
        print(f"[CFG] Built {len(blocks)} basic blocks")
        
        if not blocks:
            print("[CFG] Warning: No basic blocks. Using fallback.")
            return self._fallback_cfg()
        
        # Build function CFGs
        self._build_function_cfgs(blocks)
        
        # Build edges
        self._build_cfg_edges()
        
        # Build call graph
        self._build_call_graph()
        
        return self.functions
    
    def _find_block_leaders(self) -> Set[int]:
        """Find all basic block leaders."""
        leaders = {0}  # First instruction is always a leader
        
        for i, instr in enumerate(self.instructions):
            # After call: next instruction is leader
            if instr.is_call:
                if i + 1 < len(self.instructions):
                    leaders.add(int(self.instructions[i + 1].offset))
            
            # FIXED: After syscall: next instruction is leader
            if instr.is_syscall:
                if i + 1 < len(self.instructions):
                    leaders.add(int(self.instructions[i + 1].offset))
            
            # Jump targets are leaders
            if instr.is_jump and instr.target_offset is not None:
                leaders.add(int(instr.target_offset))
        
        return leaders
    
    def _build_basic_blocks(self, leaders: Set[int]) -> Dict[int, BasicBlock]:
        """Build basic blocks from instructions and leaders."""
        blocks = {}
        current_block = None
        
        for instr in self.instructions:
            # CRITICAL FIX: Convert to int to avoid type mismatch with set membership
            instr_offset = int(instr.offset)
            
            if instr_offset in leaders:
                # Start new block
                if current_block is not None:
                    blocks[int(current_block.start_offset)] = current_block
                
                block_id = f"lbb_{instr.offset:04x}"
                current_block = BasicBlock(
                    id=block_id,
                    start_offset=instr.offset,
                    end_offset=instr.offset
                )
            
            if current_block is not None:
                current_block.add_instruction(instr)
        
        # Save last block
        if current_block is not None:
            blocks[int(current_block.start_offset)] = current_block
        
        return blocks
    
    def _fallback_cfg(self) -> Dict[str, FunctionCFG]:
        """Create single-block fallback CFG."""
        func = FunctionCFG(name="entrypoint", entry_offset=0)
        last_offset = self.instructions[-1].offset if self.instructions else 0
        block = BasicBlock(id="lbb_0", start_offset=0, end_offset=last_offset, is_entry=True)
        for instr in self.instructions:
            block.add_instruction(instr)
        block.is_exit = True
        func.blocks["lbb_0"] = block
        self.functions["entrypoint"] = func
        return self.functions
    
    def _build_function_cfgs(self, blocks: Dict[int, BasicBlock]):
        """Group blocks into functions."""
        symbols = self.disasm.get_function_boundaries()
        
        if symbols:
            for name, (start, size) in symbols.items():
                func = FunctionCFG(name=name, entry_offset=start)
                for offset, block in blocks.items():
                    if start <= offset < start + size:
                        func.blocks[block.id] = block
                if func.blocks:
                    self.functions[name] = func
        
        if not self.functions:
            # Single function with all blocks
            func = FunctionCFG(name="entrypoint", entry_offset=0)
            for offset, block in sorted(blocks.items()):
                func.blocks[block.id] = block
            if "lbb_0" in func.blocks:
                func.blocks["lbb_0"].is_entry = True
            self.functions["entrypoint"] = func
    
    def _build_cfg_edges(self):
        """Build control flow edges."""
        for func_name, func in self.functions.items():
            offset_to_block = {}
            for block_id, block in func.blocks.items():
                for instr in block.instructions:
                    offset_to_block[instr.offset] = block_id
            
            for block_id, block in func.blocks.items():
                if not block.instructions:
                    continue
                
                last_instr = block.instructions[-1]
                
                # Unconditional jump
                if last_instr.mnemonic == "ja" and last_instr.target_offset is not None:
                    target_id = offset_to_block.get(last_instr.target_offset)
                    if target_id:
                        block.successors.append(target_id)
                        func.edges.append((block_id, target_id, "jump"))
                
                # Conditional jump
                elif last_instr.is_jump and last_instr.target_offset is not None:
                    target_id = offset_to_block.get(last_instr.target_offset)
                    if target_id:
                        block.successors.append(target_id)
                        func.edges.append((block_id, target_id, "branch_taken"))
                    
                    # Fall-through
                    fallthrough = self._get_fallthrough(block_id, func)
                    if fallthrough:
                        block.successors.append(fallthrough)
                        func.edges.append((block_id, fallthrough, "branch_not_taken"))
                
                # Call (fall-through)
                elif last_instr.is_call:
                    fallthrough = self._get_fallthrough(block_id, func)
                    if fallthrough:
                        block.successors.append(fallthrough)
                        func.edges.append((block_id, fallthrough, "fallthrough"))
                
                # Return
                elif last_instr.is_return:
                    block.is_exit = True
                
                # Regular fall-through
                else:
                    fallthrough = self._get_fallthrough(block_id, func)
                    if fallthrough:
                        block.successors.append(fallthrough)
                        func.edges.append((block_id, fallthrough, "fallthrough"))
    
    def _get_fallthrough(self, current_block_id: str, func: FunctionCFG) -> Optional[str]:
        """Get next block in sequential order."""
        current = func.blocks.get(current_block_id)
        if not current:
            return None
        
        next_block = None
        next_offset = float('inf')
        
        for block_id, block in func.blocks.items():
            if block.start_offset > current.end_offset and block.start_offset < next_offset:
                next_offset = block.start_offset
                next_block = block_id
        
        return next_block
    
    def _build_call_graph(self):
        """Build inter-procedural call graph."""
        for func_name, func in self.functions.items():
            self.call_graph.add_node(func_name)
            for block in func.blocks.values():
                for instr in block.instructions:
                    if instr.is_call and not instr.is_syscall:
                        target = instr.operands
                        self.call_graph.add_edge(func_name, target)
    
    def get_call_graph(self) -> nx.DiGraph:
        return self.call_graph
    
    def get_dominator_tree(self, func_name: str) -> Optional[Dict]:
        if func_name not in self.functions:
            return None
        
        func = self.functions[func_name]
        if not func.blocks:
            return None
        
        G = nx.DiGraph()
        for block_id in func.blocks:
            G.add_node(block_id)
        for from_id, to_id, _ in func.edges:
            G.add_edge(from_id, to_id)
        
        entry = None
        for block_id, block in func.blocks.items():
            if block.is_entry:
                entry = block_id
                break
        
        if not entry:
            entry = min(func.blocks.keys())
        
        try:
            return nx.immediate_dominators(G, entry)
        except Exception:
            return None
    
    def find_loops(self, func_name: str) -> List[List[str]]:
        if func_name not in self.functions:
            return []
        
        func = self.functions[func_name]
        G = nx.DiGraph()
        for block_id in func.blocks:
            G.add_node(block_id)
        for from_id, to_id, _ in func.edges:
            G.add_edge(from_id, to_id)
        
        try:
            return list(nx.simple_cycles(G))
        except Exception:
            return []