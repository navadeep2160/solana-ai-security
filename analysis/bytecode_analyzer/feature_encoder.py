"""
Feature Encoder for Graph Neural Networks (HGT)

Converts eBPF bytecode analysis results into graph features suitable for:
- Heterogeneous Graph Transformer (HGT)
- Graph Convolutional Networks (GCN)
- Graph Attention Networks (GAT)

Node types:
- Program
- Function
- BasicBlock
- Instruction
- Syscall
- AccountAccess
- VulnerabilityPattern

Edge types:
- contains (Program -> Function -> BasicBlock -> Instruction)
- calls (Function -> Function)
- jumps (BasicBlock -> BasicBlock)
- uses (Instruction -> Syscall)
- accesses (Instruction -> AccountAccess)
- has_vulnerability (BasicBlock -> VulnerabilityPattern)
"""

import numpy as np
from typing import List, Dict, Tuple, Set, Optional
from dataclasses import dataclass
import networkx as nx

from .disassembler import eBPFInstruction, eBPFDisassembler
from .cfg_recovery import CFGRecoverer, FunctionCFG, BasicBlock
from .semantic_extractor import SemanticExtractor, VulnerabilityPattern


@dataclass
class GraphFeatures:
    """Encoded graph features for GNN input."""
    node_types: List[str]
    node_features: np.ndarray
    edge_index: np.ndarray
    edge_types: List[str]
    node_labels: Dict[int, str]
    vulnerability_nodes: List[int]

    def to_pytorch_geometric(self):
        """Convert to PyTorch Geometric Data format."""
        try:
            import torch
            from torch_geometric.data import HeteroData
            
            data = HeteroData()
            
            # Group nodes by type
            type_to_nodes = {}
            for i, nt in enumerate(self.node_types):
                if nt not in type_to_nodes:
                    type_to_nodes[nt] = []
                type_to_nodes[nt].append(i)
            
            # Add node features per type
            for nt, nodes in type_to_nodes.items():
                data[nt].x = torch.tensor(self.node_features[nodes], dtype=torch.float)
                data[nt].node_ids = nodes
            
            # Add edges per type
            edge_type_to_edges = {}
            for i in range(len(self.edge_index[0])):
                src, dst = self.edge_index[0][i], self.edge_index[1][i]
                et = self.edge_types[i]
                if et not in edge_type_to_edges:
                    edge_type_to_edges[et] = {"src_type": self.node_types[src], 
                                               "dst_type": self.node_types[dst],
                                               "edges": []}
                edge_type_to_edges[et]["edges"].append([src, dst])
            
            for et, info in edge_type_to_edges.items():
                src_type = info["src_type"]
                dst_type = info["dst_type"]
                edges = torch.tensor(info["edges"], dtype=torch.long).t()
                data[src_type, et, dst_type].edge_index = edges
            
            return data
            
        except ImportError:
            print("[FeatureEncoder] PyTorch Geometric not installed")
            return None


class FeatureEncoder:
    """
    Encodes eBPF bytecode into graph features for GNN models.
    
    Feature dimensions per node type:
    - Program: [num_functions, total_instructions, has_cpi, has_panic]
    - Function: [num_blocks, num_instructions, entry_block_id, has_cpi, has_panic, cyclomatic_complexity]
    - BasicBlock: [num_instructions, has_cpi, has_syscall, has_panic, has_arithmetic, is_entry, is_exit]
    - Instruction: [opcode_class, is_load, is_store, is_call, is_jump, is_syscall, imm_value]
    - Syscall: [syscall_type_onehot]  # One-hot encoding of syscall type
    - VulnerabilityPattern: [pattern_type_onehot, confidence]
    """
    
    SYSCALL_TYPES = [
        "invoke", "log", "panic", "crypto", "create_address",
        "get_sysvar", "memcpy", "alloc", "other"
    ]
    
    VULN_TYPES = [
        "missing_signer_check_before_cpi",
        "missing_owner_check_before_cpi",
        "unchecked_arithmetic",
        "pda_without_seed_validation",
        "potential_missing_owner_check",
        "signer_check_present",
        "owner_check_present",
        "account_initialization",
        "account_closure",
        "pda_with_seed_validation",
    ]
    
    FEATURE_DIM = 32  # Fixed feature dimension for all node types
    
    def __init__(self, disassembler: eBPFDisassembler, cfg: CFGRecoverer,
                 semantic: SemanticExtractor):
        self.disasm = disassembler
        self.cfg = cfg
        self.semantic = semantic
        self.graph = nx.DiGraph()
        self.node_id_map = {}  # (type, original_id) -> int
        self.features = GraphFeatures([], None, None, [], {}, [])
    
    def encode(self) -> GraphFeatures:
        """
        Main encoding entry point.
        Builds heterogeneous graph with all node and edge types.
        """
        self.graph = nx.DiGraph()
        self.node_id_map = {}
        node_idx = 0
        
        # 1. Add Program node
        prog_id = self._add_node("Program", "program", {
            "num_functions": len(self.cfg.functions),
            "total_instructions": len(self.disasm.instructions),
            "has_cpi": any(b.has_cpi for f in self.cfg.functions.values() for b in f.blocks.values()),
            "has_panic": any(b.has_panic for f in self.cfg.functions.values() for b in f.blocks.values()),
        })
        
        # 2. Add Function nodes
        for func_name, func_cfg in self.cfg.functions.items():
            func_id = self._add_node("Function", func_name, {
                "num_blocks": len(func_cfg.blocks),
                "num_instructions": sum(len(b.instructions) for b in func_cfg.blocks.values()),
                "has_cpi": any(b.has_cpi for b in func_cfg.blocks.values()),
                "has_panic": any(b.has_panic for b in func_cfg.blocks.values()),
                "cyclomatic_complexity": self._compute_complexity(func_cfg),
            })
            self.graph.add_edge(prog_id, func_id, type="contains")
            
            # 3. Add BasicBlock nodes
            for bid, block in func_cfg.blocks.items():
                block_id = self._add_node("BasicBlock", f"{func_name}:{bid}", {
                    "num_instructions": len(block.instructions),
                    "has_cpi": block.has_cpi,
                    "has_syscall": block.has_syscall,
                    "has_panic": block.has_panic,
                    "has_arithmetic": block.has_arithmetic,
                    "is_entry": block.is_entry,
                    "is_exit": block.is_exit,
                })
                self.graph.add_edge(func_id, block_id, type="contains")
                
                # 4. Add Instruction nodes
                for instr in block.instructions:
                    instr_id = self._add_node("Instruction", f"{func_name}:{bid}:{instr.offset}", {
                        "opcode": instr.opcode,
                        "is_load": instr.is_load,
                        "is_store": instr.is_store,
                        "is_call": instr.is_call,
                        "is_jump": instr.is_jump,
                        "is_syscall": instr.is_syscall,
                        "imm": instr.imm,
                    })
                    self.graph.add_edge(block_id, instr_id, type="contains")
                    
                    # 5. Add Syscall nodes
                    if instr.is_syscall:
                        syscall_type = self._classify_syscall(instr.operands)
                        syscall_id = self._add_node("Syscall", f"syscall:{instr.operands}", {
                            "syscall_type": syscall_type,
                        })
                        self.graph.add_edge(instr_id, syscall_id, type="invokes")
                
                # 6. Add VulnerabilityPattern nodes
                vulns = [p for p in self.semantic.patterns 
                         if p.function == func_name and p.block_id == bid]
                for vuln in vulns:
                    vuln_id = self._add_node("VulnerabilityPattern", 
                                             f"vuln:{func_name}:{bid}:{vuln.pattern_type}", {
                        "pattern_type": vuln.pattern_type,
                        "confidence": vuln.confidence,
                        "is_critical": vuln.pattern_type in [
                            "missing_signer_check_before_cpi",
                            "missing_owner_check_before_cpi",
                            "unchecked_arithmetic",
                        ],
                    })
                    self.graph.add_edge(block_id, vuln_id, type="has_vulnerability")
                    self.features.vulnerability_nodes.append(vuln_id)
        
        # 7. Add control flow edges (BasicBlock -> BasicBlock)
        for func_name, func_cfg in self.cfg.functions.items():
            for from_id, to_id, edge_type in func_cfg.edges:
                src = self._get_node_idx("BasicBlock", f"{func_name}:{from_id}")
                dst = self._get_node_idx("BasicBlock", f"{func_name}:{to_id}")
                if src is not None and dst is not None:
                    self.graph.add_edge(src, dst, type=edge_type)
        
        # 8. Add call edges (Function -> Function)
        call_graph = self.cfg.get_call_graph()
        for src_func, dst_func in call_graph.edges():
            src = self._get_node_idx("Function", src_func)
            dst = self._get_node_idx("Function", dst_func)
            if src is not None and dst is not None:
                self.graph.add_edge(src, dst, type="calls")
        
        # 9. Build feature matrices
        self._build_feature_matrix()
        
        return self.features
    
    def _add_node(self, node_type: str, original_id: str, attrs: Dict) -> int:
        """Add a node to the graph and return its index."""
        key = (node_type, original_id)
        if key in self.node_id_map:
            return self.node_id_map[key]
        
        idx = len(self.node_id_map)
        self.node_id_map[key] = idx
        self.graph.add_node(idx, type=node_type, original_id=original_id, **attrs)
        self.features.node_types.append(node_type)
        self.features.node_labels[idx] = f"{node_type}:{original_id}"
        return idx
    
    def _get_node_idx(self, node_type: str, original_id: str) -> Optional[int]:
        """Get node index by type and original ID."""
        return self.node_id_map.get((node_type, original_id))
    
    def _build_feature_matrix(self):
        """Build fixed-size feature matrix for all nodes."""
        num_nodes = len(self.features.node_types)
        features = np.zeros((num_nodes, self.FEATURE_DIM))
        
        for idx in range(num_nodes):
            node_type = self.features.node_types[idx]
            attrs = self.graph.nodes[idx]
            
            if node_type == "Program":
                features[idx, 0] = attrs.get("num_functions", 0) / 50.0
                features[idx, 1] = attrs.get("total_instructions", 0) / 10000.0
                features[idx, 2] = float(attrs.get("has_cpi", False))
                features[idx, 3] = float(attrs.get("has_panic", False))
            
            elif node_type == "Function":
                features[idx, 0] = attrs.get("num_blocks", 0) / 20.0
                features[idx, 1] = attrs.get("num_instructions", 0) / 500.0
                features[idx, 2] = float(attrs.get("has_cpi", False))
                features[idx, 3] = float(attrs.get("has_panic", False))
                features[idx, 4] = attrs.get("cyclomatic_complexity", 0) / 10.0
            
            elif node_type == "BasicBlock":
                features[idx, 0] = attrs.get("num_instructions", 0) / 50.0
                features[idx, 1] = float(attrs.get("has_cpi", False))
                features[idx, 2] = float(attrs.get("has_syscall", False))
                features[idx, 3] = float(attrs.get("has_panic", False))
                features[idx, 4] = float(attrs.get("has_arithmetic", False))
                features[idx, 5] = float(attrs.get("is_entry", False))
                features[idx, 6] = float(attrs.get("is_exit", False))
            
            elif node_type == "Instruction":
                features[idx, 0] = attrs.get("opcode", 0) / 255.0
                features[idx, 1] = float(attrs.get("is_load", False))
                features[idx, 2] = float(attrs.get("is_store", False))
                features[idx, 3] = float(attrs.get("is_call", False))
                features[idx, 4] = float(attrs.get("is_jump", False))
                features[idx, 5] = float(attrs.get("is_syscall", False))
                features[idx, 6] = (attrs.get("imm", 0) & 0xFFFFFFFF) / 0xFFFFFFFF
            
            elif node_type == "Syscall":
                syscall_type = attrs.get("syscall_type", "other")
                type_idx = self.SYSCALL_TYPES.index(syscall_type) if syscall_type in self.SYSCALL_TYPES else len(self.SYSCALL_TYPES) - 1
                features[idx, type_idx] = 1.0
            
            elif node_type == "VulnerabilityPattern":
                pattern_type = attrs.get("pattern_type", "")
                type_idx = self.VULN_TYPES.index(pattern_type) if pattern_type in self.VULN_TYPES else len(self.VULN_TYPES) - 1
                features[idx, type_idx] = 1.0
                features[idx, len(self.VULN_TYPES)] = attrs.get("confidence", 0)
                features[idx, len(self.VULN_TYPES) + 1] = float(attrs.get("is_critical", False))
        
        self.features.node_features = features
        
        # Build edge index
        edges = list(self.graph.edges())
        if edges:
            self.features.edge_index = np.array(edges, dtype=np.int64).T
            self.features.edge_types = [self.graph[u][v].get("type", "unknown") for u, v in edges]
        else:
            self.features.edge_index = np.zeros((2, 0), dtype=np.int64)
            self.features.edge_types = []
    
    def _compute_complexity(self, func_cfg: FunctionCFG) -> int:
        """Compute cyclomatic complexity: E - N + 2P."""
        num_edges = len(func_cfg.edges)
        num_nodes = len(func_cfg.blocks)
        num_components = 1  # Assuming connected
        return max(1, num_edges - num_nodes + 2 * num_components)
    
    def _classify_syscall(self, syscall_name: str) -> str:
        """Classify syscall into category."""
        name = syscall_name.lower()
        if "invoke" in name:
            return "invoke"
        elif "log" in name:
            return "log"
        elif "panic" in name or "abort" in name:
            return "panic"
        elif any(x in name for x in ["sha256", "keccak", "blake3"]):
            return "crypto"
        elif "create_program_address" in name or "find_program_address" in name:
            return "create_address"
        elif "get_" in name and "sysvar" in name:
            return "get_sysvar"
        elif "mem" in name:
            return "memcpy"
        elif "alloc" in name:
            return "alloc"
        else:
            return "other"
    
    def export_to_dot(self, output_path: str):
        """Export CFG to Graphviz DOT format."""
        dot_lines = ["digraph BytecodeCFG {"]
        dot_lines.append("  rankdir=TB;")
        dot_lines.append("  node [shape=box, style=rounded];")
        
        # Color scheme
        colors = {
            "Program": "lightblue",
            "Function": "lightgreen",
            "BasicBlock": "lightyellow",
            "Instruction": "white",
            "Syscall": "lightcoral",
            "VulnerabilityPattern": "salmon",
        }
        
        for idx in self.graph.nodes():
            node_type = self.features.node_types[idx]
            label = self.features.node_labels[idx].split(":")[-1][:20]
            color = colors.get(node_type, "white")
            dot_lines.append(f'  n{idx} [label="{node_type}\\n{label}", fillcolor={color}, style=filled];')
        
        for u, v in self.graph.edges():
            edge_type = self.graph[u][v].get("type", "unknown")
            dot_lines.append(f'  n{u} -> n{v} [label="{edge_type}"];')
        
        dot_lines.append("}")
        
        with open(output_path, 'w') as f:
            f.write("\n".join(dot_lines))
        
        print(f"[FeatureEncoder] Exported DOT to {output_path}")
    
    def export_to_json(self, output_path: str):
        """Export graph features to JSON."""
        import json
        
        data = {
            "node_types": self.features.node_types,
            "node_features": self.features.node_features.tolist(),
            "edge_index": self.features.edge_index.tolist() if self.features.edge_index is not None else [],
            "edge_types": self.features.edge_types,
            "node_labels": {str(k): v for k, v in self.features.node_labels.items()},
            "vulnerability_nodes": self.features.vulnerability_nodes,
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[FeatureEncoder] Exported JSON to {output_path}")
    
    def get_node_statistics(self) -> Dict[str, int]:
        """Get statistics about encoded graph."""
        stats = {}
        for nt in self.features.node_types:
            stats[nt] = stats.get(nt, 0) + 1
        return stats