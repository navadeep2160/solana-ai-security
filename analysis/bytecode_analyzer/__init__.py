"""
Solana eBPF Bytecode Analyzer
Production-ready module for reverse-engineering deployed Solana programs.
"""

from .bytecode_scanner import BytecodeScanner, BytecodeScanResult
from .batch_scanner import BatchBytecodeScanner, BatchScanResult, SolanaProgramDownloader
from .so_fetcher import SolanaProgramFetcher
from .disassembler import eBPFDisassembler, eBPFInstruction
from .cfg_recovery import CFGRecoverer, FunctionCFG, BasicBlock
from .semantic_extractor import SemanticExtractor, VulnerabilityPattern
from .feature_encoder import FeatureEncoder, GraphFeatures

__all__ = [
    "BytecodeScanner",
    "BytecodeScanResult",
    "BatchBytecodeScanner",
    "BatchScanResult",
    "SolanaProgramDownloader",
    "SolanaProgramFetcher",
    "eBPFDisassembler",
    "eBPFInstruction",
    "CFGRecoverer",
    "FunctionCFG",
    "BasicBlock",
    "SemanticExtractor",
    "VulnerabilityPattern",
    "FeatureEncoder",
    "GraphFeatures",
]