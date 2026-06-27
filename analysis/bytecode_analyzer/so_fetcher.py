"""
Solana Program Fetcher
Downloads deployed program binaries from mainnet/devnet/testnet.

Uses solana-cli (free) or direct RPC calls.
"""

import subprocess
import json
import base64
import struct
from pathlib import Path
from typing import Optional, Tuple
import urllib.request


class SolanaProgramFetcher:
    """
    Fetches Solana program bytecode from the blockchain.
    
    Supports:
    - solana program dump (via CLI)
    - Direct RPC getAccountInfo
    - Upgradeable loader resolution
    """
    
    UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
    DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
    
    def __init__(self, rpc_url: str = None, output_dir: str = "fetched_programs"):
        self.rpc_url = rpc_url or self.DEFAULT_RPC
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def fetch_via_cli(self, program_id: str, filename: str = None) -> Path:
        """
        Use solana-cli program dump (most reliable).
        
        Args:
            program_id: Base58-encoded program address
            filename: Output filename (default: {program_id}.so)
            
        Returns:
            Path to downloaded .so file
        """
        if not filename:
            filename = f"{program_id}.so"
        
        output_path = self.output_dir / filename
        
        cmd = [
            "solana", "program", "dump",
            "--url", self.rpc_url,
            program_id,
            str(output_path)
        ]
        
        print(f"[Fetcher] Downloading {program_id} via solana-cli...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"Fetch failed: {result.stderr}")
        
        if not output_path.exists() or output_path.stat().st_size == 0:
            raise RuntimeError("Downloaded file is empty")
        
        size = output_path.stat().st_size
        print(f"[Fetcher] Saved {size} bytes to {output_path}")
        return output_path
    
    def fetch_via_rpc(self, program_id: str) -> bytes:
        """
        Direct RPC fetch (no solana-cli needed).
        Handles upgradeable loader indirection.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [
                program_id,
                {"encoding": "base64"}
            ]
        }
        
        req = urllib.request.Request(
            self.rpc_url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        
        if "error" in data:
            raise RuntimeError(f"RPC error: {data['error']}")
        
        account = data["result"]["value"]
        if not account:
            raise RuntimeError("Account not found")
        
        raw = base64.b64decode(account["data"][0])
        
        # Check if upgradeable loader
        if len(raw) > 4 and raw[:4] == b"\x03\x00\x00\x00":
            # Upgradeable loader: parse programdata address
            programdata_addr = base58_encode(raw[4:36])
            print(f"[Fetcher] Upgradeable loader detected, fetching ProgramData: {programdata_addr}")
            return self._fetch_programdata(programdata_addr)
        
        return raw
    
    def _fetch_programdata(self, programdata_addr: str) -> bytes:
        """Fetch actual bytecode from ProgramData account."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [
                programdata_addr,
                {"encoding": "base64"}
            ]
        }
        
        req = urllib.request.Request(
            self.rpc_url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        
        account = data["result"]["value"]
        raw = base64.b64decode(account["data"][0])
        
        # Skip upgradeable loader header (45 bytes)
        # Header: [1 byte status][8 bytes slot][32 bytes authority][...]
        return raw[45:]
    
    def fetch(self, program_id: str, use_cli: bool = True) -> Path:
        """
        Main fetch method. Tries CLI first, falls back to RPC.
        """
        if use_cli:
            try:
                return self.fetch_via_cli(program_id)
            except Exception as e:
                print(f"[Fetcher] CLI failed ({e}), trying RPC...")
        
        raw = self.fetch_via_rpc(program_id)
        output_path = self.output_dir / f"{program_id}.so"
        output_path.write_bytes(raw)
        print(f"[Fetcher] Saved {len(raw)} bytes via RPC to {output_path}")
        return output_path


def base58_encode(data: bytes) -> str:
    """Simple base58 encoder for Solana addresses."""
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, 'big')
    if num == 0:
        return ALPHABET[0]
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(ALPHABET[rem])
    return ''.join(reversed(result))