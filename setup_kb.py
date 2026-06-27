#!/usr/bin/env python3
"""
setup_kb.py — Production KB Setup for Fresh Clones
====================================================
Run once after `git clone` to build the knowledge base from raw_sources/.

Usage:
    python3 setup_kb.py              # normal run
    python3 setup_kb.py --force      # rebuild everything
"""
import os
import sys
import warnings
import json
import argparse
from pathlib import Path

os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")

try:
    import chromadb.telemetry.product.posthog as _posthog
    _posthog._direct_capture = lambda *a, **k: None
    if hasattr(_posthog, 'Posthog'):
        _posthog.Posthog.capture = lambda *a, **k: None
except Exception:
    pass

import chromadb
from chromadb.config import Settings

parser = argparse.ArgumentParser(description="Build KB from raw sources")
parser.add_argument("--force", action="store_true", help="Destroy existing KB and rebuild")
args = parser.parse_args()

print("=" * 60)
print("  Solana AI Security — Knowledge Base Setup")
print("=" * 60)

PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

def get_kb_stats(path="knowledge_base/chromadb"):
    p = PROJECT_ROOT / path
    if not p.exists():
        return {"total": 0, "exists": False, "collections": {}}
    try:
        client = chromadb.PersistentClient(
            path=str(p),
            settings=Settings(anonymized_telemetry=False)
        )
        stats = {"total": 0, "exists": True, "collections": {}}
        for c in client.list_collections():
            try:
                name = c.name if hasattr(c, 'name') else str(c)
                col = client.get_collection(name)
                stats["collections"][name] = col.count()
                stats["total"] += stats["collections"][name]
            except Exception:
                pass
        return stats
    except Exception as e:
        return {"total": 0, "exists": True, "error": str(e)}

def count_raw_sources():
    raw_dir = PROJECT_ROOT / "knowledge_base" / "raw_sources"
    if not raw_dir.exists():
        return 0
    return len([f for f in raw_dir.iterdir() if f.is_file()])

def read_vuln_nodes_json():
    """Read vuln_nodes.json, handling both old and new formats."""
    vuln_path = PROJECT_ROOT / "knowledge_base" / "vuln_nodes.json"
    if not vuln_path.exists():
        return 0, {}
    try:
        with open(vuln_path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            nodes = data.get("nodes", [])
            if isinstance(nodes, list):
                return len(nodes), count_categories(nodes)
            # Fallback: maybe total is stored differently
            total = data.get("total", 0)
            if isinstance(total, int) and total > 0:
                return total, {}
        elif isinstance(data, list):
            return len(data), count_categories(data)
        return 0, {}
    except Exception as e:
        print(f"   ⚠️  Could not read vuln_nodes.json: {e}")
        return 0, {}

def count_categories(nodes):
    cats = {}
    for node in nodes:
        cat = node.get("category", "other") if isinstance(node, dict) else "other"
        cats[cat] = cats.get(cat, 0) + 1
    return cats

# ── Force rebuild? ─────────────────────────────────────────
if args.force:
    print("\n⚠️  FORCE REBUILD requested...")
    kb_dir = PROJECT_ROOT / "knowledge_base" / "chromadb"
    if kb_dir.exists():
        import shutil
        shutil.rmtree(kb_dir)
        print("   ✅ Deleted knowledge_base/chromadb/")
    vuln_file = PROJECT_ROOT / "knowledge_base" / "vuln_nodes.json"
    if vuln_file.exists():
        vuln_file.unlink()
        print("   ✅ Deleted knowledge_base/vuln_nodes.json")

# ── Step 0: Check state ────────────────────────────────────
print("\n[0/4] Checking current state...")
before = get_kb_stats()
raw_count = count_raw_sources()

print(f"   Raw sources: {raw_count} files")
if before["total"] > 0:
    print(f"   Main KB: {before['total']} records present")
    for col, count in before.get("collections", {}).items():
        print(f"      • {col}: {count}")
else:
    print(f"   Main KB: EMPTY (will build)")

# ── Step 1: Build embeddings ───────────────────────────────
print("\n[1/4] Building ChromaDB embeddings...")

need_build = before["total"] == 0
if need_build:
    print("   Running ingest.py to chunk and embed raw sources...")
    ingest_script = PROJECT_ROOT / "knowledge_base" / "scripts" / "ingest.py"
    if ingest_script.exists():
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("ingest", ingest_script)
            ingest_mod = importlib.util.module_from_spec(spec)
            sys.modules["ingest"] = ingest_mod
            spec.loader.exec_module(ingest_mod)
            if hasattr(ingest_mod, 'main'):
                ingest_mod.main()
            print("   ✅ ingest.py completed")
        except Exception as e:
            print(f"   ⚠️  ingest.py failed: {e}")
    else:
        print(f"   ⚠️  ingest.py not found")
else:
    print("   ℹ️  KB already exists. Skipping embed build.")

# ── Step 2: Remove network collections ─────────────────────
print("\n[2/4] Cleaning network-layer data...")
try:
    client = chromadb.PersistentClient(
        path=str(PROJECT_ROOT / "knowledge_base" / "chromadb"),
        settings=Settings(anonymized_telemetry=False)
    )
    cols = [c.name if hasattr(c, 'name') else str(c) for c in client.list_collections()]
    removed = []
    for net_col in ["network_kb", "network_incidents", "validator_baselines"]:
        if net_col in cols:
            client.delete_collection(net_col)
            removed.append(net_col)
    if removed:
        print(f"   ✅ Removed: {', '.join(removed)}")
    else:
        print("   ℹ️  No network collections found")
except Exception as e:
    print(f"   ⚠️  Could not clean: {e}")

# ── Step 3: Build vulnerability nodes ────────────────────────
print("\n[3/4] Building vulnerability nodes...")

vuln_nodes_path = PROJECT_ROOT / "knowledge_base" / "vuln_nodes.json"
vuln_count, vuln_categories = read_vuln_nodes_json()

# Also check ChromaDB vuln_nodes collection as backup
db_stats = get_kb_stats()
db_vuln_count = db_stats.get("collections", {}).get("vuln_nodes", 0)

if vuln_count > 0:
    print(f"   vuln_nodes.json: {vuln_count} nodes")
elif db_vuln_count > 0:
    print(f"   vuln_nodes.json: {vuln_count} (but ChromaDB has {db_vuln_count})")
    vuln_count = db_vuln_count  # Use DB count if JSON is broken
else:
    print("   No vuln nodes found. Will build...")

# Only build if missing AND not forcing
if (vuln_count == 0 and db_vuln_count == 0) or args.force:
    vuln_script = PROJECT_ROOT / "knowledge_base" / "scripts" / "build_vuln_nodes.py"
    if vuln_script.exists():
        print("   Running build_vuln_nodes.py (may take 5-10 min)...")
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("build_vuln_nodes", vuln_script)
            bvn_mod = importlib.util.module_from_spec(spec)
            sys.modules["build_vuln_nodes"] = bvn_mod
            spec.loader.exec_module(bvn_mod)
            for func_name in ['build_all_nodes', 'main']:
                if hasattr(bvn_mod, func_name):
                    getattr(bvn_mod, func_name)()
                    print(f"   ✅ {func_name}() completed")
                    break
        except Exception as e:
            print(f"   ⚠️  build_vuln_nodes.py failed: {e}")
    else:
        print(f"   ⚠️  build_vuln_nodes.py not found")
    
    # Re-read after build
    vuln_count, vuln_categories = read_vuln_nodes_json()
else:
    print("   ℹ️  Skipping node build (already exists)")

# ── Step 4: Final Report ───────────────────────────────────
print("\n" + "=" * 60)
print("  KB SETUP REPORT")
print("=" * 60)

after = get_kb_stats()
print(f"\n📊 CHROMADB EMBEDDINGS (knowledge_base/chromadb/):")
if after["total"] > 0:
    print(f"   Total records: {after['total']}")
    for col, count in after.get("collections", {}).items():
        print(f"   • {col}: {count}")
else:
    print("   ❌ EMPTY")

print(f"\n📊 VULNERABILITY NODES:")
print(f"   vuln_nodes.json: {vuln_count} nodes")
if vuln_categories:
    for cat, count in sorted(vuln_categories.items()):
        print(f"   • {cat}: {count}")

print(f"\n📊 RAW SOURCES: {raw_count} files")

print("\n" + "=" * 60)
if after["total"] > 0 and vuln_count > 0:
    print("✅ KB SETUP COMPLETE")
    print(f"   Semantic records: {after['total']}")
    print(f"   Vulnerability nodes: {vuln_count}")
    print("   Ready for agent pipeline.")
elif after["total"] > 0:
    print("⚠️  PARTIAL SETUP")
    print(f"   Semantic records: {after['total']} ✅")
    print(f"   Vulnerability nodes: {vuln_count} ❌")
else:
    print("❌ KB SETUP FAILED")
    print("   No embeddings built.")
print("=" * 60)
