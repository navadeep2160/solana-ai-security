"""
Builds vulnerability nodes directly from KB source chunks.
Uses Ollama locally — zero API rate limits.
AI discovers what vulnerabilities exist in each source — no hardcoding.
"""
import os, json, time, warnings
os.environ["ANONYMIZED_TELEMETRY"] = "False"
warnings.filterwarnings("ignore")

import chromadb
from pathlib import Path
from models.ollama_client import load_model

DB_DIR     = Path("knowledge_base/chromadb")
NODES_FILE = Path("knowledge_base/vuln_nodes.json")

SOURCES = {
    "vulnerabilities": [
        "vrust_paper", "sealevel_attacks", "neodyme_pitfalls",
        "otter_anchor_security", "sec3_spl", "swc_registry",
        "acm_2022", "acm_2025", "fuzzdelsel_paper", "solana_program_arxiv"
    ],
    "audit_findings": [
        "neodyme_anker", "cantina_guide", "trailofbits_solana",
        "neodyme_reports", "slither_detectors", "immunefi_solana"
    ],
    "network_kb": [
        "eclipse_attack_arxiv", "solana_vulns_wu", "ddos_spam_acm_ccs_2024",
        "vote_censorship_anza", "gossip_abuse_anza", "sandwich_mev_jito",
        "helius_mev_report", "helius_outage_history", "tpu_congestion_helius",
        "cve_2024_54134_detail", "slow_patch_adoption", "epsilon_stake_halt",
        "anza_tech_report", "solana_program_arxiv2"
    ]
}

def get_source_chunks(client, col_name, source_id):
    col  = client.get_collection(col_name)
    data = col.get(include=["documents", "metadatas"])
    return [doc for doc, meta in zip(data["documents"], data["metadatas"])
            if meta.get("source_id") == source_id and len(doc) > 100]

def extract_nodes(llm, source_id, chunks):
    text = "\n\n---\n\n".join(chunks[:6])
    prompt = f"""You are a Solana security knowledge engineer.

Read this security research text and extract ALL distinct vulnerability types mentioned.
Source: {source_id}

TEXT:
{text[:3000]}

Extract every unique vulnerability or attack pattern explicitly described.
Return ONLY valid JSON, no markdown:
{{
  "nodes": [
    {{
      "name": "exact vulnerability name from text",
      "category": "auth|arithmetic|account|cpi|network|oracle|other",
      "severity": "critical|high|medium|low",
      "description": "one sentence from the text describing this vulnerability",
      "preconditions": ["specific condition in code/network that enables this"],
      "ast_patterns": ["AST pattern to look for, e.g. AccountInfo without Signer"],
      "cfg_patterns": ["CFG pattern, e.g. transfer without owner_check"],
      "fix": "one line fix from the text",
      "source": "{source_id}"
    }}
  ]
}}

Rules:
- Only extract vulnerabilities explicitly described in the text
- Use exact names from the text
- Return empty nodes list if no clear vulnerabilities found
- No invented vulnerabilities"""

    try:
        raw = llm.invoke(prompt).content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip()).get("nodes", [])
    except Exception as e:
        print(f"  Failed: {e}")
        return []

def build_all_nodes():
    # Load existing nodes if partial run
    existing = []
    done_sources = set()
    if NODES_FILE.exists():
        data = json.loads(NODES_FILE.read_text())
        existing = data.get("nodes", [])
        done_sources = {n["source"] for n in existing}
        print(f"Resuming — {len(existing)} nodes already built, "
              f"{len(done_sources)} sources done")

    client = chromadb.PersistentClient(path=str(DB_DIR))
    llm    = load_model(force_local=True)

    all_nodes  = existing.copy()
    node_id    = len(existing) + 1

    for col_name, source_ids in SOURCES.items():
        print(f"\n=== {col_name} ===")
        for source_id in source_ids:
            if source_id in done_sources:
                print(f"  {source_id}: already done, skipping")
                continue

            chunks = get_source_chunks(client, col_name, source_id)
            if not chunks:
                print(f"  {source_id}: no chunks")
                continue

            print(f"  {source_id}: {len(chunks)} chunks → extracting...")
            nodes = extract_nodes(llm, source_id, chunks)

            for node in nodes:
                node["vuln_id"]    = f"SOL-{node_id:03d}"
                node["collection"] = col_name
                all_nodes.append(node)
                node_id += 1

            print(f"    → {len(nodes)} nodes: "
                  f"{[n['name'][:30] for n in nodes]}")

            # Save after every source — resume if interrupted
            NODES_FILE.write_text(json.dumps(
                {"total": len(all_nodes), "nodes": all_nodes}, indent=2))

    # Deduplicate
    seen, unique = set(), []
    for n in all_nodes:
        key = n["name"].lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append(n)

    NODES_FILE.write_text(json.dumps(
        {"total": len(unique), "nodes": unique}, indent=2))

    print(f"\n{'='*50}")
    print(f"VULNERABILITY NODES: {len(unique)}")
    cats = {}
    for n in unique:
        c = n.get("category", "other")
        cats[c] = cats.get(c, 0) + 1
    for cat, count in sorted(cats.items()):
        print(f"  {cat}: {count} nodes")
    return unique

if __name__ == "__main__":
    build_all_nodes()
