import os, warnings
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")

from pathlib import Path
import chromadb
from sentence_transformers import SentenceTransformer

DB_DIR = Path(__file__).parent / "chromadb"

class RAGQuery:
    def __init__(self, n_results=5):
        self.n_results = n_results
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.client = chromadb.PersistentClient(path=str(DB_DIR))
        self._collections = {}

    def _get_collection(self, name):
        if name not in self._collections:
            self._collections[name] = self.client.get_collection(name)
        return self._collections[name]

    def query(self, collection_name, question, n=None):
        n = n or self.n_results
        col = self._get_collection(collection_name)
        embedding = self.model.encode([question]).tolist()
        raw = col.query(query_embeddings=embedding, n_results=n)

        output = []
        for doc, meta, distance in zip(
            raw["documents"][0],
            raw["metadatas"][0],
            raw["distances"][0]
        ):
            # skip garbage chunks (github login pages etc)
            if "signed in with another tab" in doc or "camo.githubusercontent.com" in doc or len(doc) < 80:
                continue
            output.append({
                "text":       doc,
                "source":     meta["title"],
                "url":        meta["url"],
                "source_id":  meta["source_id"],
                "collection": collection_name,
                "relevance":  round(1 - distance, 3)
            })
        return output

    def format_for_llm(self, results, max_chars=3000):
        if not results:
            return "=== NO RELEVANT CONTEXT FOUND ===\n"
        context = "=== RELEVANT KNOWLEDGE BASE CONTEXT ===\n\n"
        total = 0
        for i, r in enumerate(results):
            chunk = f"[{i+1}] Source: {r['source']} (relevance: {r['relevance']})\n{r['text']}\n\n"
            if total > 0 and total + len(chunk) > max_chars:
                break
            context += chunk
            total += len(chunk)
        context += "=== END CONTEXT ===\n"
        return context

    def query_scanner(self, question, n=5):
        return self.query("vulnerabilities", question, n)

    def query_patcher(self, question, n=5):
        return self.query("audit_findings", question, n)

    def query_exploit(self, question, n=5):
        return self.query("vulnerabilities", question, n)

    def query_scorer(self, question, n=5):
        vuln  = self.query("vulnerabilities", question, n=3)
        audit = self.query("audit_findings",  question, n=2)
        return vuln + audit

    def query_network(self, question, n=5):
        return self.query("network_kb", question, n)

    def query_architecture(self, question, n=5):
        return self.query("architecture", question, n)

    def query_all(self, question, n=2):
        results = []
        for col in ["vulnerabilities", "audit_findings", "architecture", "network_kb"]:
            results += self.query(col, question, n)
        return sorted(results, key=lambda x: x["relevance"], reverse=True)


if __name__ == "__main__":
    rag = RAGQuery()
    print("Testing RAGQuery...\n")

    tests = [
        ("query_scanner",      "missing signer check anchor program"),
        ("query_patcher",      "PDA ownership validation fix"),
        ("query_exploit",      "arbitrary CPI reentrancy attack"),
        ("query_network",      "validator eclipse attack consensus"),
        ("query_architecture", "proof of history tower BFT"),
    ]

    for method, question in tests:
        results = getattr(rag, method)(question)
        if not results:
            print(f"[{method}] NO RESULTS\n")
            continue
        top = results[0]
        context = rag.format_for_llm(results)
        print(f"[{method}]")
        print(f"  Question : {question}")
        print(f"  Top src  : {top['source']}")
        print(f"  Relevance: {top['relevance']}")
        print(f"  Context  : {len(context):,} chars ready for LLM")
        print(f"  Preview  : {top['text'][:120]}...")
        print()

    print("✅ RAGQuery ready for all agents!")
