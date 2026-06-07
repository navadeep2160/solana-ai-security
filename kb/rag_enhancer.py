def build_rag_context(query_funcs, queries):
    """
    Strong RAG builder:
    - dedup
    - multi-source merge
    - structured formatting
    """

    seen = set()
    context_blocks = []

    for q in queries:
        for fn in query_funcs:
            try:
                results = fn(q, top_k=3)
                for r in results:
                    text = r.get("content", "")
                    if not text:
                        continue

                    # normalize
                    text = text.strip()[:500]

                    if text in seen:
                        continue

                    seen.add(text)

                    source = r.get("source", "KB")
                    context_blocks.append(f"""
SOURCE: {source}
CONTENT:
{text}
""")

            except Exception:
                continue

    return "\n\n".join(context_blocks)
