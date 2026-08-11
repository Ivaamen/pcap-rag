"""RAG_pipeline.py — ingest per-connection summaries into a Chroma vector
collection, and answer questions about them via retrieval + Groq generation.

Implements stages 2 and 4 of security_log_rag_project.md:
- ingest: take the `connections_summary_*.txt` file produced by parse_pcaps.py
  and store each connection as its own retrievable document in a persistent
  Chroma collection (embedded with all-MiniLM-L6-v2).
- ask: embed a question, retrieve the top-k most relevant connections, then
  have Groq (llama-3.3-70B) answer grounded ONLY in that retrieved context.

Usage (from the repo root, inside the pcap-rag-venv):
    python3 RAG_pipeline.py [path/to/connections_summary_*.txt]  # ingest
    python3 RAG_pipeline.py ask "question" [--top-k N]           # one-shot RAG answer
    python3 RAG_pipeline.py ask --interactive                    # chat loop

With no argument it auto-picks `connections_summary.txt`, else the most
recently modified `connections_summary_*.txt`.
"""

import argparse
import ast
import glob
import os
import sys

import chromadb
from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
from groq import Groq

# --- LLM client (Groq) ----------------------------------------------------
# Used by `ask` to generate answers grounded in retrieved context (see
# generate()). Guarded on the env var because the Groq SDK raises if
# GROQ_API_KEY is missing — set it in ~/.bashrc or via export.
groq_client = Groq(
    api_key=os.environ["GROQ_API_KEY"]
) if os.environ.get("GROQ_API_KEY") else None

# The generation model. llama-3.3-70B is the pipeline's target model
# (see README.md and security_log_rag_project.md).
GROQ_MODEL = "llama-3.3-70b-versatile"

# Persistent location of the vector store. A PersistentClient (rather than the
# in-memory Client()) means week-3 retrieval can load this store without
# re-ingesting the summary on every run.
CHROMA_DIR = "chroma_db"
COLLECTION_NAME = "connections"
DEFAULT_SUMMARY = "connections_summary.txt"

# Summary lines arrive as strings; Chroma metadata only accepts scalar
# str/int/float/bool. Coerce the numeric/bool fields to their natural type so
# later queries can filter on them (e.g. where={"dst_port": 22}).
FIELD_TYPES = {
    "src_port": int,
    "dst_port": int,
    "start_ts": float,
    "end_ts": float,
    "duration_s": float,
    "packet_count_fwd": int,
    "packet_count_rev": int,
    "byte_count_fwd": int,
    "byte_count_rev": int,
    "handshake_complete": lambda v: v == "True",
    "retransmissions": int,
}


def find_summary_file():
    """Return the connections-summary file to ingest.

    Prefers `connections_summary.txt` (the name CLAUDE.md references); falls
    back to the most recently modified `connections_summary_*.txt` since
    parse_pcaps.py writes timestamped files by default.
    """
    if os.path.exists(DEFAULT_SUMMARY):
        return DEFAULT_SUMMARY
    candidates = sorted(glob.glob("connections_summary_*.txt"), key=os.path.getmtime)
    if not candidates:
        sys.exit("No connections_summary file found. Run parse_pcaps.py first.")
    return candidates[-1]


def parse_connections(path):
    """Read the summary file into a list of per-connection dicts.

    The file is a sequence of blocks, each starting with a `Connection:`
    header followed by `key: value` lines. Each block becomes one document
    for Chroma, with its fields broken out into typed metadata so later
    queries can filter by them.
    """
    with open(path) as f:
        lines = f.read().splitlines()

    connections = []
    block_lines = []

    def finish_block(block):
        # First line: "Connection: <stream_id> (<a>:<pa> <-> <b>:<pb>)"
        stream_id = block[0].split()[1]
        text = "\n".join(block).strip()
        metadata = parse_fields(block[1:])
        metadata["stream_id"] = stream_id
        connections.append({"id": stream_id, "text": text, "metadata": metadata})

    for line in lines:
        if line.startswith("Connection:"):
            if block_lines:
                finish_block(block_lines)
            block_lines = [line]
        elif block_lines:
            block_lines.append(line)
    if block_lines:
        finish_block(block_lines)

    return connections


def parse_fields(lines):
    """Turn `  key: value` lines into typed Chroma metadata.

    `stream_id` is added by parse_connections from the block header, so it is
    not handled here.
    """
    metadata = {}
    for line in lines:
        if ": " not in line:
            continue
        key, value = line.strip().split(": ", 1)
        if key == "tcp_flags_seq":
            # The parser writes a Python list repr like ['PA', 'A']; Chroma
            # metadata can't hold lists, so flatten to a comma-joined string.
            try:
                metadata[key] = ",".join(ast.literal_eval(value))
            except (ValueError, SyntaxError):
                metadata[key] = value
        elif key in FIELD_TYPES:
            try:
                metadata[key] = FIELD_TYPES[key](value)
            except ValueError:
                # Unparseable (e.g. app_protocol: None stays a string).
                metadata[key] = value
        else:
            metadata[key] = value if value != "None" else "unknown"
    return metadata


def cmd_ingest(args):
    """Ingest a connections summary into Chroma (the historical default)."""
    summary_path = args[0] if args else find_summary_file()
    if not os.path.exists(summary_path):
        sys.exit(f"Summary file not found: {summary_path}")

    connections = parse_connections(summary_path)
    if not connections:
        sys.exit(f"No connections parsed from {summary_path}")

    print(f"Ingesting {len(connections)} connections from {summary_path}")
    for conn in connections:
        print(f"  {conn['id']}")

    client = chromadb.PersistentClient(path=CHROMA_DIR)
    # Explicitly embed with Chroma's default all-MiniLM-L6-v2 model so the
    # collection is created with a known embedder rather than relying on the
    # implicit default. For an already-existing collection Chroma keeps the
    # stored config, which matches (both are the default) — so this is
    # behavior-preserving and only guarantees the choice for fresh DBs.
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=DefaultEmbeddingFunction(),
    )

    # upsert (not add) so re-running the script updates in place instead of
    # failing on duplicate stream_id keys.
    collection.upsert(
        ids=[conn["id"] for conn in connections],
        documents=[conn["text"] for conn in connections],
        metadatas=[conn["metadata"] for conn in connections],
    )
    print(f"Collection '{COLLECTION_NAME}' now holds {collection.count()} documents")


def retrieve(query, top_k=3):
    """Return the top-k connection summaries most relevant to `query`.

    The query is embedded with the same all-MiniLM-L6-v2 embedder used at
    ingest time (the collection's stored embedding function), so retrieval
    happens in the same space the documents were embedded in.
    """
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=DefaultEmbeddingFunction(),
    )
    if collection.count() == 0:
        sys.exit(
            "Vector store is empty — run `python3 RAG_pipeline.py` first "
            "to ingest a connections summary."
        )
    results = collection.query(
        query_texts=[query],
        n_results=top_k,
        include=["documents", "distances"],
    )
    return [
        {
            "stream_id": results["ids"][0][i],
            "document": results["documents"][0][i],
            "distance": results["distances"][0][i],
        }
        for i in range(len(results["ids"][0]))
    ]


def format_context(hits):
    """Render retrieved hits as labeled context blocks for the LLM prompt."""
    return "\n\n".join(
        f"[source: {hit['stream_id']}]\n{hit['document']}"
        for hit in hits
    )


def generate(question, context):
    """Ask Groq to answer `question` using ONLY the retrieved `context`.

    Retrieval always runs before this is called, so the model can only answer
    from what the vector store actually contained. The system prompt forbids
    inventing data and requires the model to say so when the context is
    insufficient.
    """
    if groq_client is None:
        sys.exit(
            "GROQ_API_KEY is not set. Export it first (it lives in ~/.bashrc):\n"
            "    export GROQ_API_KEY=<your-key>"
        )
    system_prompt = (
        "You are a network-capture analyst answering questions about a packet capture. "
        "A retrieval system selected the most relevant connection summaries from the "
        "capture; they are listed under 'Retrieved context'.\n\n"
        "Rules:\n"
        "- Answer ONLY from the retrieved context. Never invent packets, IP addresses, "
        "ports, protocols, packet/byte counts, timestamps, or retransmissions.\n"
        "- If the retrieved context does not contain enough information to answer, say "
        "so explicitly instead of guessing.\n"
        "- When you use a connection's data, cite its stream_id (e.g. \"stream "
        "1785460112.075620-1\").\n"
    )
    user_prompt = (
        f"Retrieved context:\n{context}\n\n"
        f"Question: {question}"
    )
    completion = groq_client.chat.completions.create(
        model=GROQ_MODEL,
        temperature=0.1,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )
    return completion.choices[0].message.content


def answer_question(question, top_k):
    """Retrieve relevant connections, then answer grounded only in them."""
    hits = retrieve(question, top_k=top_k)
    print(f"\nRetrieved {len(hits)} connection(s):")
    for hit in hits:
        print(f"  {hit['stream_id']}  (distance {hit['distance']:.4f})")
    print("\n--- Groq answer ---")
    print(generate(question, format_context(hits)))


def cmd_ask(args):
    """Answer a question (or start a chat loop) via retrieval + Groq."""
    parser = argparse.ArgumentParser(prog="RAG_pipeline.py ask")
    parser.add_argument("question", nargs="?", help="Question to ask about the capture.")
    parser.add_argument("--top-k", type=int, default=3,
                        help="Number of connections to retrieve (default: 3).")
    parser.add_argument("--interactive", action="store_true",
                        help="Chat loop instead of a one-shot answer.")
    ns = parser.parse_args(args)

    if ns.interactive:
        print("Interactive mode — ask about the capture (Ctrl-D to exit).")
        while True:
            try:
                question = input("> ")
            except EOFError:
                break
            if question.strip():
                answer_question(question.strip(), ns.top_k)
        return

    if not ns.question:
        parser.error("a question is required unless --interactive is used")
    answer_question(ns.question, ns.top_k)


def main(argv=None):
    # Default is ingest (historical behavior); `ask` switches to RAG queries.
    args = list(argv) if argv is not None else sys.argv[1:]
    if args and args[0] == "ask":
        return cmd_ask(args[1:])
    return cmd_ingest(args)


if __name__ == "__main__":
    main()
