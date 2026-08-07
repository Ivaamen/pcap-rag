"""LLM_RAG.py — ingest per-connection summaries into a Chroma vector collection.

Stage 2 of the pipeline in security_log_rag_project.md: take the
`connections_summary_*.txt` file produced by parse_pcaps.py and store each
connection as its own retrievable document in a persistent Chroma collection.
Week-3 retrieval (query -> embed -> top-k -> grounded answer) reads this store.

Usage (from the repo root, inside the pcap-rag-venv):
    python3 LLM_RAG.py [path/to/connections_summary_*.txt]

With no argument it auto-picks `connections_summary.txt`, else the most
recently modified `connections_summary_*.txt`.
"""

import ast
import glob
import os
import sys

import chromadb
from groq import Groq

# --- LLM client (placeholder, wired in during week 3) --------------------
# Generation is not implemented yet (see security_log_rag_project.md: retrieval
# must work by hand before the LLM is hooked up). The client is initialized now
# so it is ready when that stage lands; the chat-completion call below is a
# commented-out stub until then. Guarded on the env var because the Groq SDK
# raises if GROQ_API_KEY is missing.
groq_client = Groq(
    api_key=os.environ["GROQ_API_KEY"]
) if os.environ.get("GROQ_API_KEY") else None
# chat_completion = groq_client.chat.completions.create(
#     messages=[
#         {
#             "role": "user",
#             "content": "Explain the importance of fast language models",
#         }
#     ],
#     model="llama-3.3-70b-versatile",
# )

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


def main(argv=None):
    summary_path = argv[0] if argv else find_summary_file()
    if not os.path.exists(summary_path):
        sys.exit(f"Summary file not found: {summary_path}")

    connections = parse_connections(summary_path)
    if not connections:
        sys.exit(f"No connections parsed from {summary_path}")

    print(f"Ingesting {len(connections)} connections from {summary_path}")
    for conn in connections:
        print(f"  {conn['id']}")

    client = chromadb.PersistentClient(path=CHROMA_DIR)
    collection = client.get_or_create_collection(name=COLLECTION_NAME)

    # upsert (not add) so re-running the script updates in place instead of
    # failing on duplicate stream_id keys.
    collection.upsert(
        ids=[conn["id"] for conn in connections],
        documents=[conn["text"] for conn in connections],
        metadatas=[conn["metadata"] for conn in connections],
    )
    print(f"Collection '{COLLECTION_NAME}' now holds {collection.count()} documents")


if __name__ == "__main__":
    main()
