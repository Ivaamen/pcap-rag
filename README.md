# PCAP RAG-based LLM Analyzer
## Overview

A LLM tool to help analyze pcap files (captured from wireshark, nmap, etc.), capable of answering complex questions grounded in real data.

## How it works
It takes pcap files as an input (stored under directory "captures/*"), parsing through their metadata and documentation. This output is then embedded into a chroma vector database using miniLM-L6-V2, so that it is prepared for retrieval. It is finally retrieved using Groq's llama-3.3-70B cloud model, now fully primed with all necessary information.

## How to use
First configure your Groq api key in bash:
```bash
export GROQ_API_KEY=<your-api-key-here>
```
Then run
```python
python3 parse_pcaps.py <file-name.pcapng>
```
In order to extract all of the important information from the pcapng files.
Then run
```python
python3 RAG_pipeline.py
```
In order to embed every connection into the chroma vector database using miniLM-L6-V2, ready for retrieval. With no argument it auto-picks the most recent connections summary; pass a specific one as an argument if you prefer.
Finally, ask questions about the capture. The top-k most relevant connections are retrieved from the vector database and the answer is generated grounded only in them:
```python
python3 RAG_pipeline.py ask "What SSH connections were captured?"
```
For a conversational session instead of a single question:
```python
python3 RAG_pipeline.py ask --interactive
```
Control how many connections are retrieved per question with --top-k (default 3). Run the RAG_pipeline.py commands from inside the pcap-rag-venv virtual environment, since chromadb and groq are installed there.

## Future changes
Possibly an ability to do this live using live capture (perhaps by shifting to another library like pyshark instead), to build a constantly updating LLM for dynamic usage.