# PCAP RAG-based LLM Analyzer
## Overview

A LLM tool to help analyze pcap files (captured from wireshark, nmap, etc.), capable of answering complex questions grounded in real data.

## How it works
It takes pcap files as an input (stored under directory "captures/*"), parsing through their metadata and documentation. This output is then embedded into a chroma vector database using miniLM-L6-V2, so that it is prepared for retrieval. It is finally retrieved using a Gemini Flash cloud model, now fully primed with all necessary information.

## Future changes
Possibly an ability to do this live using live capture (perhaps by shifting to another library like pyshark instead), to build a constantly updating LLM for dynamic usage.