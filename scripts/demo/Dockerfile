# Demo host for the README recordings (scripts/demo/record.py). The agent
# binary and the scripts in this directory are mounted in at run time.
FROM python:3-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
RUN apt-get update \
 && apt-get install -y --no-install-recommends jq \
 && rm -rf /var/lib/apt/lists/*
