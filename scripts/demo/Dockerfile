# Demo host for the README recordings (scripts/demo/record.py). The agent
# binary and the scripts in this directory are mounted in at run time.
FROM python:3-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913
RUN apt-get update \
 && apt-get install -y --no-install-recommends jq \
 && rm -rf /var/lib/apt/lists/*
