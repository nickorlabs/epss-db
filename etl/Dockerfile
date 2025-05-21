FROM python:3.11-slim

WORKDIR /scripts

COPY . /scripts
ENV PYTHONPATH=/scripts

RUN apt-get update && apt-get install -y postgresql-client && \
    pip install --no-cache-dir psycopg2-binary vulncheck-sdk requests && \
    rm -rf /var/lib/apt/lists/*

# Default CMD allows for ad-hoc ETL job runs for exploitpulse-importer
CMD ["bash"]
