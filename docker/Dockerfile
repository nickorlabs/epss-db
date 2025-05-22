FROM python:3.11-slim

# Install system dependencies for psycopg2
RUN apt-get update && apt-get install -y gcc libpq-dev curl && rm -rf /var/lib/apt/lists/*

WORKDIR /scripts

# Ensure project root is on the Python path for ETL imports
ENV PYTHONPATH=/scripts

# Install Python dependencies (add others as needed)
RUN pip install --no-cache-dir psycopg2-binary requests vulncheck_sdk

# Add wait-for-it script
RUN curl -sSL -o /wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh \
    && chmod +x /wait-for-it.sh

# Copy the entire ETL package
COPY ../etl /scripts/etl

# Default command (override in docker-compose)
CMD ["python", "--version"]
