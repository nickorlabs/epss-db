FROM python:3.11-slim

# Install system dependencies for psycopg2
RUN apt-get update && apt-get install -y gcc libpq-dev curl git && rm -rf /var/lib/apt/lists/*

WORKDIR /scripts

# Ensure project root is on the Python path for ETL imports
ENV PYTHONPATH=/scripts

# Copy requirements.txt and install Python dependencies
COPY etl/feeds/requirements.txt /scripts/requirements.txt
RUN pip install --no-cache-dir -r /scripts/requirements.txt

# Install Playwright browsers (Chromium)
RUN apt-get update && apt-get install -y wget libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libpangocairo-1.0-0 libasound2 libxshmfence1 libgtk-3-0 libxss1 libxtst6 libx11-xcb1 libxcb-dri3-0 libxcomposite1 libxdamage1 libxrandr2 && rm -rf /var/lib/apt/lists/*
RUN python -m playwright install --with-deps chromium

# Add wait-for-it script
RUN curl -sSL -o /wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh \
    && chmod +x /wait-for-it.sh

# Copy the entire ETL package
COPY ../etl /scripts/etl

# Default command (override in docker-compose)
CMD ["python", "--version"]
