import os
import sys
import requests
import gzip
import shutil
import csv
import psycopg2
import logging
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(
    filename='update_epss.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': os.environ.get('PGUSER', 'postgres'),
    'password': os.environ.get('PGPASSWORD', 'postgres'),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

EPSS_DATA_DIR = os.path.join(os.path.dirname(__file__), 'epss-data', '3rd')
EPSS_OUT_DIR = os.path.join(os.path.dirname(__file__), 'epss-data')

MIN_DATE = datetime.strptime('2022-02-04', '%Y-%m-%d')

EPSS_URL_TEMPLATE = 'https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz'


def get_last_imported_date():
    # Connect to PostgreSQL and get the last imported date
    try:
        conn = psycopg2.connect(**PG_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT MAX(date) FROM epssdb;")
        row = cur.fetchone()
        if row and row[0]:
            return datetime.strptime(str(row[0]), '%Y-%m-%d')
        else:
            return MIN_DATE
    except Exception as e:
        logging.warning(f"Warning: Could not get last imported date from DB: {e}")
        return MIN_DATE
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

def download_and_extract(date):
    os.makedirs(EPSS_DATA_DIR, exist_ok=True)
    os.makedirs(EPSS_OUT_DIR, exist_ok=True)
    gz_file = os.path.join(EPSS_DATA_DIR, f'epss_scores-{date}.csv.gz')
    csv_file = os.path.join(EPSS_OUT_DIR, f'epss_scores-{date}.csv')
    url = EPSS_URL_TEMPLATE.format(date=date)
    if os.path.exists(gz_file):
        logging.info(f"File already exists: {gz_file}")
    else:
        logging.info(f"Downloading {url} ...")
        r = requests.get(url, stream=True)
        if r.status_code != 200:
            logging.error(f"ERROR: Could not download {url}")
            return None
        with open(gz_file, 'wb') as f:
            f.write(r.content)
    # Extract
    with gzip.open(gz_file, 'rb') as f_in, open(csv_file, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
    return csv_file

def preprocess_csv(csv_file, date):
    # Read the model version from the header
    model_version = None
    processed_rows = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('#model_version:'):
                model_version = line.strip().split(':')[1].split(',')[0]
            elif line.startswith('cve,epss,percentile') or line.startswith('#'):
                continue
            else:
                row = line.strip().split(',')
                if len(row) == 3:
                    cve, epss, percentile = row
                    processed_rows.append([cve, epss, percentile, model_version, date])
    return processed_rows

def import_to_postgres(rows):
    logging.info(f"Importing {len(rows)} rows into PostgreSQL...")
    conn = None
    try:
        conn = psycopg2.connect(**PG_CONFIG)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS epssdb (
            cve TEXT,
            epss FLOAT,
            percentile FLOAT,
            model TEXT,
            date DATE
        );
        """)
        # Use COPY for efficient bulk import
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerows(rows)
        buf.seek(0)
        cur.copy_expert(
            "COPY epssdb (cve, epss, percentile, model, date) FROM STDIN WITH CSV",
            buf
        )
        conn.commit()
        logging.info("Import complete.")
    except Exception as e:
        logging.error(f"ERROR importing to PostgreSQL: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            cur.close()
            conn.close()

def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days)):
        yield start_date + timedelta(n)

def main():
    last_date = get_last_imported_date()
    start_date = last_date + timedelta(days=1)
    end_date = datetime.today()
    logging.info(f"Auto data import: {start_date.date()} to {end_date.date()}")
    for d in daterange(start_date, end_date):
        date_str = d.strftime('%Y-%m-%d')
        logging.info(f"Processing {date_str}")
        csv_file = download_and_extract(date_str)
        if not csv_file:
            logging.warning(f"Skipping {date_str} (no file)")
            continue
        rows = preprocess_csv(csv_file, date_str)
        if rows:
            import_to_postgres(rows)
        else:
            logging.info(f"No data for {date_str}")
        # Clean up
        try:
            os.remove(csv_file)
        except Exception:
            pass
    logging.info("Auto data import finished.")

if __name__ == "__main__":
    main()
