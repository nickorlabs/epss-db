import logging


def safe_execute(cur, sql, params=None, dry_run=False):
    """
    Executes a SQL statement if not in dry run mode. Logs the statement and params if dry_run is True.
    Args:
        cur: psycopg2 cursor
        sql: SQL statement
        params: parameters for SQL statement
        dry_run: if True, do not execute, just log
    """
    if dry_run:
        logging.info(f"[DRY RUN] Would execute: {sql} | params: {params}")
        return None
    else:
        return cur.execute(sql, params)


def safe_executemany(cur, sql, seq_of_params, dry_run=False):
    """
    Executes a SQL statement multiple times if not in dry run mode. Logs the statement and params if dry_run is True.
    Args:
        cur: psycopg2 cursor
        sql: SQL statement
        seq_of_params: sequence of parameter sets
        dry_run: if True, do not execute, just log
    """
    if dry_run:
        logging.info(f"[DRY RUN] Would executemany: {sql} | params: {seq_of_params}")
        return None
    else:
        return cur.executemany(sql, seq_of_params)


def dry_run_notice():
    logging.warning("[DRY RUN] No changes will be made to the database.")

class RunMetrics:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.inserts = 0
        self.updates = 0
        self.deletes = 0
        self.fetched = 0
        self.errors = 0
        self.skipped = 0
        self.extra = {}

    def log_summary(self):
        prefix = '[DRY RUN]' if self.dry_run else '[SUMMARY]'
        logging.info(f"{prefix} Would insert {self.inserts} records, update {self.updates}, delete {self.deletes}." if self.dry_run else f"{prefix} Inserted {self.inserts} records, updated {self.updates}, deleted {self.deletes}.")
        logging.info(f"{prefix} Fetched {self.fetched} records. Skipped: {self.skipped}. Errors: {self.errors}.")
        if self.extra:
            for k, v in self.extra.items():
                logging.info(f"{prefix} {k}: {v}")

# Alias for backward compatibility
DryRunMetrics = RunMetrics
