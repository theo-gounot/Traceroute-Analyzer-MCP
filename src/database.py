import logging
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager

logger = logging.getLogger("Traceroute-Analyser-DB")

_db_pool = None

def init_db_pool(host, port, name, user, password):
    """Initialize the global database pool."""
    global _db_pool
    try:
        if not _db_pool:
            _db_pool = psycopg2.pool.SimpleConnectionPool(
                minconn=1,
                maxconn=20,
                host=host,
                port=port,
                database=name,
                user=user,
                password=password
            )
            logger.info("Database connection pool initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize database pool: {e}")
        # We don't raise here to allow the server to start even if DB is down (though tools will fail)

@contextmanager
def get_db_connection():
    """Yields a connection from the pool and ensures it's returned."""
    if _db_pool is None:
        raise Exception("Database pool is not initialized. Check your .env configuration.")
    
    conn = _db_pool.getconn()
    try:
        yield conn
    finally:
        _db_pool.putconn(conn)
