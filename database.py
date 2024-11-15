from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import urllib
import os
from dotenv import load_dotenv

load_dotenv()
db_server = os.getenv('DB_SERVER')
db_name = os.getenv('DB_NAME')
db_user_id = os.getenv('DB_USER_ID')
db_password = os.getenv('DB_PASSWORD')
db_connection_pool_size = int(os.getenv('DB_CONNECTION_POOL_SIZE'))
db_connection_overflow = int(os.getenv('DB_CONNECTION_OVERFLOW'))

odbc_str = (
    "Driver={ODBC Driver 18 for SQL Server};"
    f"Server=tcp:{db_server},1433;"
    f"Database={db_name};"
    f"Uid={db_user_id};"
    f"Pwd={db_password};"
    f"Encrypt=yes;"
    f"TrustServerCertificate=no;"
    f"Connection Timeout=30;"
)

conn_string = f"mssql+pyodbc:///?odbc_connect={urllib.parse.quote_plus(odbc_str)}"
engine = create_engine(
    conn_string,
    pool_size=db_connection_pool_size,  
    max_overflow=db_connection_overflow,  
    pool_timeout=30,  
    pool_recycle=900,  
    echo=False, 
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
