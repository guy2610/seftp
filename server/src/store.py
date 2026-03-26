from collections import defaultdict
import os
import sqlite3
import uuid
import datetime

class ClientRecord:
    def __init__(self,client_id_hex: str,username: str, public_key_der, aes_key_b64,created_at: str,last_seen: str):
        self.client_id_hex = client_id_hex
        self.username = username
        self.public_key_der = public_key_der
        self.aes_key_b64 = aes_key_b64
        self.created_at = created_at
        self.last_seen = last_seen

class Store:
    def __init__(self):
        self.clients_recent_log=defaultdict(list)
        self.sqliteConnection = None
        self.clients_by_id = {}
        self.clients_by_username = {}

    def _now(self):
        return  str(datetime.datetime.now())

    def _row_to_client_record(self,row):
        return ClientRecord(row[0],row[1],row[2],row[3],row[4],row[5])

    def _index_put(self,record):
        self.clients_by_id[record.client_id_hex] = record
        self.clients_by_username[record.username] = record

    def _load_clients_index(self):
        self.clients_by_id.clear()
        self.clients_by_username.clear()

        cursor = self.sqliteConnection.cursor()
        query = """SELECT client_id_hex, username, public_key_der, aes_key_b64, created_at, last_seen 
                    FROM Clients"""
        cursor.execute(query)
        for row in cursor.fetchall():
            record = self._row_to_client_record(row)
            self._index_put(record)
        cursor.close()

    def _get_index_record_or_raise(self,client_id_hex):
        record = self.clients_by_id.get(client_id_hex,None)
        if record is None:
            raise RuntimeError(
                f"Store index inconsistency: client_id {client_id_hex} exists in DB flow but missing from in-memory index"
            )
        return record

    def initialize(self,db_name = 'seftp_server_sql.db'):
        try:
            db_dir = os.path.dirname(os.path.abspath(db_name))
            os.makedirs(db_dir, exist_ok=True)

            self.sqliteConnection = sqlite3.connect(db_name)
            self.sqliteConnection.execute("PRAGMA foreign_keys = ON")
            self.sqliteConnection.execute("PRAGMA journal_mode = WAL")
            self.sqliteConnection.execute("PRAGMA synchronous = NORMAL")
            cursor = self.sqliteConnection.cursor()
            print("DB initialize")

            create_clients_table_query = """
            CREATE TABLE IF NOT EXISTS Clients (
                id INTEGER PRIMARY KEY,
                client_id_hex TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                public_key_der BLOB,
                aes_key_b64 TEXT,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            """
            create_uploads_table_query = """
            CREATE TABLE IF NOT EXISTS Uploads (
                id INTEGER PRIMARY KEY,
                client_id_hex TEXT NOT NULL,
                file_name TEXT NOT NULL,
                stored_path TEXT,
                orig_file_size INTEGER,
                cipher_size INTEGER,
                server_crc32 INTEGER,
                status TEXT NOT NULL,
                failure_reason TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (client_id_hex) REFERENCES Clients(client_id_hex)
            );
            """
            cursor.execute(create_clients_table_query)
            cursor.execute(create_uploads_table_query)
            self.sqliteConnection.commit()
            cursor.close()

            self._load_clients_index()
            print(f"Backend initialized: Connected to {db_name}")
            return True

        except sqlite3.Error as error:
            print("Error occurred -", error)
            self.sqliteConnection = None
            return False

    def close(self):
        if not self.sqliteConnection:
            print("No active connection to close.")
            return
        try:
            self.sqliteConnection.commit()
            self.sqliteConnection.close()
            self.sqliteConnection = None
            self.clients_by_id.clear()
            self.clients_by_username.clear()
            print("Backend closed successfully.")
        except sqlite3.Error as e:
            print(f"Error during closing: {e}")

    def create_client(self,username):
        if not self.sqliteConnection:
            print("No active connection.\nError create_client")
            return None

        cursor = self.sqliteConnection.cursor()
        client_id_hex = uuid.uuid4().hex
        created_at = self._now()
        last_seen = created_at
        data = (client_id_hex,username,created_at,last_seen)
        cursor.execute("INSERT INTO Clients (client_id_hex,username,created_at,last_seen) VALUES (?,?,?,?)",data)
        self.sqliteConnection.commit()
        cursor.close()

        record = ClientRecord(client_id_hex,username,None,None, created_at,last_seen)
        self._index_put(record)
        return record
    def get_client_by_username(self,username):
        if not self.sqliteConnection:
            print("No active connection.\n Error get_client_by_username")
            return None
        return self.clients_by_username.get(username,None)

    def get_client_by_id(self,client_id_hex):
        if not self.sqliteConnection:
            print("No active connection.\n Error get_client_by_id")
            return None
        return self.clients_by_id.get(client_id_hex,None)


    def client_exists_by_username(self,username):
        if not self.sqliteConnection:
            print("No active connection.\n Error client_exists_by_username")
            return False

        return username in self.clients_by_username


    def client_exists_by_id(self,client_id_hex):
        if not self.sqliteConnection:
            print("No active connection.\n Error client_exists_by_id")
            return False

        return client_id_hex in self.clients_by_id

    def set_client_public_key(self,client_id_hex, public_key_der):
        if not self.sqliteConnection:
            print("No active connection.\n Error set_client_public_key")
            return False
        cursor = self.sqliteConnection.cursor()
        query = """UPDATE Clients
            SET public_key_der = ?
            WHERE client_id_hex = ?
            """
        cursor.execute(query, (public_key_der, client_id_hex))
        self.sqliteConnection.commit()
        if cursor.rowcount == 0:
            cursor.close()
            return False

        record = self._get_index_record_or_raise(client_id_hex)
        record.public_key_der = public_key_der
        cursor.close()
        return True

    def set_client_aes_key(self,client_id_hex, aes_key_b64):
        if not self.sqliteConnection:
            print("No active connection.\n Error set_client_aes_key")
            return False
        cursor = self.sqliteConnection.cursor()
        query = """UPDATE Clients
            SET aes_key_b64 = ?
            WHERE client_id_hex = ?
            """
        cursor.execute(query, (aes_key_b64, client_id_hex))
        self.sqliteConnection.commit()
        if cursor.rowcount == 0:
            cursor.close()
            return False

        record = self._get_index_record_or_raise(client_id_hex)
        record.aes_key_b64 = aes_key_b64
        cursor.close()
        return True

    def touch_client_last_seen(self,client_id_hex):
        if not self.sqliteConnection:
            print("No active connection.\n Error touch_client_last_seen")
            return False
        cursor = self.sqliteConnection.cursor()
        last_seen = self._now()
        query = """UPDATE Clients
            SET last_seen = ?
            WHERE client_id_hex = ?
            """
        cursor.execute(query, (last_seen, client_id_hex))
        self.sqliteConnection.commit()
        if cursor.rowcount == 0:
            cursor.close()
            return False

        record = self._get_index_record_or_raise(client_id_hex)
        record.last_seen = last_seen
        cursor.close()
        return True
    def create_upload_record(self,client_id_hex, file_name, orig_file_size, cipher_size, status='in_progress'):
        if not self.sqliteConnection:
            print("No active connection.\n Error create_upload_record")
            return None
        cursor = self.sqliteConnection.cursor()
        created_at = self._now()
        data = (client_id_hex,file_name,orig_file_size,cipher_size,status,created_at)
        cursor.execute("INSERT INTO Uploads (client_id_hex,file_name,orig_file_size,cipher_size,status,created_at) VALUES (?,?,?,?,?,?)",data)
        self.sqliteConnection.commit()
        upload_record = cursor.lastrowid
        cursor.close()
        return upload_record

    def complete_upload_record(self, upload_id, stored_path, server_crc32, completed_at):
        if not self.sqliteConnection:
            print("No active connection.\n Error complete_upload_record")
            return False
        cursor = self.sqliteConnection.cursor()
        status = "completed"
        query = """UPDATE Uploads
            SET status = ? ,
            completed_at = ? ,
            stored_path = ? ,
            server_crc32 = ? 
            WHERE id = ?
            """
        cursor.execute(query, (status, completed_at, stored_path, server_crc32, upload_id))
        self.sqliteConnection.commit()
        record_exist = cursor.rowcount > 0
        cursor.close()
        return record_exist

    def fail_upload_record(self, upload_id, failure_reason, status, completed_at):
        if not self.sqliteConnection:
            print("No active connection.\n Error fail_upload_record")
            return False
        cursor = self.sqliteConnection.cursor()
        query = """UPDATE Uploads
            SET status = ? ,
            completed_at = ?,
            failure_reason = ?
            WHERE id = ?
            """
        cursor.execute(query, (status, completed_at, failure_reason, upload_id))
        self.sqliteConnection.commit()
        record_exist = cursor.rowcount > 0
        cursor.close()
        return record_exist

    def get_client_uploads(self,client_id_hex):
        if not self.sqliteConnection:
            print("No active connection.\n Error get_client_uploads")
            return None
        cursor = self.sqliteConnection.cursor()
        query = """SELECT * FROM Uploads WHERE client_id_hex = ? ORDER BY id DESC"""
        cursor.execute(query,(client_id_hex,))
        uploads = cursor.fetchall()
        cursor.close()
        return uploads



