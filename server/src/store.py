from collections import defaultdict
import base64
import json
import tempfile
import os
import sqlite3
import uuid
import datetime
class Store:
    def __init__(self):
        self.clients_info={}
        self.clients_recent_log=defaultdict(list)
        self.sqliteConnection = None
        # clients_info structure:
        # {
        #   "username": [
        #       client_id (16-byte UUID as bytes),
        #       public_key (RSA public key in DER format, as bytes),
        #       last_seen (string timestamp),
        #       aes_key_b64 (AES-256 key, Base64-encoded string)
        #   ]
        # }
    def load_client_info(self,path):
        try:
            with open(path,"r",encoding="utf-8") as f:
                data=json.load(f)
            for username,obj in data.items():
                try:
                    cid_b64 = obj.get("client_id_b64")
                    pub_b64 = obj.get("public_key_b64")
                    last_seen = obj.get("last_seen")
                    aes_b64 = obj.get("aes_key_b64")

                    client_id = base64.b64decode(cid_b64) if cid_b64 else None
                    if client_id is not None and len(client_id) != 16:
                        raise ValueError(f"bad client_id length for {username}: {len(client_id)}")

                    public_key = base64.b64decode(pub_b64) if pub_b64 else None
                    self.clients_info[username] = [client_id,public_key,last_seen,aes_b64]
                except Exception as e:
                    print(f"Error decoding data for user {username}: {e}")
            return True, f"Successfully loaded data from {path}"
        except FileNotFoundError:
            return (True, f"data file not found: {path}; starting with empty store")
        except json.JSONDecodeError:
            return False, f"invalid data file: {path}"
        except Exception as e:
            return False, f"failed loading client data: {e}"

    def name_of_dict_from_id(self,client_id):
        """
            Given client_id (bytes), return the associated username from clients_info.
            Returns None if not found.
            """
        for k, vals in self.clients_info.items():
            if vals[0] == client_id:
                return k
        return None

    def save_clients_info(self,name_file):
        out={}
        for username,values in self.clients_info.items():
            client_id = values[0]
            public_key = values[1]

            client_id_b64 = base64.b64encode(client_id).decode("utf-8") if isinstance(client_id,(bytes, bytearray)) else None
            public_key_b64 = base64.b64encode(public_key).decode("utf-8") if isinstance(public_key,(bytes, bytearray)) else None

            out[username]={
                    "client_id_b64":client_id_b64,
                    "public_key_b64":public_key_b64,
                    "last_seen":values[2],
                    "aes_key_b64":values[3]
            }
        dir_path = os.path.dirname(os.path.abspath(name_file))
        os.makedirs(dir_path, exist_ok=True)
        tmp_path=None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=".clients_info.", suffix=".tmp", dir=dir_path)
            with os.fdopen(fd,"w",encoding="utf-8") as f:
                json.dump(out,f,indent=4)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path,name_file)
            tmp_path= None
            return True, f"Data successfully saved to {name_file}"
        except OSError as e:
            return False, f"failed saving client data: {e}"
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def initialize(self,db_name = 'seftp_server_sql.db'):
        try:
            self.sqliteConnection = sqlite3.connect(db_name)
            self.sqliteConnection.execute("PRAGMA foreign_keys = ON")
            cursor = self.sqliteConnection.cursor()
            print("DB initialize")

            create_clients_table_query = """
            CREATE TABLE IF NOT EXISTS Clients (
                id INTEGER PRIMARY KEY,
                client_id_hex TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                public_key_b64 TEXT,
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
            print("Backend closed successfully.")
        except sqlite3.Error as e:
            print(f"Error during closing: {e}")

    def create_client(self,username):
        if not self.sqliteConnection:
            print("No active connection.\nError create_client")
            return None

        cursor = self.sqliteConnection.cursor()
        client_id_hex = uuid.uuid4().hex
        created_at = str(datetime.datetime.now())
        last_seen = created_at
        data = (client_id_hex,username,created_at,last_seen)
        cursor.execute("INSERT INTO Clients (client_id_hex,username,created_at,last_seen) VALUES (?,?,?,?)",data)
        self.sqliteConnection.commit()
        return client_id_hex
    def get_client_by_username(self,username):
        if not self.sqliteConnection:
            print("No active connection.\n Error get_client_by_username")
            return None
        cursor = self.sqliteConnection.cursor()
        query = """SELECT client_id_hex, username, public_key_b64, aes_key_b64, created_at, last_seen 
        FROM Clients 
        WHERE username = ?"""
        cursor.execute(query,(username,))
        return cursor.fetchone()

    def get_client_by_id(self,client_id_hex):
        if not self.sqliteConnection:
            print("No active connection.\n Error get_client_by_id")
            return None
        cursor = self.sqliteConnection.cursor()
        query =  """SELECT client_id_hex, username, public_key_b64, aes_key_b64, created_at, last_seen 
        FROM Clients
        WHERE client_id_hex = ?"""
        cursor.execute(query,(client_id_hex,))
        return cursor.fetchone()


    def client_exists_by_username(self,username):
        if self.sqliteConnection:
            cursor = self.sqliteConnection.cursor()
            query = "SELECT 1 FROM Clients WHERE username = ? LIMIT 1"
            cursor.execute(query,(username,))
            result = cursor.fetchone()
            return result is not None
        else:
            print("No active connection.\n Error client_exists_by_username")
            return False
    def client_exists_by_id(self,client_id_hex):
        if not self.sqliteConnection:
            print("No active connection.\n Error client_exists_by_id")
            return False

        cursor = self.sqliteConnection.cursor()
        query = """SELECT 1 FROM Clients WHERE client_id_hex = ? LIMIT 1"""
        cursor.execute(query,(client_id_hex,))
        return cursor.fetchone() is not None

    def set_client_public_key(self,client_id_hex, public_key_b64):
        if not self.sqliteConnection:
            print("No active connection.\n Error set_client_public_key")
            return False
        cursor = self.sqliteConnection.cursor()
        query = """UPDATE Clients
            SET public_key_b64 = ?
            WHERE client_id_hex = ?
            """
        cursor.execute(query, (public_key_b64, client_id_hex))
        self.sqliteConnection.commit()
        return cursor.rowcount > 0

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
        return cursor.rowcount > 0

    def touch_client_last_seen(self,client_id_hex):
        if not self.sqliteConnection:
            print("No active connection.\n Error touch_client_last_seen")
            return False
        cursor = self.sqliteConnection.cursor()
        last_seen = str(datetime.datetime.now())
        query = """UPDATE Clients
            SET last_seen = ?
            WHERE client_id_hex = ?
            """
        cursor.execute(query, (last_seen, client_id_hex))
        self.sqliteConnection.commit()
        return cursor.rowcount > 0

    def create_upload_record(self,client_id_hex, file_name, orig_file_size, cipher_size, status='in_progress'):
        if not self.sqliteConnection:
            print("No active connection.\n Error create_upload_record")
            return None
        cursor = self.sqliteConnection.cursor()
        created_at = str(datetime.datetime.now())
        data = (client_id_hex,file_name,orig_file_size,cipher_size,status,created_at)
        cursor.execute("INSERT INTO Uploads (client_id_hex,file_name,orig_file_size,cipher_size,status,created_at) VALUES (?,?,?,?,?,?)",data)
        self.sqliteConnection.commit()
        return cursor.lastrowid

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
        return cursor.rowcount > 0

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
        return cursor.rowcount > 0

    def get_client_uploads(self,client_id_hex):
        if not self.sqliteConnection:
            print("No active connection.\n Error get_client_uploads")
            return None
        cursor = self.sqliteConnection.cursor()
        query = """SELECT * FROM Uploads WHERE client_id_hex = ? ORDER BY id DESC"""
        cursor.execute(query,(client_id_hex,))
        return cursor.fetchall()



