from collections import defaultdict
import base64
import json
import tempfile
import os
class Store:
    def __init__(self):
        self.clients_info={}
        self.clients_recent_log=defaultdict(list)
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
            print(f"Successfully loaded data from {path}")

        except FileNotFoundError:
            print(f"Warning: The file {path} was not found.")
        except json.JSONDecodeError:
            print(f"Error: The file {path} is not a valid JSON.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

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
        temp_path=None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=".clients_info.", suffix=".tmp", dir=dir_path)
            with os.fdopen(fd,"w",encoding="utf-8") as f:
                json.dump(out,f,indent=4)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path,name_file)
            tmp_path= None
            print(f'Data successfully saved to {name_file}')
        except OSError as e:
            print(f"Error saving file: {e}")
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

