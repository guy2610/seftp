from collections import defaultdict
import base64
class Store:
    def __init__(self):
        self.clients_info={}
        self.clients_recent_log=defaultdict(list)
    def load_client_info(self,path):
        # clients_info structure:
        # {
        #   "username": [
        #       client_id (16-byte UUID as bytes),
        #       public_key (RSA public key in DER format, as bytes),
        #       last_seen (string timestamp),
        #       aes_key_b64 (AES-256 key, Base64-encoded string)
        #   ]
        # }
        try:
            with open(path, "r") as file:
                i = 0
                for line in file:
                    line = raw.rstrip("\n")
                    if i % 5 == 0:
                        name = line[:len(line) - 1]
                        self.clients_info[name] = [None] * 4
                    elif i % 5 == 1:
                        self.clients_info[name][0] =  base64.b64decode(line) # bytes(16)
                    elif i % 5 == 2:
                        self.clients_info[name][1] =  base64.b64decode(line) # DER bytes
                    elif i % 5 == 3:
                        self.clients_info[name][2] = line
                    else:
                        self.clients_info[name][3] = line
                    i += 1

        except:
            print(f'file name clients.info not found')

    def name_of_dict_from_id(self,client_id):
        """
            Given client_id (bytes), return the associated username from clients_info.
            Returns None if not found.
            """
        for k, vals in self.clients_info.items():
            if vals[0] == client_id:
                return k
        return None