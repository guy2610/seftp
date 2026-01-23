from collections import defaultdict
class Store:
    def __init__(self):
        self.clients_info={}
        self.clients_recent_log=defaultdict(list)
    def load_client_info(self,path):
        try:
            with open(path, "r") as file:
                i = 0
                for line in file:
                    if i % 4 == 0:
                        name = line[:len(line) - 1]
                        self.clients_info[name] = ["none"] * 4
                    elif i % 4 == 1:
                        self.clients_info[name][0] = line[:len(line) - 1]
                    elif i % 4 == 2:
                        self.clients_info[name][1] = line[:len(line) - 1]
                    elif i % 4 == 3:
                        self.clients_info[name][2] = line[:len(line) - 1]
                    else:
                        self.clients_info[name][3] = line[:len(line) - 1]
                    i += 1

        except:
            print(f'file name clients.info not found')