class Config:
    def __init__(self,host,port,data_path,log_level,idle_timeout_s=60, upload_inactivity_timeout_s=20):
        self.host=host
        self.port=port
        self.data_path=data_path
        self.log_level=log_level
        self.idle_timeout_s = idle_timeout_s
        self.upload_inactivity_timeout_s = upload_inactivity_timeout_s

    @classmethod
    def load(cls):
        host = '127.0.0.1'
        port=1256
        data_path="data/clients_info.json"
        log_level="INFO"
        try:
            with open("port.info", "r") as port_file:
                port=int(port_file.readline().strip())
        except:
            pass
        return cls(host=host, port=port, data_path=data_path, log_level=log_level)
