import os

class Config:
    def __init__(self,host,port,data_path,log_level,idle_timeout_s=60, upload_inactivity_timeout_s=20,max_file_size=100* 1024 * 1024,max_packets=12000,max_chunk_size=64* 1024, max_payload_size=10_000_000,read_timeout_s=10):
        self.host=host
        self.port=port
        self.data_path=data_path
        self.log_level=log_level
        self.idle_timeout_s = idle_timeout_s
        self.upload_inactivity_timeout_s = upload_inactivity_timeout_s
        self.max_file_size=max_file_size
        self.max_packets=max_packets
        self.max_chunk_size=max_chunk_size
        self.max_payload_size=max_payload_size
        self.read_timeout_s = read_timeout_s

    @classmethod
    def load(cls):
        host = '127.0.0.1'
        port=1256
        data_path="data/clients_info.json"
        log_level="INFO"
        try:
            with open("port.info", "r") as port_file:
                port=int(port_file.readline().strip())
            if port>65535 or port<1:
                raise ValueError
        except FileNotFoundError:
            pass
        except ValueError:
            raise ValueError("invalid port.info: expected integer port")
        def env_int(name: str, default: int) -> int:
            v = os.getenv(name)
            if v is None or v == "":
                return default
            return int(v)
        def env_float(name: str, default: float) -> float:
            v = os.getenv(name)
            if v is None or v == "":
                return default
            return float(v)

        return cls(
            host=host,
            port=port,
            data_path=data_path,
            log_level=os.getenv("SEFTP_LOG_LEVEL", log_level),
            idle_timeout_s=env_int("SEFTP_IDLE_TIMEOUT_S", 60),
            upload_inactivity_timeout_s=env_int("SEFTP_UPLOAD_INACTIVITY_TIMEOUT_S", 20),
            max_file_size=env_int("SEFTP_MAX_FILE_SIZE", 100 * 1024 * 1024),
            max_packets=env_int("SEFTP_MAX_PACKETS", 12000),
            max_chunk_size=env_int("SEFTP_MAX_CHUNK_SIZE", 64 * 1024),
            max_payload_size=env_int("SEFTP_MAX_PAYLOAD_SIZE", 10_000_000),
            read_timeout_s=env_float("SEFTP_READ_TIMEOUT_S", 10),
        )
