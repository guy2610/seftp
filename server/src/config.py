import os

class Config:
    def __init__(self,host,port,data_path,log_level,idle_timeout_s=60, upload_inactivity_timeout_s=20,handshake_timeout_s=5,
                 max_file_size=100* 1024 * 1024,max_packets=65535,max_chunk_size=64* 1024,
                 max_payload_size=10_000_000,read_timeout_s=10,max_concurrent_uploads=10, max_connections=10, max_connections_per_ip=10,
                 cpu_worker_threads=4, cpu_max_in_flight=8,max_req_per_window=50,req_window_s=5,metrics_enabled=False,
                 metrics_host="127.0.0.1", metrics_port=9100):
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
        self.max_concurrent_uploads = max_concurrent_uploads
        self.max_connections = max_connections
        self.max_connections_per_ip = max_connections_per_ip
        self.cpu_max_in_flight = cpu_max_in_flight
        self.cpu_worker_threads = cpu_worker_threads
        self.handshake_timeout_s = handshake_timeout_s
        self.max_req_per_window = max_req_per_window
        self.req_window_s = req_window_s
        self.metrics_enabled = metrics_enabled
        self.metrics_host = metrics_host
        self.metrics_port = metrics_port

    @classmethod
    def load(cls):
        host = '127.0.0.1'
        port=1256
        data_path = "data/seftp_server_sql.db"
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
        def env_bool(name: str, default: bool) -> bool:
            v = os.getenv(name)
            if v is None or v == "":
                return default
            return v.lower() in {"1", "true", "yes", "on"}

        return cls(
            host=host,
            port=port,
            data_path=data_path,
            log_level=os.getenv("SEFTP_LOG_LEVEL", log_level),
            idle_timeout_s=env_int("SEFTP_IDLE_TIMEOUT_S", 60),
            upload_inactivity_timeout_s=env_int("SEFTP_UPLOAD_INACTIVITY_TIMEOUT_S", 20),
            handshake_timeout_s=env_float("SEFTP_HANDSHAKE_TIMEOUT_S", 5),
            max_file_size=env_int("SEFTP_MAX_FILE_SIZE", 100 * 1024 * 1024),
            max_packets=env_int("SEFTP_MAX_PACKETS", 65535),
            max_chunk_size=env_int("SEFTP_MAX_CHUNK_SIZE", 64 * 1024),
            max_payload_size=env_int("SEFTP_MAX_PAYLOAD_SIZE", 10_000_000),
            read_timeout_s=env_float("SEFTP_READ_TIMEOUT_S", 10),
            max_concurrent_uploads=env_int("SEFTP_MAX_CONCURRENT_UPLOADS", 10),
            max_connections=env_int("SEFTP_MAX_CONNECTIONS",10),
            max_connections_per_ip=env_int("SEFTP_MAX_CONNECTIONS_PER_IP", 10),
            cpu_worker_threads=env_int("SEFTP_CPU_WORKER_THREADS",4),
            cpu_max_in_flight=env_int("SEFTP_CPU_MAX_IN_FLIGHT",8),
            max_req_per_window=env_int("SEFTP_MAX_REQUESTS_PER_WINDOW",50),
            req_window_s=env_int("SEFTP_REQUEST_WINDOW_SECONDS",5),
            metrics_enabled=env_bool("SEFTP_METRICS_ENABLED", False),
            metrics_host=os.getenv("SEFTP_METRICS_HOST", "127.0.0.1"),
            metrics_port=env_int("SEFTP_METRICS_PORT", 9100),
        )
