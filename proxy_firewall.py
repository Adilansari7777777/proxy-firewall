import socket
import threading
import logging
import signal
import sys
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Tuple, Dict, Optional

DEFAULT_CONFIG_PATH = "proxy_config.json"

class ProxyConfig:
    def __init__(self, cfg_path: str = DEFAULT_CONFIG_PATH):
        self.cfg_path = Path(cfg_path)
        self.load()

    def load(self):
        default = {
            "listen_addr": "127.0.0.1",
            "listen_port": 8888,
            "blocked_domains_file": "blocked_domains.txt",
            "blocked_domains": ["facebook.com", "instagram.com"],
            "max_workers": 50,
            "socket_timeout": 10,
            "log_file": "proxy.log"
        }

        user = {}
        if self.cfg_path.exists():
            try:
                content = self.cfg_path.read_text(encoding="utf-8").strip()
                if not content:
                    raise json.JSONDecodeError("Empty file", content, 0)
                user = json.loads(content)
            except (json.JSONDecodeError, OSError) as e:
                logging.warning(f"Config file invalid or empty, recreating defaults: {e}")
                user = {}
                self.cfg_path.write_text(json.dumps(default, indent=2), encoding="utf-8")
        else:
            self.cfg_path.write_text(json.dumps(default, indent=2), encoding="utf-8")
            logging.info(f"[+] Created sample config at {self.cfg_path.resolve()}")

        for k, v in default.items():
            setattr(self, k, user.get(k, v))

        self._load_blocked_domains_file()

    def _load_blocked_domains_file(self):
        bd_file = Path(self.blocked_domains_file)
        if bd_file.exists():
            try:
                lines = [line.strip() for line in bd_file.read_text(encoding="utf-8").splitlines()]
                file_domains = [l for l in lines if l and not l.startswith("#")]
                combined = list(dict.fromkeys(file_domains + getattr(self, "blocked_domains", [])))
                self.blocked_domains = combined
            except Exception as e:
                logging.warning(f"Failed to load blocked domains file: {e}")

    def is_blocked(self, host: str) -> bool:
        if not host:
            return False
        host_l = host.lower()
        return any(
            host_l == bd.lower() or host_l.endswith("." + bd.lower())
            for bd in getattr(self, "blocked_domains", [])
        )

def setup_logging(log_file: str):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding="utf-8")
        ]
    )

def parse_http_request(request_bytes: bytes) -> Tuple[str, Dict[str, str], bytes]:
    try:
        request_text = request_bytes.decode("iso-8859-1")
    except Exception:
        request_text = request_bytes.decode(errors="ignore")
    parts = request_text.split("\r\n\r\n", 1)
    head = parts[0]
    body = parts[1].encode("iso-8859-1") if len(parts) > 1 else b""
    lines = head.split("\r\n")
    first_line = lines[0] if lines else ""
    headers = {}
    for h in lines[1:]:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return first_line, headers, body

def rebuild_request_for_server(first_line: str, headers: Dict[str, str], body: bytes) -> Optional[bytes]:
    parts = first_line.split(" ")
    if len(parts) < 3:
        return None
    method, uri, version = parts[0], parts[1], parts[2]
    if uri.startswith("http://") or uri.startswith("https://"):
        scheme_sep = uri.find("://")
        rest = uri[scheme_sep+3:]
        slash = rest.find("/")
        path = rest[slash:] if slash != -1 else "/"
    else:
        path = uri
    new_first_line = f"{method} {path} {version}"
    header_lines = [f"{k}: {v}" for k, v in headers.items()]
    header_block = "\r\n".join(header_lines)
    return f"{new_first_line}\r\n{header_block}\r\n\r\n".encode("iso-8859-1") + body

def safe_close(sock: socket.socket):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        sock.close()

def forward_data(src: socket.socket, dst: socket.socket, timeout: float):
    src.settimeout(timeout)
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        safe_close(dst)

def handle_client(client_sock: socket.socket, client_addr: Tuple[str, int], cfg: ProxyConfig):
    client_sock.settimeout(cfg.socket_timeout)
    try:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = client_sock.recv(8192)
            if not chunk:
                break
            request += chunk
            if len(request) > 65536:
                break
        if not request:
            safe_close(client_sock)
            return

        first_line, headers, body = parse_http_request(request)

        # HTTPS tunnel (CONNECT)
        if first_line.upper().startswith("CONNECT"):
            try:
                target = first_line.split(" ")[1]
                host, port = (target.split(":", 1) + ["443"])[:2]
                port = int(port)
            except Exception:
                client_sock.send(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                safe_close(client_sock)
                return

            if cfg.is_blocked(host):
                client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Proxy Firewall")
                safe_close(client_sock)
                logging.info(f"[BLOCKED] CONNECT to {host} from {client_addr}")
                return

            try:
                server_sock = socket.create_connection((host, port), timeout=cfg.socket_timeout)
            except Exception as e:
                logging.warning(f"Failed to connect to {host}:{port} -> {e}")
                client_sock.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                safe_close(client_sock)
                return

            client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            t1 = threading.Thread(target=forward_data, args=(client_sock, server_sock, cfg.socket_timeout), daemon=True)
            t2 = threading.Thread(target=forward_data, args=(server_sock, client_sock, cfg.socket_timeout), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            logging.info(f"[TUNNEL CLOSED] {client_addr} -> {host}:{port}")
            return

        # Normal HTTP
        host = headers.get("Host", "")
        if not host:
            try:
                uri = first_line.split(" ")[1]
                if uri.startswith("http://") or uri.startswith("https://"):
                    scheme_sep = uri.find("://")
                    rest = uri[scheme_sep+3:]
                    slash = rest.find("/")
                    host = rest if slash == -1 else rest[:slash]
            except Exception:
                host = ""

        target_host, target_port = host, 80
        if ":" in host:
            h, p = host.rsplit(":", 1)
            target_host, target_port = h, int(p) if p.isdigit() else 80

        if cfg.is_blocked(target_host):
            client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Proxy Firewall")
            safe_close(client_sock)
            logging.info(f"[BLOCKED] HTTP to {target_host} from {client_addr}")
            return

        try:
            server_sock = socket.create_connection((target_host, target_port), timeout=cfg.socket_timeout)
        except Exception as e:
            logging.warning(f"Failed to connect to {target_host}:{target_port} -> {e}")
            client_sock.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            safe_close(client_sock)
            return

        outbound = rebuild_request_for_server(first_line, headers, body)
        if outbound is None:
            safe_close(client_sock)
            safe_close(server_sock)
            return

        server_sock.sendall(outbound)
        client_to_server = threading.Thread(target=forward_data, args=(client_sock, server_sock, cfg.socket_timeout), daemon=True)
        client_to_server.start()

        try:
            while True:
                data = server_sock.recv(8192)
                if not data:
                    break
                client_sock.sendall(data)
        except Exception:
            pass
        finally:
            safe_close(server_sock)
            safe_close(client_sock)
            logging.info(f"[HTTP CLOSED] {client_addr} -> {target_host}:{target_port}")

    except Exception as exc:
        logging.exception(f"Error handling client {client_addr}: {exc}")
        safe_close(client_sock)

class ProxyServer:
    def __init__(self, cfg: ProxyConfig):
        self.cfg = cfg
        self._sock = None
        self._should_stop = threading.Event()
        self.executor = ThreadPoolExecutor(max_workers=cfg.max_workers)

    def start(self):
        setup_logging(self.cfg.log_file)
        bind_addr = (self.cfg.listen_addr, self.cfg.listen_port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(bind_addr)
        self._sock.listen(200)
        logging.info(f"Proxy listening on {bind_addr[0]}:{bind_addr[1]} (max_workers={self.cfg.max_workers})")

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Only on systems that support SIGHUP (Linux/macOS)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, lambda *_: self.cfg.load())

        try:
            while not self._should_stop.is_set():
                client_sock, client_addr = self._sock.accept()
                logging.info(f"[CONNECT] {client_addr}")
                self.executor.submit(handle_client, client_sock, client_addr, self.cfg)
        except OSError:
            pass
        finally:
            self.stop()

    def stop(self):
        logging.info("Shutting down proxy...")
        self._should_stop.set()
        if self._sock:
            safe_close(self._sock)
        self.executor.shutdown(wait=True)
        logging.info("Proxy stopped.")

    def _signal_handler(self, signum, frame):
        logging.info(f"Signal {signum} received, shutting down...")
        self.stop()
        sys.exit(0)

if __name__ == "__main__":
    cfg = ProxyConfig(DEFAULT_CONFIG_PATH)
    server = ProxyServer(cfg)
    server.start()
