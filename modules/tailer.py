import paramiko
import time
import os

ORACLE_IP   = os.environ["ORACLE_IP"]
ORACLE_KEY  = os.environ["ORACLE_SSH_KEY"]

KNOWN_HOSTS_PATH = os.environ.get("KNOWN_HOSTS_PATH", "known_hosts")

class _TofuPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, known_hosts_path: str):
        self.path = known_hosts_path

    def missing_host_key(self, client, hostname, key):
        hk = client.get_host_keys()
        if hk.lookup(hostname):
            raise paramiko.SSHException(
                f"[tailer] SECURITY ALERT: Host key for {hostname} has changed! "
                "Possible MITM attack. Remove the entry from known_hosts to reset."
            )
        hk.add(hostname, key.get_name(), key)
        hk.save(self.path)
        print(
            f"[tailer] TOFU: Pinned {key.get_name()} host key for {hostname} "
            f"to '{self.path}'. Fingerprint: {paramiko.util.hexdigest(key.get_fingerprint())}"
        )

def _load_client() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    if os.path.exists(KNOWN_HOSTS_PATH):
        client.load_host_keys(KNOWN_HOSTS_PATH)
    client.set_missing_host_key_policy(_TofuPolicy(KNOWN_HOSTS_PATH))
    return client

def stream_oracle_logs():
    retry_delay = 10
    while True:
        client = None
        try:
            print(f"[tailer] Connecting to {ORACLE_IP}...")
            client = _load_client()
            client.connect(
                hostname=ORACLE_IP,
                username="ubuntu",
                key_filename=ORACLE_KEY,
                timeout=30,
            )
            print("[tailer] Connected. Tailing /var/log/auth.log ...")
            _stdin, stdout, _stderr = client.exec_command(
                "sudo tail -f /var/log/auth.log"
            )
            for line in stdout:
                yield line.strip()
            print("[tailer] Stream ended. Reconnecting...")
        except paramiko.SSHException as e:
            print(f"[tailer] SSH error: {e}")
            if "SECURITY ALERT" in str(e):
                raise 
        except Exception as e:
            print(f"[tailer] Connection error: {e}. Retrying in {retry_delay}s...")
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass
        time.sleep(retry_delay)

def tail_log_local(filepath):
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.5)
