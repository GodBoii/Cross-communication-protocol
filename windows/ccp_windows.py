import base64
import hashlib
import json
import os
import queue
import random
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, Button, Frame, Label, Listbox, StringVar, Tk, filedialog, messagebox

PROTOCOL = "ccp.v0"
UDP_PORT = 47827
TCP_PORT = 47828
CHUNK_SIZE = 64 * 1024


def now():
    return int(time.time())


def app_dir():
    root = os.environ.get("APPDATA") or str(Path.home())
    path = Path(root) / "CCP"
    path.mkdir(parents=True, exist_ok=True)
    return path


def inbox_dir():
    path = Path.home() / "Downloads" / "CCP-Inbox"
    path.mkdir(parents=True, exist_ok=True)
    return path


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def safe_filename(name):
    blocked = '<>:"/\\|?*'
    clean = "".join("_" if ch in blocked else ch for ch in name).strip()
    return clean or "received-file"


@dataclass
class Peer:
    device_id: str
    device_name: str
    platform: str
    host: str
    tcp_port: int
    last_seen: int
    trusted: bool = False

    @property
    def label(self):
        trust = "trusted" if self.trusted else "new"
        return f"{self.device_name} ({self.platform}) - {self.host}:{self.tcp_port} - {trust}"


class ConfigStore:
    def __init__(self):
        self.path = app_dir() / "config.json"
        self.data = self._load()

    def _load(self):
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        device_seed = f"{socket.gethostname()}-{uuid.uuid4()}"
        return {
            "device_id": hashlib.sha256(device_seed.encode("utf-8")).hexdigest(),
            "device_name": f"{socket.gethostname()} Windows",
            "trusted_peers": {},
        }

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    @property
    def device_id(self):
        return self.data["device_id"]

    @property
    def device_name(self):
        return self.data["device_name"]

    def is_trusted(self, device_id):
        return device_id in self.data.get("trusted_peers", {})

    def trust(self, peer_info):
        self.data.setdefault("trusted_peers", {})[peer_info["device_id"]] = peer_info
        self.save()


class CcpBackend:
    def __init__(self, events):
        self.events = events
        self.config = ConfigStore()
        self.peers = {}
        self.running = threading.Event()
        self.running.set()

    def sender(self):
        return {
            "device_id": self.config.device_id,
            "device_name": self.config.device_name,
            "platform": "windows",
        }

    def envelope(self, kind, payload):
        return {
            "protocol": PROTOCOL,
            "id": str(uuid.uuid4()),
            "type": kind,
            "sender": self.sender(),
            "payload": payload,
            "timestamp": now(),
        }

    def log(self, text):
        self.events.put(("log", text))

    def ask_yes_no(self, title, prompt):
        replies = queue.Queue(maxsize=1)
        self.events.put(("confirm", (title, prompt, replies)))
        return replies.get()

    def start(self):
        threading.Thread(target=self._discovery_broadcast_loop, daemon=True).start()
        threading.Thread(target=self._discovery_listen_loop, daemon=True).start()
        threading.Thread(target=self._tcp_server_loop, daemon=True).start()
        self.log(f"Started as {self.config.device_name}")

    def stop(self):
        self.running.clear()

    def _discovery_packet(self):
        return {
            "protocol": PROTOCOL,
            "type": "discovery",
            "device_id": self.config.device_id,
            "device_name": self.config.device_name,
            "platform": "windows",
            "tcp_port": TCP_PORT,
            "capabilities": ["pairing", "file.transfer"],
            "timestamp": now(),
        }

    def _discovery_broadcast_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while self.running.is_set():
            try:
                data = json.dumps(self._discovery_packet()).encode("utf-8")
                sock.sendto(data, ("255.255.255.255", UDP_PORT))
            except OSError as exc:
                self.log(f"Discovery broadcast failed: {exc}")
            time.sleep(3)

    def _discovery_listen_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", UDP_PORT))
        while self.running.is_set():
            try:
                data, addr = sock.recvfrom(8192)
                packet = json.loads(data.decode("utf-8"))
                if packet.get("protocol") != PROTOCOL or packet.get("device_id") == self.config.device_id:
                    continue
                peer = Peer(
                    device_id=packet["device_id"],
                    device_name=packet.get("device_name", "Unknown"),
                    platform=packet.get("platform", "unknown"),
                    host=addr[0],
                    tcp_port=int(packet.get("tcp_port", TCP_PORT)),
                    last_seen=now(),
                    trusted=self.config.is_trusted(packet["device_id"]),
                )
                self.peers[peer.device_id] = peer
                self.events.put(("peers", list(self.peers.values())))
            except Exception as exc:
                self.log(f"Discovery receive failed: {exc}")

    def _tcp_server_loop(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("", TCP_PORT))
        server.listen()
        self.log(f"Listening on TCP {TCP_PORT}")
        while self.running.is_set():
            client, addr = server.accept()
            threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()

    def _read_message(self, file_obj):
        line = file_obj.readline()
        if not line:
            return None
        return json.loads(line.decode("utf-8"))

    def _write_message(self, file_obj, message):
        file_obj.write((json.dumps(message) + "\n").encode("utf-8"))
        file_obj.flush()

    def _handle_client(self, client, addr):
        with client:
            file_obj = client.makefile("rwb")
            active_transfer = None
            transfer_file = None
            try:
                while True:
                    msg = self._read_message(file_obj)
                    if msg is None:
                        break
                    kind = msg.get("type")
                    sender = msg.get("sender", {})
                    if kind == "pair.request":
                        self._handle_pair_request(file_obj, sender, msg.get("payload", {}), addr[0])
                    elif kind == "file.offer":
                        active_transfer, transfer_file = self._handle_file_offer(file_obj, sender, msg.get("payload", {}))
                    elif kind == "file.chunk" and active_transfer and transfer_file:
                        self._handle_file_chunk(msg.get("payload", {}), active_transfer, transfer_file)
                    elif kind == "file.complete" and active_transfer and transfer_file:
                        self._handle_file_complete(file_obj, msg.get("payload", {}), active_transfer, transfer_file)
                        active_transfer = None
                        transfer_file = None
            except Exception as exc:
                self.log(f"Connection from {addr[0]} failed: {exc}")
            finally:
                if transfer_file:
                    transfer_file.close()

    def _handle_pair_request(self, file_obj, sender, payload, host):
        code = payload.get("pair_code", "??????")
        prompt = f"Pair with {sender.get('device_name')} ({sender.get('platform')})?\nPair code: {code}"
        accepted = self.ask_yes_no("CCP Pairing Request", prompt)
        if accepted:
            self.config.trust(sender)
            peer = self.peers.get(sender["device_id"])
            if peer:
                peer.trusted = True
                peer.host = host
            self.events.put(("peers", list(self.peers.values())))
            self.log(f"Trusted {sender.get('device_name')}")
        response = self.envelope("pair.response", {"accepted": accepted, "reason": None if accepted else "rejected"})
        self._write_message(file_obj, response)

    def _handle_file_offer(self, file_obj, sender, payload):
        if not self.config.is_trusted(sender.get("device_id")):
            self._write_message(file_obj, self.envelope("file.offer.response", {
                "transfer_id": payload.get("transfer_id"),
                "accepted": False,
                "resume_from": 0,
                "reason": "peer is not paired",
            }))
            return None, None
        filename = safe_filename(payload.get("filename", "received-file"))
        target = inbox_dir() / filename
        stem = target.stem
        suffix = target.suffix
        counter = 1
        while target.exists():
            target = inbox_dir() / f"{stem}-{counter}{suffix}"
            counter += 1
        accepted = self.ask_yes_no("Incoming File", f"Accept {filename} from {sender.get('device_name')}?")
        self._write_message(file_obj, self.envelope("file.offer.response", {
            "transfer_id": payload.get("transfer_id"),
            "accepted": accepted,
            "resume_from": 0,
            "reason": None if accepted else "rejected",
        }))
        if not accepted:
            return None, None
        self.log(f"Receiving {filename} -> {target}")
        transfer = dict(payload)
        transfer["target"] = str(target)
        transfer["received"] = 0
        return transfer, open(target, "wb")

    def _handle_file_chunk(self, payload, transfer, transfer_file):
        raw = base64.b64decode(payload["data_b64"])
        if sha256_bytes(raw) != payload["sha256"]:
            raise ValueError(f"chunk {payload.get('index')} checksum mismatch")
        transfer_file.write(raw)
        transfer["received"] += len(raw)
        self.events.put(("progress", f"Receiving {transfer['filename']}: {transfer['received']} / {transfer['size']} bytes"))

    def _handle_file_complete(self, file_obj, payload, transfer, transfer_file):
        transfer_file.flush()
        transfer_file.close()
        actual = sha256_file(transfer["target"])
        ok = actual == payload.get("sha256") == transfer.get("sha256")
        self._write_message(file_obj, self.envelope("file.complete.response", {
            "transfer_id": transfer.get("transfer_id"),
            "ok": ok,
            "sha256": actual,
        }))
        self.log(("Received and verified " if ok else "Received but checksum failed ") + transfer["target"])

    def pair(self, peer):
        code = f"{random.randint(0, 999999):06d}"
        self.log(f"Pair request sent to {peer.device_name}. Code: {code}")
        response = self._send_single(peer, self.envelope("pair.request", {"pair_code": code, "public_key": "reserved-for-v1"}))
        if response and response.get("payload", {}).get("accepted"):
            self.config.trust({"device_id": peer.device_id, "device_name": peer.device_name, "platform": peer.platform})
            peer.trusted = True
            self.events.put(("peers", list(self.peers.values())))
            self.log(f"Paired with {peer.device_name}")
        else:
            self.log(f"Pairing rejected by {peer.device_name}")

    def send_file(self, peer, path):
        if not peer.trusted:
            self.log("Pair with the device before sending files.")
            return
        threading.Thread(target=self._send_file_worker, args=(peer, path), daemon=True).start()

    def _send_single(self, peer, message):
        with socket.create_connection((peer.host, peer.tcp_port), timeout=10) as sock:
            file_obj = sock.makefile("rwb")
            self._write_message(file_obj, message)
            return self._read_message(file_obj)

    def _send_file_worker(self, peer, path):
        transfer_id = str(uuid.uuid4())
        file_path = Path(path)
        size = file_path.stat().st_size
        full_hash = sha256_file(file_path)
        total_chunks = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
        offer = self.envelope("file.offer", {
            "transfer_id": transfer_id,
            "filename": file_path.name,
            "size": size,
            "sha256": full_hash,
            "chunk_size": CHUNK_SIZE,
            "total_chunks": total_chunks,
        })
        try:
            with socket.create_connection((peer.host, peer.tcp_port), timeout=10) as sock:
                file_obj = sock.makefile("rwb")
                self._write_message(file_obj, offer)
                response = self._read_message(file_obj)
                if not response or not response.get("payload", {}).get("accepted"):
                    self.log(f"{peer.device_name} rejected the file.")
                    return
                sent = 0
                with open(file_path, "rb") as f:
                    for index in range(total_chunks):
                        chunk = f.read(CHUNK_SIZE)
                        msg = self.envelope("file.chunk", {
                            "transfer_id": transfer_id,
                            "index": index,
                            "sha256": sha256_bytes(chunk),
                            "data_b64": base64.b64encode(chunk).decode("ascii"),
                        })
                        self._write_message(file_obj, msg)
                        sent += len(chunk)
                        self.events.put(("progress", f"Sending {file_path.name}: {sent} / {size} bytes"))
                self._write_message(file_obj, self.envelope("file.complete", {"transfer_id": transfer_id, "sha256": full_hash}))
                complete = self._read_message(file_obj)
                if complete and complete.get("payload", {}).get("ok"):
                    self.log(f"Sent and verified {file_path.name}")
                else:
                    self.log(f"Sent {file_path.name}, but receiver verification failed.")
        except Exception as exc:
            self.log(f"Send failed: {exc}")


class CcpApp:
    def __init__(self):
        self.root = Tk()
        self.root.title("CCP Windows")
        self.root.geometry("860x560")
        self.events = queue.Queue()
        self.backend = CcpBackend(self.events)
        self.peer_ids = []
        self.status = StringVar(value="Starting...")
        self._build_ui()
        self.backend.start()
        self.root.after(200, self._pump_events)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _build_ui(self):
        top = Frame(self.root)
        top.pack(fill=BOTH, expand=True, padx=12, pady=12)
        left = Frame(top)
        left.pack(side=LEFT, fill=BOTH, expand=True)
        right = Frame(top)
        right.pack(side=RIGHT, fill=BOTH, expand=True, padx=(12, 0))

        Label(left, text="Nearby devices").pack(anchor="w")
        self.device_list = Listbox(left, height=18)
        self.device_list.pack(fill=BOTH, expand=True)
        Button(left, text="Pair", command=self._pair_selected).pack(fill=BOTH, pady=(8, 0))
        Button(left, text="Send file", command=self._send_selected).pack(fill=BOTH, pady=(8, 0))

        Label(right, text="Activity").pack(anchor="w")
        self.log_list = Listbox(right, height=18)
        self.log_list.pack(fill=BOTH, expand=True)
        Label(self.root, textvariable=self.status).pack(fill=BOTH, padx=12, pady=(0, 12))

    def _selected_peer(self):
        selection = self.device_list.curselection()
        if not selection:
            messagebox.showinfo("CCP", "Select a nearby device first.")
            return None
        return self.backend.peers.get(self.peer_ids[selection[0]])

    def _pair_selected(self):
        peer = self._selected_peer()
        if peer:
            threading.Thread(target=self.backend.pair, args=(peer,), daemon=True).start()

    def _send_selected(self):
        peer = self._selected_peer()
        if not peer:
            return
        path = filedialog.askopenfilename()
        if path:
            self.backend.send_file(peer, path)

    def _pump_events(self):
        while True:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self.log_list.insert(END, payload)
                self.log_list.see(END)
                self.status.set(payload)
            elif kind == "progress":
                self.status.set(payload)
            elif kind == "peers":
                self.peer_ids = [peer.device_id for peer in payload]
                self.device_list.delete(0, END)
                for peer in payload:
                    self.device_list.insert(END, peer.label)
            elif kind == "confirm":
                title, prompt, replies = payload
                replies.put(messagebox.askyesno(title, prompt))
        self.root.after(200, self._pump_events)

    def _close(self):
        self.backend.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    CcpApp().run()
