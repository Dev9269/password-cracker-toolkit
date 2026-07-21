import json
import os
import time


SESSION_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sessions")


class SessionManager:
    def __init__(self, name=None):
        self.name = name
        self.data = {
            "name": name,
            "created_at": time.time(),
            "updated_at": time.time(),
            "hash_type": None,
            "hash_target": None,
            "mode": None,
            "keyspace_offset": 0,
            "total_keyspace": 0,
            "attempts": 0,
            "cracked": False,
            "password": None,
            "results": [],
            "threads": 1,
        }

    def set(self, key, value):
        self.data[key] = value
        self.data["updated_at"] = time.time()

    def get(self, key, default=None):
        return self.data.get(key, default)

    def incr(self, key, amount=1):
        self.data[key] = self.data.get(key, 0) + amount
        self.data["updated_at"] = time.time()

    def save(self):
        if not self.name:
            return
        if not os.path.exists(SESSION_DIR):
            os.makedirs(SESSION_DIR)
        safe_name = self.name.replace("/", "_").replace("\\", "_")
        path = os.path.join(SESSION_DIR, f"{safe_name}.session")
        with open(path, "w") as f:
            json.dump(self.data, f, indent=2)
        return path

    def load(self, name=None):
        name = name or self.name
        if not name:
            return None
        safe_name = name.replace("/", "_").replace("\\", "_")
        path = os.path.join(SESSION_DIR, f"{safe_name}.session")
        if not os.path.exists(path):
            return None
        with open(path, "r") as f:
            self.data = json.load(f)
        self.name = self.data.get("name", name)
        return self.data

    def delete(self):
        if not self.name:
            return
        safe_name = self.name.replace("/", "_").replace("\\", "_")
        path = os.path.join(SESSION_DIR, f"{safe_name}.session")
        if os.path.exists(path):
            os.unlink(path)

    @staticmethod
    def list_sessions():
        if not os.path.exists(SESSION_DIR):
            return []
        sessions = []
        for fname in os.listdir(SESSION_DIR):
            if fname.endswith(".session"):
                path = os.path.join(SESSION_DIR, fname)
                try:
                    with open(path, "r") as f:
                        data = json.load(f)
                    sessions.append(data)
                except (json.JSONDecodeError, IOError):
                    pass
        return sessions
