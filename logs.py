from datetime import datetime
import json

def log_event(action, user=None, ip=None, extra=None):
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "user": user,
        "ip": ip,
        "extra": extra
    }

    print(json.dumps(log))