def log_event(tipo, msg):
    with open("audit.log", "a") as f:
        f.write(f"{tipo} | {msg}\n")