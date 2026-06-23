import re

def parse_line(line):
    patterns = [
        (r"(\w+ +\d+ [\d:]+).*Failed password for (\S+) from ([\d.]+)",       "failed_login"),
        (r"(\w+ +\d+ [\d:]+).*Invalid user (\S+) from ([\d.]+)",               "invalid_user"),
        (r"(\w+ +\d+ [\d:]+).*Accepted password for (\S+) from ([\d.]+)",      "successful_login"),
        (r"(\w+ +\d+ [\d:]+).*Accepted publickey for (\S+) from ([\d.]+)",     "successful_login_key"),
        (r"(\w+ +\d+ [\d:]+).*Failed password for root from ([\d.]+)",          "root_attack"),
        (r"(\w+ +\d+ [\d:]+).*Disconnecting invalid user (\S+) ([\d.]+)",       "auth_flood"),
        (r"(\w+ +\d+ [\d:]+).*new user: name=(\S+)",                            "new_user_created"),
        (r"(\w+ +\d+ [\d:]+).*usermod.*-aG.*(sudo|admin|wheel).*(\S+)",         "privilege_escalation"),
        (r"(\w+ +\d+ [\d:]+).*Connection (closed|reset) by (invalid user \S+ )?([\d.]+)", "connection_reset"),
        (r"(\w+ +\d+ [\d:]+).*maximum authentication attempts exceeded.*from ([\d.]+)", "max_auth_exceeded"),
        (r"(\w+ +\d+ [\d:]+).*pam_unix.*authentication failure.*rhost=([\d.]+).*user=(\S+)", "pam_auth_failure"),
        (r"(\w+ +\d+ [\d:]+).*sudo.*?([\w-]+) :.*COMMAND=(.+)",                "sudo_command"),
    ]

    for pattern, event_type in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            groups = match.groups()
            if event_type == "root_attack":
                return {"type": event_type, "time": groups[0], "user": "root",         "ip": groups[1]}
            if event_type == "connection_reset":
                return {"type": event_type, "time": groups[0], "user": "unknown",      "ip": groups[3]}
            if event_type == "max_auth_exceeded":
                return {"type": event_type, "time": groups[0], "user": "unknown",      "ip": groups[1]}
            if event_type == "pam_auth_failure":
                return {"type": event_type, "time": groups[0], "user": groups[2],      "ip": groups[1]}
            if event_type == "new_user_created":
                return {"type": event_type, "time": groups[0], "user": groups[1],      "ip": "local"}
            if event_type == "privilege_escalation":
                return {"type": event_type, "time": groups[0], "user": groups[2],      "ip": "local"}
            if event_type == "sudo_command":
                return {"type": event_type, "time": groups[0], "user": groups[1],      "ip": "local", "command": groups[2].strip()}
            return {"type": event_type, "time": groups[0], "user": groups[1], "ip": groups[2]}

    return None
