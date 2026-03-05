import time
import collections

THRESHOLD = 5
WINDOW_SECONDS = 60

attempts_tracker = collections.defaultdict(set)
start_time = time.time()

def process_login_event(ip_address, username, status):
    """
    Detect password spraying from log events.
    """
    global start_time

    # Reset detection window if time exceeds
    if time.time() - start_time > WINDOW_SECONDS:
        attempts_tracker.clear()
        start_time = time.time()

    # Check failed login attempts
    if status.upper() == "FAILED":
        attempts_tracker[ip_address].add(username)

        # Check threshold
        if len(attempts_tracker[ip_address]) >= THRESHOLD:
            print(f"[!] ALERT: Potential Password Spray detected from {ip_address}")
            print(f"Targeted users: {list(attempts_tracker[ip_address])}")
            return True

    return False


def analyze_log_file(file_path):
    """
    Reads log file and analyzes login events.
    """
    try:
        with open(file_path, "r") as file:
            for line in file:
                parts = line.strip().split(",")

                if len(parts) != 3:
                    continue

                ip, username, status = parts
                process_login_event(ip, username, status)

    except FileNotFoundError:
        print("Error: Log file not found.")


# Run detection
log_file = "login_logs.csv"
analyze_log_file(log_file)

