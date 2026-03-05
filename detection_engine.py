import collections
import time


THRESHOLD = 5  
WINDOW_SECONDS = 60  


attempts_tracker = collections.defaultdict(set)
start_time = time.time()

def process_login_event(ip_address, username, status):
    """
    Analyzes login events to detect password spraying.
    """
    global start_time
    
    
    if time.time() - start_time > WINDOW_SECONDS:
        attempts_tracker.clear()
        start_time = time.time()

    if status == "FAILED":
        attempts_tracker[ip_address].add(username)
        
        
        if len(attempts_tracker[ip_address]) >= THRESHOLD:
            print(f"[!] ALERT: Potential Password Spray detected from {ip_address}")
            print(f"    Targeted users: {list(attempts_tracker[ip_address])}")
            return True
    return False


events = [
    ("192.168.1.50", "admin", "FAILED"),
    ("192.168.1.50", "user1", "FAILED"),
    ("192.168.1.50", "guest", "FAILED"),
    ("192.168.1.50", "hr_manager", "FAILED"),
    ("192.168.1.50", "it_support", "FAILED"), 
]

for ip, user, stat in events:
    process_login_event(ip, user, stat)