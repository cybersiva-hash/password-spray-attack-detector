import random
import datetime

users = ["user1", "user2", "user3", "user4", "user5"]
common_password = "Password@123"

def generate_log():
    with open("login_logs.csv", "w") as f:
        f.write("timestamp,username,password,status\n")
        
        # Normal login attempts
        for _ in range(10):
            user = random.choice(users)
            password = "randomPass"
            status = "FAIL"
            timestamp = datetime.datetime.now()
            f.write(f"{timestamp},{user},{password},{status}\n")
        
        # Password spray attack
        for user in users:
            timestamp = datetime.datetime.now()
            f.write(f"{timestamp},{user},{common_password},FAIL\n")

generate_log()