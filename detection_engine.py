import csv
from collections import defaultdict

LOG_FILE = "login_logs.csv"

THRESHOLD = 3


def detect_password_spray():
    password_users = defaultdict(set)

    try:
        with open(LOG_FILE, "r") as file:
            reader = csv.DictReader(file)

            for row in reader:
                username = row["username"]
                password = row["password"]
                status = row["status"]

                if status == "FAIL":
                    password_users[password].add(username)

        attacks_detected = []

        for password, users in password_users.items():
            if len(users) >= THRESHOLD:
                attacks_detected.append((password, list(users)))

        return attacks_detected

    except FileNotFoundError:
        print("Error: login_logs.csv not found. Run attack_simulation.py first.")
        return []


if __name__ == "__main__":
    results = detect_password_spray()

    if results:
        print("\n⚠ Password Spray Attack Detected!\n")

        for password, users in results:
            print("Suspicious Password:", password)
            print("Number of Users Targeted:", len(users))
            print("Users:", ", ".join(users))
            print("-" * 40)

    else:
        print("No password spray attack detected.")
