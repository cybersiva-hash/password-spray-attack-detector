import csv
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt

LOG_FILE = "login_logs.csv"
SPRAY_THRESHOLD = 3   # same password used on 3+ users


def read_logs():
    logs = []
    with open(LOG_FILE, "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            logs.append(row)
    return logs


def detect_password_spray(logs):
    password_usage = defaultdict(set)

    for row in logs:
        if row["status"] == "FAIL":
            password_usage[row["password"]].add(row["username"])

    detected = False
    for password, users in password_usage.items():
        if len(users) >= SPRAY_THRESHOLD:
            print("\n🚨 ALERT: Password Spray Attack Detected!")
            print(f"Suspicious Password: {password}")
            print(f"Number of Users Targeted: {len(users)}")
            print(f"Users: {', '.join(users)}")
            detected = True

    if not detected:
        print("\n✅ No Password Spray Attack Detected.")


def generate_summary(logs):
    total_attempts = len(logs)
    failed_attempts = 0
    unique_users = set()
    failed_per_user = defaultdict(int)

    for row in logs:
        unique_users.add(row["username"])
        if row["status"] == "FAIL":
            failed_attempts += 1
            failed_per_user[row["username"]] += 1

    print("\n------ Attack Summary Report ------")
    print(f"Total Login Attempts: {total_attempts}")
    print(f"Total Failed Attempts: {failed_attempts}")
    print(f"Unique Users Targeted: {len(unique_users)}")


    return failed_per_user


def plot_failed_attempts(failed_per_user):
    users = list(failed_per_user.keys())
    failures = list(failed_per_user.values())

    plt.figure()
    plt.bar(users, failures)
    plt.xlabel("Users")
    plt.ylabel("Number of Failed Attempts")
    plt.title("Failed Login Attempts Per User")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


def main():
    print("Reading Logs...")
    logs = read_logs()

    detect_password_spray(logs)

    failed_data = generate_summary(logs)

    plot_failed_attempts(failed_data)


if __name__ == "__main__":
    main()