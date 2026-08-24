import random

passwords = [
    "admin",
    "password",
    "123456",
    "root",
    "ubuntu",
    "letmein",
    "qwerty",
    "raspberry"
]

chosen = random.choice(passwords)

with open("/home/faizan/cowrie/etc/userdb.txt", "w") as f:
    f.write(f"root:0:{chosen}\n")

print(f"Active password set to: {chosen}")
