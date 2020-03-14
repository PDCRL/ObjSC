import subprocess

subprocess.call(["python", "run.py"], cwd="1.Coin")
subprocess.call(["python", "run.py"], cwd="2.Ballot")
subprocess.call(["python", "run.py"], cwd="3.Auction")
subprocess.call(["python", "run.py"], cwd="4.Mix")
