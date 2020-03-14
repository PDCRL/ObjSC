import subprocess
for i in range(1, 4):
	subprocess.call("./decDef")
for i in range(1, 4):
	subprocess.call("./decSCV")
for i in range(1, 4):
	subprocess.call("./forkDef")
for i in range(1, 4):
	subprocess.call("./forkSCV")
print("\n                  *********************************               \n")
