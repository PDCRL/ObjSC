import subprocess
for i in range(1, 4):
	subprocess.call("./decCDef")
for i in range(1, 4):
	subprocess.call("./decCSCV")
for i in range(1, 4):
	subprocess.call("./forkCDef")
for i in range(1, 4):
	subprocess.call("./forkCSCV")
print("\n                  *********************************               \n")
