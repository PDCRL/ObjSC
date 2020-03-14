import subprocess

GenAUs = ["g++", "-std=c++17", "GenAUs.cpp", "-o", "genAUs", "-O3", "-g"]
subprocess.call(GenAUs)

########################  Workload 1  ##################################
print("\n\n\n---------------- Workload 1 ----------------\n")
cmd = ["./genAUs", "500", "600", "50", "50", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "500", "600", "50", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "500", "600", "50", "150", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "500", "600", "50", "200", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "500", "600", "50", "250", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "500", "600", "50", "300", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

########################  Workload 2  ##################################
print("\n\n\n---------------- Workload 2 ----------------\n")
cmd = ["./genAUs", "500", "600", "10", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "500", "600", "20", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "500", "600", "30", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "500", "600", "40", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "500", "600", "60", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")
		
########################  Workload 3  ##################################
print("\n\n\n---------------- Workload 3 ----------------\n")

cmd = ["./genAUs", "100", "600", "50", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "200", "600", "50", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "300", "600", "50", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "400", "600", "50", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")

cmd = ["./genAUs", "600", "600", "50", "100", "1"]
subprocess.call(cmd)
subprocess.call(["python", "run.py"], cwd="Serial")
subprocess.call(["python", "run.py"], cwd="MVOSTM")
subprocess.call(["python", "run.py"], cwd="OSTM")
subprocess.call(["python", "run.py"], cwd="MVTO")
subprocess.call(["python", "run.py"], cwd="BTO-STM")
subprocess.call(["python", "run.py"], cwd="Spec-Bin")
subprocess.call(["python", "run.py"], cwd="Static-Bin")
print("\n--------------------------------------------------------------\n")
