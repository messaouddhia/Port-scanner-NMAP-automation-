import nmap
import re
from sys import argv, version

print("""
                                                  _      ___         _        
  /\/\    ___  ___  ___   __ _   ___   _   _   __| |    /   \ /\  /\(_)  __ _ 
 /    \  / _ \/ __|/ __| / _` | / _ \ | | | | / _` |   / /\ // /_/ /| | / _` |
/ /\/\ \|  __/\__ \\__ \| (_| || (_) || |_| || (_| |  / /_/// __  / | || (_| |
\/    \/ \___||___/|___/ \__,_| \___/  \__,_| \__,_| /___,' \/ /_/  |_| \__,_|
""")
#code here..

sperate= "--------------------------------------------------------------------------------------------------------"
#shorten the function with a variable
scanner = nmap.PortScanner()

#make the user able to scan from the terminal
#Get the target ip address and the port range
args = argv[1:]
if len(argv)==4:
    target_ip=args[0]
    port_range=args[1]
    scan_type=args[2]
else:
    print("""Your supposed to enter the Target IP address 
        then the port range and the attack type, enter them again.""")
    target_ip= str(input("Enter the target IP address:\n"))
    port_range= str(input("Enter the port range please:\n "))
    scan_type=str(input("Enter attack type: "))

#Function for scan 1 
def scan_aggressive():
    #print the nmap version to the user
    nversion = "NMAP.Version:" + str(scanner.nmap_version())
    #Print nmap version without any special characters
    string = re.sub(r"[() ]","",nversion)
    #start scanning
    print(string+"\nScanning...")
    scanner.scan(target_ip,port_range,"-v -sA -O -sV")
    #Save the scan info into a variable
    print("This a list of the scan info. Please ignore if not wanted: " 
        + str(scanner.scaninfo()))
    #For every host in the target aquired we check its status
    for host in scanner.all_hosts():
        print(sperate)
        #print the status of the target
        print(F'Host : {host} ({scanner[host].hostname()}) \t State : {scanner[host].state()} \n ')
        #Check the protocol for every host
        for proto in scanner[host].all_protocols():
            print(F"Protocol: {proto}")
            #Make a variable to get the ports from the protocol
            lport = scanner[host][proto].keys()
            #Check port status
            for port in lport:
                print(F"""Port: {port} \t State: {scanner[host][proto][port]['state']} 
                    \t Service: {scanner[host][proto][port]['name']}
                    \t Version: {scanner[host][proto][port]["version"]}""")
            print("""--------------------------------------------------------------------------------------------------------""")
            print("\n Finished scan.")
            print("CSV Output: \n"+ scanner.csv())


#Function for scan 2
def scan_paranoid():
    #print the nmap version to the user
    nversion = "NMAP.Version:" + str(scanner.nmap_version())
    #Print nmap version without any special characters
    string = re.sub(r"[() ]","",nversion)
    #start scanning
    print(string+"\nScanning...")
    scanner.scan(target_ip,port_range,"-sS -T0")  
    #Save the scan info into a variable
    print("This a list of the scan info. Please ignore if not wanted: " 
        + str(scanner.scaninfo()))
    #For every host in the target aquired we check its status
    for host in scanner.all_hosts():
        print(sperate)
        #print the status of the target
        print(F'Host : {host} ({scanner[host].hostname()}) \t State : {scanner[host].state()} \n ')
        #Check the protocol for every host
        for proto in scanner[host].all_protocols():
            print(F"Protocol: {proto}")
            #Make a variable to get the ports from the protocol
            lport = scanner[host][proto].keys()
            #Check port status
            for port in lport:
                print(F"""Port: {port} \t State: {scanner[host][proto][port]['state']} 
                    \t Service: {scanner[host][proto][port]['name']}
                    \t Version: {scanner[host][proto][port]["version"]}""")
            print("--------------------------------------------------------------------------------------------------------")
            print("\n Finished scan.")
            print("CSV Output: \n"+scanner.csv())

#if statement to check which scan combination the user want to use.
if scan_type=="1":
    scan_aggressive()
elif scan_type=="2":
    scan_paranoid()
else:
    scan_aggressive()