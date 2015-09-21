<h1>Progue</h1>

<h2>A probe reader and automatic Rogue AP Tool</h2>

<h3>About</h3>

<p>Progue is a python tool which allow you to read probe requests from people's devices around you.</p>

<p>After a phase of reading you just have to select which probe request you want to use to create the Rogue AP with the same SSID.  
Choose a probe with a SSID which sounds like there was no authentication (FreeWifi, OpenWifi, etc...) and the client will connect to your AP without even knowing it!</p>

<p>Progue has been tested and works on <strong>Kali Linux</strong>. However it should work on other OSs since you can put your wireless card into monitor mode.</p>


<h3>How it works</h3>

<p>First of all, put your wireless card into monitor mode:</p>
<code>airmon-ng check kill</code>
<p></p>
<code>airmon-ng start wlan0</code>


<p>Progue can work in 2 different modes:</p>

<p>1. With probe reader:</p>

<ol>
<li>Fire up the program with no arguments</li>
<li>Wait for probe requests to arrive</li>
<li>Stop probes reading by "CTRL+C"</li>
<li>Select which # you would like to attack</li>
<li>The Rogue AP is automatically fired up with the name selected/li>
<li>Wait for clients to connect automatically or on prupose!</li>
<li>Open your favorite tools like sslstrip or Wireshark on at0</li>
</ol>



<p>2. Without probe reader:</p>

<ol>
<li>Fire up the program with the argument: "-s SSID_FROM_THE_ROGUE_AP" </li>
<li>The Rogue AP is automatically fired up with the name selected/li>
<li>Wait for clients to connect automatically or on purpose!</li>
<li>Open your favorite tools like sslstrip or Wireshark on at0</li>
</ol>


<p>For some help:</p>

<code>root@name:~/Desktop# ./progue.py --help</code>


<h3>Requirements</h3>

<ul>
<li>1 wireless interface in monitor mode (wlan0mon by default) and 1 interface with internet (eth0 by default)</li>
<li>The following programs installed : python, scapy, aircrack-ng, udhcpd.  
To be sure just perform : <code>apt-get install python scapy aircrack-ng udhcpd</code></li>
</ul>



<h3>License</h3>

<p>Progue is licensed under the GPL license.</p>


<h3>Disclaimer</h3>

<p>This product is meant for educational purposes only.  
This tool is published in good faith and for general information purpose only.  
Progue has been developed in the hope that it will be useful for network administrators, teachers, security consultants/professionals, forensic staff, security software vendors, professional penetration tester and everyone else that plans to use it for ethical reasons.  
The author will not help or support any illegal activity done with this program. Be warned that there is the possibility that you will cause damages and/or loss of data using this software and that in no events shall the author be liable for such damages or loss of data.</p>
