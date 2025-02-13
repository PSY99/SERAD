# Attack Scenarios and Step-by-Step Breakdown

We provide a detailed explanation of two designed attack scenarios and their corresponding steps.

---

## **Attack Scenario 1**

The attacker begins by scanning open servers from the Internet, discovering open ports such as 80 and 6379. Upon accessing port 80, they find a website built using ThinkPHP5 and identify an RCE vulnerability through a vulnerability scan. The attacker attempts to gain a reverse shell. After acquiring a shell, they notice an nginx reverse proxy and proceed to examine host configuration files. The attacker leverages an unauthorized Redis access vulnerability on port 6379 to gain control over the nginx server. From there, they attempt lateral movement within the internal network, discovering four hosts. By connecting to the database, they exfiltrate sensitive files. Furthermore, they try to brute-force the password of an internal host (user1), discovering weak credentials. They then download a privilege escalation script, which fails. However, they uncover sensitive files on another internal host (user2) by exploiting anonymous FTP login.


### Step-by-Step Breakdown

| **ID** | **Attack Step** | **Attacker Host** | **Victim Host** | **Inter-/Intra-host** | **Detection** | **Tag ID** |
| :---: | --- | :---: | :---: | :---: | :---: | :---: |
| 1 | The attacker uses `nmap` and `fscan` to scan open ports on the reverse proxy host. | kali (external)<br/>Reverse Proxy (internal) | Reverse Proxy (external)<br/>Web Server (internal) | Inter-host | Detected | 1 |
| 2 | Exploited the ThinkPHP5 vulnerability to gain a shell on the web host. | Reverse Proxy (internal) | Web Server (internal) | Inter-host | Detected | 2 |
| 3 | Collected host information and sensitive files from the web server. | kali/Reverse Proxy | Web Server | Intra-host | Limited detection of sensitive file access between hosts. Commands executed as `www-data`, no terminal logs. | 3 |
| 4 | Wrote an SSH public key to Redis via unauthorized access. | kali | Reverse Proxy | Inter-host | Detected | 4 |
| 5 | Lateral movement and host information collection. | kali | Reverse Proxy | Intra-host | Detected | 5 |
| 6 | Uploaded MSF backdoor and configured a SOCKS5 proxy tunnel. | kali | Reverse Proxy | Inter-host & Intra-host | Detected | 6 |
| 7 | Scanned internal hosts for availability and vulnerabilities. | Reverse Proxy | Web/Database/User1/User2 | Inter-host | Detected | 7 |
| 8 | Performed SSH brute force attack. | Reverse Proxy | User1 | Inter-host | Detected | 8 |
| 9 | Lateral movement and host information collection. | Reverse Proxy | User1 | Inter-host & Intra-host | Detected | 9 |
| 10 | Logged in anonymously to FTP and stole sensitive data. | User2 | User5 | Inter-host & Intra-host | FTP detected, data exfiltration less obvious between hosts but supplemented by intra-host evidence. | 10 |

+ In **Step 1**, `nmap` scan traffic was detected as **SURICATA STREAM SHUTDOWN RST invalid ack** and **SURICATA STREAM Packet with invalid ack**. The timestamp was **16:20:34**.
+ In **Step 1**, `fscan` vulnerability scanning occurred between **16:22:04~16:22:22**. Internal network alerts showed fingerprints of a large number of CVE vulnerability probes.
+ In **Step 2**, the shell was established between **16:23:49~16:29:00**, and it was successfully detected within the internal network.
+ **Step 3** overlapped with Step 2 in terms of timing, but due to the commands being executed by the `www-data` user and the unique shell type, no terminal command logs or `auth.log` login records were found on the web server.
+ In **Step 4**, unauthorized access to Redis was detected, with the alert timestamped between **16:30:11~16:30:45**.
+ **Step 5** occurred between **16:31:19~16:32:07**.
+ In **Step 6**, the backdoor was uploaded and executed within the host between **16:34:42~16:37:29**, while the inter-host shell connection was established between **16:38:01~17:27:46**. The primary backdoor continuously generated traffic during execution, all flagged as alerts involving port **4444** from the attacker host to the reverse proxy.
+ In **Step 7**, the upload and execution of the reverse proxy tool were entirely performed via the `msf` shell. No `bash` traces were left on the reverse proxy server. Network traffic primarily consisted of reverse control traffic on port **4444**, and one SOCKS5 communication alert was detected on port **1080**.
+ **Step 8** included numerous scanning alerts, such as internal host availability scans, internal port scans, SSH brute force attempts, and database connection attempts. The port scanning occurred between **16:43:28~16:43:55**, and weak credential attempts for database connections occurred between **16:45:00~16:46:00**.
+ In **Step 9**, SSH brute force attempts on the database host occurred between **16:47:51~16:49:06**, on the `user2` host between **16:49:16~16:49:26**, and on the `user1` host between **16:49:35~16:49:43**.
+ In **Steps 10~12**, the attacker logged into `user1` via the reverse proxy host. The alerts matched the fingerprints generated during brute-force attempts, and the activity occurred between **16:50:12~16:52:38**.
+ In **Step 11**, the attacker anonymously logged into `user2`'s FTP server via `user1` and retrieved the `flag.txt` file, transferring it to the reverse proxy server. This activity occurred between **17:13:07~17:14:13**. **No FTP alert fingerprints were detected**.  
  **<font style="color:#DF2A3F;">The data transfer from `user1` to the reverse proxy server via `nc` showed no obvious network traffic characteristics and was marked as low risk. However, host-side command logs can assist in detection.</font>**


## Attack Scenario 2

The attacker creates a phishing payload and tricks an internal user (user2) into downloading and executing it. The attacker gains shell access to user2. Upon scanning, the attacker finds four additional hosts in the network segment but discovers no exploitable vulnerabilities. However, they find records in the `known_hosts` file on user2 and attempt lateral movement using the same username, successfully logging into user1 and gaining its shell. Using user1, the attacker scans the network and finds that port 8080 on 192.168.9.103, previously closed, is now open. Fingerprinting identifies it as a Struts system, and the attacker successfully exploits RCE to gain a reverse shell. Through information gathering on the host, they discover database connection details and attempt to access the database contents.

---

### Step-by-Step Breakdown

| **ID** | **Attack Step** | **Attacker Host** | **Victim Host** | **Inter-/Intra-host** | **Detected** | **Tag ID** |
| :---: | --- | :---: | :---: | :---: | :---: | :---: |
| 1 | Simulated phishing attack. User downloads and executes the malicious tool via Firefox, gaining MSF access. | kali | user2 | Inter-/Intra-host | Detected | 1 |
| 2 | User connects to MSF and establishes a SOCKS5 communication tunnel on port 1234. | kali | user2 | Inter-host | Detected | 2 |
| 3 | The attacker scans the internal network using user2, probing for open ports and vulnerabilities. | user2 | web/database/reverseProxy/user2 | Inter-host | Detected | 3 |
| 4 | Information gathering on user2's host. | kali | user2 | Intra-host | Not detected | 4 |
| 5 | The attacker finds user1's key information through host data collection and attempts lateral movement. | user2 | web/database/user2 | Inter-/Intra-host | Partially detected (Inter-host only) | 5 |
| 6 | The attacker moves laterally to user1, connects to MSF, and establishes a SOCKS5 tunnel on port 1235. | kali | user1 | Inter-/Intra-host | Partially detected (MSF traffic detected on inter-host level) | 6 |
| 7 | The attacker scans the web server using user1's host. | user1 | web | Inter-host | Detected | 7 |
| 8 | Scans and exploits Struts2 vulnerabilities. | user1 | web | Inter-host | Detected | 8 |
| 9 | The attacker collects sensitive information from the web server's shell and discovers database configuration details. | user1 | web | Intra-host | Partially detected (minimal inter-host detection) | 9 |
| 10 | The attacker uses the web server's shell to read sensitive information from the database host. | web | database | Inter-/Intra-host | Partially detected | 10 |


+ **Step 1:** The phishing email was accessed, and the attachment was downloaded between **17:34:38~17:34:41**. The alert source IP was **34.*.*.***, and the source port was **443**.
+ **Step 2:** Traffic involving source/destination port **4444** was detected between **17:35:50~17:35:52**. Two SOCKS5 traffic alerts were detected on source/destination port **1235**, but the fingerprint was **ET POLICY Reserved Internal IP Traffic**, making identification difficult.
+ **Step 3:** The attacker used the SOCKS5 tunnel established on user2 to scan the internal network, probing for open ports and vulnerabilities. The activity occurred between **17:39:09~17:44:13**.
+ **Step 4:** The attacker used MSF's shell for intra-host information gathering on user2. No logs were recorded in `bash` commands on user2.
+ **Step 5:** The attacker discovered the `known_hosts` file on user2 and attempted to laterally move to `database`, `web`, and `user1`. Lateral movement to user1 was successful between **17:46:36~17:48:15**.
+ **Step 6:** The attacker moved laterally to user1 using MSF's shell, uploading payloads and proxy tools. No host-side logs were left, but MSF traffic was partially detected. The activity occurred between **17:50:01~18:29:46**. One SOCKS5 traffic alert was detected, but it was difficult to differentiate.
+ **Step 7:** The attacker scanned the internal network using user1's host to probe open ports, which occurred between **17:55:14~17:57:28**.
+ **Step 8:** The attacker conducted Struts2 vulnerability scans and attacks on the web server's port 8080 between **17:59:35~18:03:46**.
+ **Step 9:** The attacker collected sensitive file data from the web server's shell and discovered the database configuration file between **18:08:42~18:16:16**.
+ **Step 10:** The attacker used the web server's shell to query and retrieve sensitive information from the database host between **18:16:16~18:18:56**.