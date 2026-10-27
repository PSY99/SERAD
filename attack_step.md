# Attack Scenarios and Steps

The two scenarios follow the ten attack steps defined in Appendix B.2 of [MuSAR](https://doi.org/10.1109/RAID67961.2025.00038). Its Figure 9 gives the host roles, and Table II summarizes the evidence available for each step. The tables below use the host names in the MHSL records. `user1` and `user2` correspond to `employee-1` and `employee-2` in MuSAR. The timing notes describe the recorded operations within these scenarios.

## Attack Scenario 1

The attacker compromises the web server through ThinkPHP5 and the reverse proxy through unauthorized Redis access. The attacker then explores the internal network, obtains SSH access to `user1`, and retrieves files from `user2` through anonymous FTP.

| Step | Stage | Activity | Hosts |
| --- | --- | --- | --- |
| 1 | Reconnaissance | Scan the portal and reverse proxy with `nmap` and `fscan`. | Portal, reverse proxy |
| 2 | Initial access | Exploit ThinkPHP5 remote code execution to gain a shell. | Web server |
| 3 | Host enumeration | Collect system information from the compromised host. | Web server |
| 4 | Privilege escalation | Use unauthorized Redis access to write an SSH public key to `authorized_keys`. | Reverse proxy |
| 5 | Lateral movement | Access the reverse proxy and collect host information. | Reverse proxy |
| 6 | Persistence | Establish a Metasploit reverse connection and a SOCKS5 tunnel. | Reverse proxy |
| 7 | Network reconnaissance | Scan internal hosts and services. | Reverse proxy, internal hosts |
| 8 | Credential access | Obtain SSH credentials through a brute-force attack. | Reverse proxy, user1 |
| 9 | Lateral movement | Log into `user1` and collect host information. | Reverse proxy, user1 |
| 10 | Data exfiltration | Retrieve sensitive files from `user2` through anonymous FTP. | user1, user2 |

### Recorded operations and times

- **Initial scans:** `nmap` traffic generates `SURICATA STREAM SHUTDOWN RST invalid ack` and `SURICATA STREAM Packet with invalid ack` alarms at **16:20:34**. `fscan` probes occur during **16:22:04–16:22:22**.
- **ThinkPHP5 exploitation:** The web shell is established during **16:23:49–16:29:00**. Information gathering overlaps this period. Commands executed as `www-data` through this shell do not appear in the retained terminal history or authentication logs.
- **Redis access:** Alarms for unauthorized Redis access occur during **16:30:11–16:30:45**.
- **Reverse proxy host enumeration:** Recorded commands occur during **16:31:19–16:32:07**.
- **Reverse connection and proxy deployment:** The payload is uploaded and executed during **16:34:42–16:37:29**. The reverse connection runs during **16:38:01–17:27:46**, with alarms involving port **4444**. Proxy deployment through the Metasploit shell leaves no Bash history. A SOCKS5 communication alarm involves port **1080**.
- **Internal scans:** Port scans occur during **16:43:28–16:43:55**, followed by database credential attempts during **16:45:00–16:46:00**.
- **SSH credential attempts:** Attempts target the database host during **16:47:51–16:49:06**, `user2` during **16:49:16–16:49:26**, and `user1` during **16:49:35–16:49:43**.
- **Access to user1:** Login and host activity occur during **16:50:12–16:52:38** through the reverse proxy.
- **File retrieval:** During **17:13:07–17:14:13**, `user1` retrieves `flag.txt` from `user2` through anonymous FTP. Host command records also describe transferring the file to the reverse proxy with `nc`. In its ground-truth description on p. 337, MuSAR assigns the network signature `ET FTP FTP PWD command attempt without login` to step 10 as evidence of data retrieval from `employee-2`.

## Attack Scenario 2

A phishing payload gives the attacker access to `user2`. The attacker examines the internal network, obtains access to `user1` using exposed key information, and reaches the OA platform. A Struts2 exploit then provides access to the web server, from which the attacker obtains database credentials and sensitive data.

| Step | Stage | Activity | Hosts |
| --- | --- | --- | --- |
| 1 | Initial access | Execute a Metasploit payload delivered through a phishing email and Firefox. | user2 |
| 2 | Persistence | Establish a reverse connection on port **4444** and a SOCKS5 tunnel on port **1234**. | user2 |
| 3 | Network reconnaissance | Scan the internal network through the tunnel. | user2, internal hosts |
| 4 | Host enumeration | Collect sensitive information on the compromised host. | user2 |
| 5 | Lateral movement | Use exposed RSA key information to access `user1`. | user2, user1 |
| 6 | Network evasion | Deploy an additional SOCKS5 tunnel on port **1235**. | user1 |
| 7 | Privilege escalation | Log into the OA platform using the compromised `user1` credentials. | user1, OA platform |
| 8 | Web exploitation | Exploit Struts2 OGNL injection on the web server. | user1, web server |
| 9 | Credential access | Read MySQL credentials from the OA configuration files. | Web server |
| 10 | Data exfiltration | Retrieve sensitive data from the database server. | Web server, database |

### Recorded operations and times

- **Phishing payload:** The attachment is accessed and downloaded during **17:34:38–17:34:41**. Its network alarm records a source address of **34.*.*.*** and source port **443**.
- **Initial reverse connection:** Traffic involving port **4444** occurs during **17:35:50–17:35:52**. The initial SOCKS5 tunnel uses **1234**, as specified in MuSAR.
- **Internal scans:** Activity through the tunnel on `user2` occurs during **17:39:09–17:44:13**.
- **Host enumeration:** Information gathering through the Metasploit shell on `user2` leaves no retained Bash history.
- **Lateral movement:** After examining `.ssh` information, the attacker attempts connections to the database host, web server, and `user1`. Access to `user1` succeeds during **17:46:36–17:48:15**.
- **Additional reverse connection and tunnel:** Payload and proxy activity on `user1` occurs during **17:50:01–18:29:46**. MuSAR assigns the additional SOCKS5 tunnel to port **1235**.
- **Internal scans from user1:** Probes occur during **17:55:14–17:57:28**.
- **Struts2 exploitation:** Scans and attacks against web port **8080** occur during **17:59:35–18:03:46**.
- **Database credential collection:** The web shell reads sensitive files and database configuration during **18:08:42–18:16:16**.
- **Database access:** Queries and data retrieval occur during **18:16:16–18:18:56**.
