import re
import bashlex

# The Parse_cmd class is designed to analyze and parse command-line commands,
# extract critical information (e.g., command type, arguments, sensitive operations),
# and classify commands based on their purpose or potential risk level.
class Parse_cmd():
    """
    The following command has been pre parsed:
    useful_command = ["ssh", "sshuttle", "nmap", "apt", "apt-get", "docker", "curl", "vim", "cat", "sed", "dpkg", "wget", "mv", "mkdir", "python", "./", "john", "nc", "ping", "crackmapexec", "dirb", "mongo", "bsondump", "gcc", "locate", "nano", "chmod", "find", "brew", "rm", "bash", "su", "ping", "git"]
    """
    def __init__(self, cmd):
        self.command, self.parsed_args = self.parse_bash_command(cmd)
        self.sensitive = self.is_sensitive_operations(self.command)
        if "sudo" in cmd:
            self.sensitive = "Privilege Escalation Attacks"
        self.dip = ""
        self.dport = ""
        if self.command == "ssh":
            self.entity = self.parse_ssh(cmd)
        elif self.command == "sshuttle":
            self.entity, self.dip = self.parse_sshuttle(cmd)
        elif self.command == "nmap":
            self.entity = self.parse_nmap()
        elif self.command == "apt" or self.command == "apt-get":
            self.entity = self.parse_apt(cmd)
        elif self.command == "docker":
            self.entity = self.parse_docker(cmd)
        elif self.command == "curl" or self.command == "dirb":
            self.entity = self.parse_web(cmd)
            if self.dport == "":
                if "https" in cmd:
                    self.dport = "443"
                elif "http" in cmd:
                    self.dport = "80"
                elif "ftp" in cmd:
                    self.dport = "21"
        elif self.command == "wget":
            self.entity = self.parse_wget(cmd)
        elif self.command == "mv":
            self.entity = self.parse_mv(cmd)
        elif self.command == "python" or self.command == "python3":
            self.entity = self.parse_python(cmd)
        elif self.command[:2] == "./":
            if cmd[:4] != "sudo":
                self.entity = self.parse_app(cmd[2:])
            else:
                self.entity = self.parse_app(cmd.split(" ")[1][2:])
        elif self.command == "nc" or self.command == "telnet":
            self.entity = self.parse_nc_telnet(cmd)
        elif self.command == "git":
            self.entity = self.parse_git(cmd)
        else:
            self.entity = []
            for arg in self.parsed_args:
                if arg[1] in [None, "|", "grep", ">", "<", ">>", "<<"]:
                    continue
                self.entity.append(arg[1])
            pattern = r"((?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b)"
            match = re.findall(pattern, cmd)
            if match:
                if len((match[0].split(":"))) > 1:
                    self.dip = match[0].split(":")[0]
                    self.dport = match[0].split(":")[1]
                else:
                    self.dip = match[0].split(":")[0]

    def parse_bash_command(self, cmd):
        pattern = re.compile(r'^(--?\w+)(=.+)?')
        parts = list(bashlex.split(cmd))
        command = parts[0]
        if command == 'sudo' and len(parts) > 1:
            command = parts[1]
            args = parts[2:]
        else:
            args = parts[1:]

        parsed_args = []
        none_flag = 1
        i = 0
        while i < len(args):
            arg = args[i]
            matches = pattern.findall(arg)
            if matches:
                option = matches[0][0]
                if matches[0][1]:  # process parameters like -- option=value
                    param = matches[0][1].strip('=')
                    parsed_args.append((option, param))
                    i += 1
                elif i+1 < len(args) and not re.match(pattern, args[i+1]): 
                    param = args[i+1]
                    parsed_args.append((option, param))
                    i += 2
                else:
                    parsed_args.append((option, None)) # Handling situations without parameters, such as the command 'ls - l'
                    i += 1
            else:  # Processing parameters without obvious command line parameter prefixes
                parsed_args.append((none_flag, arg))
                none_flag += 1
                i += 1

        return command, parsed_args
    
    def parse_ssh(self, ssh_command):
        pattern = r"ssh\s+(?:([^\s@]+)@)?(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"
        entity_list = None

        match = re.search(pattern, ssh_command)
        if match:
            username = match.group(1)
            self.dip = match.group(2)
            entity_list = [username, self.dip]

            for arg in self.parsed_args:
                if arg[1] in [None, "|", "grep", ">", "<", ">>", "<<"]:
                    continue
                if len(str(arg[0])) < 2:
                    continue
                if arg[0][:2] == '-p':
                    if len(arg[0]) > 2:
                        self.dport = arg[0][2:]
                    else:
                        self.dport = arg[1]
            if not self.dport:
                self.dport = "22"

        return entity_list
    
    def parse_sshuttle(self, sshuttle_command):
        pattern = r"\s-r\s+(?:([^\s@]+)@)?(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"
        match = re.search(pattern, sshuttle_command)
        entity_list = []
        if match:
            username = match.group(1)
            ip_address = match.group(2)
            if username:
                entity_list.append(username)
            entity_list.append(ip_address)
            return entity_list, ip_address
        else:
            return None, None
        
    
    def parse_nmap(self):
        entity_list = []
        pattern = r"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b)"

        for arg in self.parsed_args:
            if arg[1] in [None, "|", "grep", ">", "<", ">>", "<<"]:
                continue
            # print(arg[1])
            entity_list.append(arg[1])
            # print(entity_list)
            
            match = re.search(pattern, arg[1])
            if match:
                self.dip = match.group(1)
            if type(arg[0]) == int:
                continue
            if arg[0][:2] == '-p':
                if len(arg[0]) > 2:
                    self.dport = arg[0][2:]
                else:
                    self.dport = arg[1]

        return entity_list
    
    def parse_apt(self, apt_command):
        pattern = r"\s+install\s+(.+)"
        match = re.search(pattern, apt_command)
        if match:
            return match.group(1).split()
        else:
            return None
    
    def parse_docker(self, docker_command):
        entity_list = []
        for arg in self.parsed_args[1:]:
            if arg[1] == None or "bash" in arg[1]:
                continue
            entity_list.append(arg[1])
        return entity_list
    
    def parse_web(self, web_command):
        # curl, dirb
        pattern = r"((?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b)"
        match = re.findall(pattern, web_command)
        if match:
            if len((match[0].split(":"))) > 1:
                self.dip = match[0].split(":")[0]
                self.dport = match[0].split(":")[1]
            else:
                self.dip = match[0].split(":")[0]
            return match
        else:
            pattern1 = r"\s+(http(?:s)?://[^\s]+)"
            links = re.findall(pattern1, web_command)
            return links
    
    def parse_wget(self, wget_command):
        # Regular expression matches the last file name of the link
        pattern = r"/([^/\s]*)(?=\s|$)"

        # 使用 search 方法寻找匹配的字符串
        match = re.findall(pattern, wget_command)
        if match:
            return match
        else:
            return None
        
    def parse_mv(self, mv_command):
        # Match the source and target files of the mv command using regular expressions
        pattern = r"mv\s+(.*?)\s+(.*)"

        # Using the search method to find matching strings
        match = re.search(pattern, mv_command)
        if match:
            return [match.group(1), match.group(2)]
        else:
            return None
        
    def parse_python(self, python_command):
        # python, python3
        pattern = r"\s(.*\.py)"
        match = re.findall(pattern, python_command)
        if match:
            return match
        else:
            return None
        
    def parse_app(self, app_command):
        # ./****
        word = app_command.split(" ")
        entity_list = []
        for word_i in word:
            if word_i[0] != '-':
                entity_list.append(word_i)
        return entity_list
    
    def parse_nc_telnet(self, nc_command):
        # nc, telnet
        pattern = r"((?:[0-9]{1,3}\.){3}[0-9]{1,3})(\s[0-9]{1,5})?\b"
        match = re.search(pattern, nc_command)
        if match:
            self.dip = match.group(1)
            self.dport = match.group(2)
            return [match.group(1), match.group(2)]
        else:
            return None

    def parse_git(self, git_command):
        # Regular expression matching git clone command
        pattern = r"git(?:\s+)clone(?:\s+)https://github.com/\w+/([\w-]+)(?:\.git)?(\s+(.*))?"

        match = re.search(pattern, git_command)
        if match:
            project = match.group(1)
            path = match.group(3) if match.group(3) else None
            return [project, path]
        else:
            return None
        
    def has_word_invalid(self, input_string):
        invalid_cmd = ["ls", "cd", "clear", "l", "top", ]
        for i in invalid_cmd:
            pattern = r'\b{}\b'.format(i)
            match = re.search(pattern, input_string)
            if bool(match):
                return True
        return False


    def is_sensitive_operations(self, cmd_keyword):
        sensitive_operations = {
            "Privilege Escalation": ["sudo", "su", "chmod", "chown"],
            "Identity Theft and Key Access": ["ssh-keygen", "ssh-add", "ssh-copy-id"],
            "Remote Execution and Lateral Movement": ["ssh", "nc", "scp"],
            "Data Exfiltration": ["mysql", "mysqladmin", "bsondump", "mongo", "mongodump"],
            "File and Directory Exploration": ["find", "locate"],
            "Process Monitoring and Manipulation": ["ps", "top", "kill", "pkill", "pgrep"],
            "Network Reconnaissance and Scanning": ["nmap", "tcpdump", "netstat", "arp", "nmcli", "ss", "nc", "telnet"],
            "Virus and Malware Deployment": ["wget", "curl"],
            "System and Service Tampering": ["systemctl", "init", "systemd", "service", "reboot"],
            "Catalog Explosion": ["dirb", "ffuf", "dirsearch"],
            "Vulnerability Scanning": ["msfconsole", "crackmapexec", "nikto", "openvas", "openvas-start", "openvas-stop", "openvas-setup", "enum4linux"],
            "Password Cracking": ["john"],
        }
        for key, value in sensitive_operations.items():
            if cmd_keyword in value:
                return key
        return None


def classify_cmd(command):
    bash_commands = {
        "File Operations": ["ls", "cd", "pwd", "touch", "cp", "mv", "rm", "find", "cat", "more", "less", "head", "tail", "ln", "file", "locate", "l", "mkdir"],
        "Text Processing": ["grep", "awk", "sed", "cut", "sort", "wc", "uniq", "tr", "strings", "diff", "patch", "nano", "vim"],
        "Process Management": ["ps", "top", "htop", "kill", "pkill", "pgrep", "nice", "renice", "jobs"],
        "Networking": ["ping", "netstat", "nslookup", "dig", "traceroute", "wget", "curl", "ssh", "ifconfig", "nmap", "arp", "nmcli", "ss", "nc", "./onetwopunch.sh", "telnet", "sshuttle", "openssl"],
        "File Permissions": ["chmod", "chown", "chgrp", "umask"],
        "Archiving and Compression": ["tar", "gzip", "gunzip", "bzip2", "unzip"],
        "Disk Usage": ["df", "du", "fdisk", "fsck", "dir", "mount"],
        "System Information": ["uname", "hostname", "dmesg", "uptime", "free", "who", "id", "last", "whoami", "w", "history", "lsof", "tcpdump", "ps"],
        "Environment Variables": ["export", "set", "unset", "source"],
        "Programming": ["python", "perl", "ruby", "gcc", "make", "python3"],
        "Package Management": ["apt-get", "yum", "dnf", "zypper", "pacman", "apt", "brew", "dpkg", "pip", "pip3", "conda", "add-apt-repository"],
        "Database Operations": ["mysql", "mysqladmin", "bsondump", "mongo", "mongodump"],
        "User Management": ["su", "groups", "passwd"],
        "Command Execution": ["bash", "/bin/sh"],
        "Help and Documentation": ["man"],
        "Git Operations": ["git"],
        "Docker Operations": ["docker"],
        "Miscellaneous": ["which", "login", "shutdown", "busybox", "fgconsole", "wall", "vncserver", "screen", "firefox", "doveadm", "vnc4server"],
        "System Management": ["systemctl", "init", "systemd", "service", "reboot"],
        "Catalog Explosion": ["dirb", "ffuf", "dirsearch"], 
        "Vulnerability Scanning": ["msfconsole", "crackmapexec", "nikto", "openvas", "openvas-start", "openvas-stop", "openvas-setup", "enum4linux"],
        "Password Cracking": ["john"],
        "Invalid": ["clear"],
        "Finish Session": ["exit"]
    }

    for key, value in bash_commands.items():
        if command in value:
            return key
    return "unknown"


def split_operaters(cmd):
    separators = ['&&', '\|\|']
    separator_regex = '|'.join(r'\s*{}\s*'.format(separator) for separator in separators)
    parts = re.split(separator_regex, cmd)
    return parts

if __name__ == '__main__':
    # command, args = parse_bash_command("sudo vim sda")
    # print(classify_cmd(command))
    # print(Parse_cmd.parse_bash_command("cat -t -a 153"))
    cmd = "wget http://10.208.104.73:40000/dirty.c"
    a = Parse_cmd(cmd)
    print(a.command, a.parsed_args, a.entity, a.dip, a.dport, a.sensitive)

    