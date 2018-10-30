# expiring_certificates_discovery
A script to discover and alert on expiring digital certificates in the network

### What is this?
This is a simple utility to discover expiring digital certificates and alert stakeholders.<br>It practically does the following:
1. Identifies all IP addresses in the host server's network (subnet)
2. Probes these IP addresses and determines servers that are alive
3. If the server is a Windows host, queries its certificate stores and gets details on all installed digital certificates
4. Inspects certificates and determines if they are about to expire
5. Generates an HTML report showing expiring certificates
6. Sends HTML report as inline email to intended recipients

### Why did I make this?
Digital (X.509) certificates are commonplace in environments that does a lot of web hosting or certificate-based authentication to access resources. Oftentimes, having certificates expire are business disruptive, so avoiding such occurences gives great value to the organization. 

### Requiremenets
1. PowerShell 2.0 and .Net Framework 2.0+
2. Only supports Windows OS, with version at least 2008 R2 (with limited support for 2008 and 2003)
3. Certificates must be installed in any of the Windows certificate stores (i.e. Local Machine\ Trusted Root Certificate Authority)
4. A working Smtp smart host that does not require authentication

### How do I use this?
1. Check `config.ini` and ensure that it is populated with the appropraite values
2. Optionally add a logo or icon in `/img/logo.png` to include in the header of the Html report
3. Run the script, or schedule as needed. Make sure the user executing the script has appropraite privileges on the target systems. By default, it should either be a local administrator on the target systems (should be avoided) or a domain administrator. <i>Feel free to experiment on permission delegation to see what minimum privileges are required.</i>

<b>CAUTION:</b> This script heavily uses `WMI`. Windows PowerShell remoting (WinRM) was not quite popular back then and usually disabled on most systems. Nowadays, most organization would probably block, limit, or monitor remote WMI events since this protocol is often used by malware. Ideally, WMI calls should be replaced by WinRM calls if feasible for the organization (`Invoke-WmiMethod` replaced by `Invoke-Command`, etc.) and the script adjusted accordingly.<br><br>
This script is a quick hack to avoid firewall restrictions, so it only "scans" hosts within the hosts' subnet in the specified network interface. An improvement could be to be able to do <i>ad hoc</i> scans on arbitrary networks.<br><br>
This script only checks a specific user specified certificate issuer (in `config.ini`). This is because there are usually a lot of default certificates in the certificate stores, and we want to ensure that the script only queries those that are relevant.
