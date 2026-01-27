# Logs: Foundation of Security Monitoring

## What Are Logs?

Logs are records of events that occur within systems, applications, networks, and security devices. They provide a chronological trail of activities, making them essential for security monitoring, incident investigation, troubleshooting, and compliance.

## Why Logs Matter in Security

Logs are the **primary source of truth** for security analysts. They enable:
- **Threat Detection:** Identifying malicious activities and anomalies
- **Incident Response:** Understanding what happened during a security incident
- **Forensic Analysis:** Reconstructing attack timelines
- **Compliance:** Meeting regulatory requirements (GDPR, PCI-DSS, HIPAA)
- **Baseline Establishment:** Understanding normal system behavior
- **Audit Trails:** Tracking user actions and system changes

> "Without logs, you're flying blind in security operations."

## Types of Logs

### 1. Operating System Logs

#### Windows Event Logs
- **Security Logs:** Login attempts, privilege escalations, file access
- **System Logs:** System errors, driver failures, service status changes
- **Application Logs:** Application-specific events and errors

**Key Windows Event IDs:**
- `4624` - Successful logon
- `4625` - Failed logon attempt
- `4672` - Special privileges assigned to new logon
- `4688` - New process created
- `4689` - Process terminated
- `4720` - User account created
- `4732` - Member added to security-enabled local group
- `4756` - Member added to security-enabled universal group

#### Linux/Unix Logs
- **auth.log / secure:** Authentication attempts and sudo usage
- **syslog:** General system messages
- **kern.log:** Kernel messages
- **boot.log:** System boot messages
- **cron.log:** Scheduled task execution

**Common Locations:**
- `/var/log/auth.log` - Authentication logs (Debian/Ubuntu)
- `/var/log/secure` - Authentication logs (RedHat/CentOS)
- `/var/log/syslog` - System logs
- `/var/log/messages` - General messages

### 2. Network Logs

#### Firewall Logs
- Connection attempts (allowed/blocked)
- Source and destination IP addresses and ports
- Protocol information
- Packet counts and byte transfers

#### Proxy Logs
- Web traffic (URLs accessed)
- User identification
- Content types downloaded
- Response codes

#### VPN Logs
- Connection/disconnection events
- User authentication
- IP assignments
- Session duration

#### DNS Logs
- Domain name queries
- Query responses
- Client IP addresses
- Potential data exfiltration indicators

### 3. Application Logs

#### Web Server Logs
- **Access Logs:** HTTP requests, response codes, user agents
- **Error Logs:** Server errors, failed requests

**Example Apache Access Log:**
```
192.168.1.100 - - [28/Jan/2026:10:15:30 +0000] "GET /admin/login.php HTTP/1.1" 200 1234 "Mozilla/5.0..."
```

#### Database Logs
- Query execution
- Login attempts
- Schema changes
- Failed transactions

#### Email Logs
- Sent/received messages
- Spam filter actions
- Attachment information
- SMTP conversations

### 4. Security Device Logs

#### Intrusion Detection/Prevention Systems (IDS/IPS)
- Signature-based detections
- Anomaly detections
- Blocked attacks
- Network traffic patterns

#### Endpoint Detection and Response (EDR)
- Process execution
- File modifications
- Registry changes
- Network connections
- Suspicious behaviors

#### Antivirus/Anti-Malware
- Malware detections
- Quarantined files
- Scan results
- Update status

## Log Formats

### Common Log Formats

#### 1. Syslog
Industry-standard protocol for message logging.

**Format:**
```
<Priority> Timestamp Hostname Application[PID]: Message
```

**Example:**
```
<34>Jan 28 10:15:30 webserver nginx[1234]: Connection refused from 192.168.1.50
```

#### 2. JSON (JavaScript Object Notation)
Structured, machine-readable format.

**Example:**
```json
{
  "timestamp": "2026-01-28T10:15:30Z",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.50",
  "action": "blocked",
  "protocol": "TCP",
  "port": 445
}
```

#### 3. CEF (Common Event Format)
ArcSight standard format.

**Format:**
```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

#### 4. W3C Extended Log Format
Used by IIS and other web servers.

**Example:**
```
#Fields: date time c-ip cs-method cs-uri-stem sc-status
2026-01-28 10:15:30 192.168.1.100 GET /index.html 200
```

## Log Analysis Fundamentals

### What to Look For

#### 1. Authentication Events
- **Failed login attempts** - Potential brute force attacks
- **Successful logins from unusual locations** - Account compromise
- **Login outside business hours** - Insider threat or compromised account
- **Multiple failed then successful login** - Successful brute force

#### 2. Privilege Escalation
- Users gaining administrative rights
- Service account privilege changes
- Sudo usage patterns
- UAC prompts and bypasses

#### 3. File and System Changes
- Unauthorized file modifications
- New file creations in system directories
- Registry modifications (Windows)
- Configuration changes

#### 4. Network Anomalies
- Connections to suspicious IP addresses
- Unusual port usage
- Large data transfers (potential exfiltration)
- DNS queries to malicious domains
- Beaconing patterns (regular C2 communication)

#### 5. Process Activity
- New process creation
- Unusual parent-child process relationships
- Execution from temporary directories
- PowerShell/command line executions with suspicious parameters

### Log Analysis Techniques

#### 1. Baseline Analysis
Establish what "normal" looks like:
- Typical login times
- Standard network traffic patterns
- Normal process execution
- Regular application behavior

#### 2. Correlation
Connect related events across multiple sources:
- Failed login → Successful login → Privilege escalation → File access
- DNS query → HTTP connection → Data transfer
- Email received → Process execution → Network connection

#### 3. Anomaly Detection
Identify deviations from baseline:
- Login from new geographic location
- Unusual time of activity
- Abnormal data volume
- Unexpected protocol usage

#### 4. Threat Hunting
Proactively search for indicators of compromise:
- Known malicious IP addresses
- Suspicious file hashes
- Command patterns associated with malware
- Lateral movement indicators

## Common Log Analysis Challenges

### 1. Volume
**Challenge:** Millions of log entries generated daily  
**Solution:**
- Use SIEM for aggregation and filtering
- Implement log retention policies
- Focus on high-value logs
- Use automated parsing and normalization

### 2. Format Inconsistency
**Challenge:** Different systems use different log formats  
**Solution:**
- Normalize logs into common format
- Use log parsers (Logstash, Fluentd)
- Create parsing rules in SIEM
- Standardize logging configurations where possible

### 3. Noise and False Positives
**Challenge:** Legitimate activity triggering alerts  
**Solution:**
- Tune detection rules
- Implement whitelisting for known-good activity
- Use context-aware alerting
- Regular rule review and optimization

### 4. Incomplete Logging
**Challenge:** Missing critical log sources  
**Solution:**
- Conduct log coverage assessment
- Enable comprehensive logging on critical systems
- Ensure clock synchronization (NTP)
- Implement centralized log collection

## Log Collection Best Practices

### 1. Comprehensive Coverage
- Enable logging on all critical systems
- Include workstations, servers, network devices, and security tools
- Don't forget cloud services and SaaS applications

### 2. Centralized Collection
- Forward logs to central SIEM or log management platform
- Ensure reliable log transmission
- Implement redundancy for critical logs

### 3. Time Synchronization
- Use NTP (Network Time Protocol)
- Ensure all systems use same time source
- Critical for accurate event correlation

### 4. Log Retention
- Define retention periods based on compliance requirements
- Balance storage costs with investigation needs
- Typical retention: 90 days hot storage, 1+ year cold storage

### 5. Log Integrity
- Protect logs from tampering
- Implement access controls
- Consider write-once storage for critical logs
- Use log signing where possible

## Hands-On: Reading Common Logs

### Windows Security Event Log

**Event 4625 - Failed Logon:**
```
Log Name: Security
Event ID: 4625
Level: Information
Keywords: Audit Failure
User: N/A
Computer: WORKSTATION01
Description: An account failed to log on.

Subject:
    Security ID: NULL SID
    Account Name: -
    
Logon Type: 3 (Network)

Account For Which Logon Failed:
    Account Name: admin
    Account Domain: COMPANY
    
Failure Information:
    Failure Reason: Unknown user name or bad password
    Status: 0xC000006D
    Sub Status: 0xC000006A
    
Network Information:
    Workstation Name: ATTACKER-PC
    Source Network Address: 192.168.1.50
```

**Analysis:**
- Logon Type 3 = Network logon (SMB, RDP, etc.)
- Status code indicates bad password
- Source IP 192.168.1.50 attempting to access WORKSTATION01
- Multiple of these = potential brute force attack

### Linux Auth Log

```
Jan 28 10:15:30 webserver sshd[12345]: Failed password for root from 203.0.113.50 port 48520 ssh2
Jan 28 10:15:32 webserver sshd[12346]: Failed password for root from 203.0.113.50 port 48521 ssh2
Jan 28 10:15:35 webserver sshd[12347]: Failed password for admin from 203.0.113.50 port 48522 ssh2
Jan 28 10:15:38 webserver sshd[12348]: Accepted password for admin from 203.0.113.50 port 48523 ssh2
```

**Analysis:**
- Multiple failed SSH login attempts from same IP
- Pattern indicates brute force attack
- Final successful login suggests compromise
- **Action Required:** Investigate admin account activity, check for lateral movement

### Apache Access Log

```
192.168.1.100 - - [28/Jan/2026:10:15:30 +0000] "GET /admin/../../etc/passwd HTTP/1.1" 404 286
192.168.1.100 - - [28/Jan/2026:10:15:31 +0000] "GET /admin/../../../windows/system32/config/sam HTTP/1.1" 404 286
192.168.1.100 - - [28/Jan/2026:10:15:32 +0000] "POST /login.php?id=1' OR '1'='1 HTTP/1.1" 200 1542
```

**Analysis:**
- Directory traversal attempts (../)
- SQL injection attempt in POST request
- Response code 200 on SQL injection = potential vulnerability
- **Action Required:** Block source IP, investigate application vulnerability

## Tools for Log Analysis

### Command Line Tools

#### Linux/Unix
```bash
# Search for failed SSH logins
grep "Failed password" /var/log/auth.log

# Count failed login attempts by IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

# View logs in real-time
tail -f /var/log/syslog

# Search for specific error
journalctl -u nginx --since "1 hour ago" | grep ERROR
```

#### Windows PowerShell
```powershell
# Get failed logon events from last 24 hours
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)}

# Count failed logons by source IP
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | 
    Select-Object -ExpandProperty Properties | 
    Group-Object {$_[19].Value} | 
    Sort-Object Count -Descending

# Export security events to CSV
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} | 
    Export-Csv -Path "C:\logs\security_events.csv"
```

### SIEM Platforms
- **Splunk:** SPL (Search Processing Language)
- **Elastic Stack:** Elasticsearch Query DSL, KQL (Kibana Query Language)
- **QRadar:** AQL (Ariel Query Language)
- **Microsoft Sentinel:** KQL (Kusto Query Language)

## Key Takeaways

1. **Logs are essential** for security monitoring and incident investigation
2. **Multiple log sources** must be collected and correlated
3. **Understanding log formats** is crucial for effective analysis
4. **Baseline knowledge** helps identify anomalies and threats
5. **Time synchronization** is critical for accurate correlation
6. **Centralized collection** in SIEM enables efficient analysis
7. **Context matters** - single events may be benign, patterns indicate threats
8. **Regular review** and tuning reduce false positives



---

**Date Completed:** 27/01/2026  
**Time Spent:** 2 Hours  
**Key Skills Developed:** Log interpretation, event correlation, anomaly detection  
**Next Focus:** SIEM workflow and alert investigation