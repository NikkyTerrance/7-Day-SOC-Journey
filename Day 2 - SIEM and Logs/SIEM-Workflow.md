# SIEM Workflow: From Alert to Resolution

## The SOC Analyst's Investigation Workflow

The SIEM workflow is the systematic process SOC analysts follow when investigating security alerts. This structured approach ensures thorough investigation, proper documentation, and efficient incident response.

## Overview of the SIEM Workflow

```
Alert Generated → Triage → Investigation → Containment → Documentation → Closure
       ↓             ↓           ↓              ↓              ↓            ↓
   Detection    Prioritize   Analyze       Respond        Record      Lessons
   via SIEM     & Assign     Evidence      to Threat      Findings    Learned
```

## Phase 1: Alert Generation and Detection

### How Alerts Are Generated

#### 1. Rule-Based Detection
Predefined correlation rules trigger alerts:
```
Rule: Brute Force Login Attack
IF failed_login_count >= 10
AND time_window <= 300 seconds
AND same_username AND same_source_ip
THEN CREATE ALERT with Priority = HIGH
```

#### 2. Anomaly Detection
Machine learning identifies deviations from baseline:
- User accessing 1000 files when baseline is 50/day
- Login from new geographic location
- Network traffic spike to unusual destination

#### 3. Threat Intelligence Matching
Known indicators of compromise (IOCs) trigger alerts:
- Connection to known C2 server IP
- File hash matches known malware
- Domain matches threat feed

#### 4. Behavioral Analytics
User and Entity Behavior Analytics (UEBA):
- Privilege escalation outside normal pattern
- Unusual application usage
- Peer group deviation

### Alert Components

Every SIEM alert should contain:
- **Alert Name/Title:** Brief description of the detection
- **Severity:** Critical, High, Medium, Low, Informational
- **Timestamp:** When the alert was generated
- **Triggering Events:** Raw logs that caused the alert
- **Source Information:** IP addresses, hostnames, users involved
- **Detection Logic:** What rule or condition triggered the alert
- **Context:** Asset criticality, user role, threat intelligence
- **Recommended Actions:** Initial response steps

## Phase 2: Alert Triage

### What is Triage?

**Triage** is the process of quickly assessing incoming alerts to determine:
1. Is this a true positive or false positive?
2. What is the severity and urgency?
3. What is the potential impact?
4. Who should investigate it?
5. What is the priority compared to other alerts?

### Triage Steps

#### Step 1: Initial Assessment (2-5 minutes)

**Questions to Ask:**
- What type of alert is this?
- What system/user is involved?
- When did it occur?
- Is the asset critical to the business?
- Have we seen this before?

**Quick Checks:**
- Review alert description and severity
- Check if system is active/production
- Verify if user account is valid
- Look for similar recent alerts

#### Step 2: Context Gathering

**Asset Context:**
- Is this a production server or test system?
- What is the asset criticality? (Critical/High/Medium/Low)
- What data does it store/process?
- Who owns/manages this system?

**User Context:**
- Is this user account active?
- What is user's role and access level?
- Is this behavior typical for this user?
- Recent HR changes (resignation, termination)?

**Threat Intelligence:**
- Is the IP address known malicious?
- Does the domain appear in threat feeds?
- Is the file hash associated with malware?
- Recent campaigns targeting similar vectors?

#### Step 3: Initial Classification

**True Positive:** Confirmed malicious or policy-violating activity
- Indicators align with known attack patterns
- Multiple suspicious indicators present
- Activity violates security policies
- **Action:** Escalate for investigation

**False Positive:** Legitimate activity incorrectly flagged
- Known business process or application behavior
- Authorized administrative activity
- Misconfigured detection rule
- **Action:** Document, tune rule, close ticket

**Benign Positive:** Real alert but not security concern
- Informational event
- Expected behavior
- Low risk activity
- **Action:** Document and close

**Inconclusive:** Requires deeper investigation
- Insufficient information to determine
- Ambiguous indicators
- Need additional context
- **Action:** Promote to full investigation

### Triage Priority Matrix

| Severity | Asset Criticality | Priority | Response Time |
|----------|-------------------|----------|---------------|
| Critical | Critical          | P1       | Immediate     |
| Critical | High/Medium/Low   | P2       | 15 minutes    |
| High     | Critical/High     | P2       | 15 minutes    |
| High     | Medium/Low        | P3       | 1 hour        |
| Medium   | Critical/High     | P3       | 1 hour        |
| Medium   | Medium/Low        | P4       | 4 hours       |
| Low      | Any               | P5       | 24 hours      |

## Phase 3: Investigation

### Investigation Methodology

#### Step 1: Understand the Alert
- Read alert description carefully
- Review detection logic/rule
- Identify what triggered the alert
- Note the severity assessment

#### Step 2: Examine Raw Events
- Review the specific log entries that triggered alert
- Look for patterns or anomalies
- Note timestamps, source/destination, users, processes
- Identify any obvious IOCs

#### Step 3: Expand the Scope
**Temporal Analysis:** Look before and after the alert
```
Timeline Example:
T-60 min: User logged in from usual location
T-30 min: User accessed normal files
T-0 min:  [ALERT] Failed login attempts from unusual IP
T+5 min:  Successful login from unusual IP
T+10 min: Privilege escalation attempt
T+15 min: Access to sensitive files
```

**Lateral Analysis:** Check related systems and accounts
- Did the same user trigger alerts on other systems?
- Did the same source IP interact with other assets?
- Are there related alerts in the timeframe?
- What other systems did the user/IP touch?

#### Step 4: Search for Indicators of Compromise (IOCs)

**Network IOCs:**
- Source/destination IP addresses
- Domain names contacted
- URLs accessed
- Ports and protocols used
- User agents
- SSL certificates

**Host IOCs:**
- File hashes (MD5, SHA1, SHA256)
- File paths and names
- Registry keys modified
- Scheduled tasks created
- Services installed
- Process names and command lines

**User IOCs:**
- Compromised credentials
- Unusual access patterns
- Privilege escalations
- Data exfiltration indicators

#### Step 5: Correlate Across Data Sources

**Example Investigation Query Flow:**

**Initial Alert:** Failed login attempts from 203.0.113.50

**Query 1:** Find all activity from this IP
```spl
index=* src_ip="203.0.113.50" OR source="203.0.113.50"
| stats count by sourcetype, dest_ip, user
```

**Query 2:** Check if any logins succeeded
```spl
index=windows EventCode=4624 Source_Network_Address="203.0.113.50"
| table _time, Account_Name, Computer
```

**Query 3:** If successful, what did the user do after?
```spl
index=windows Account_Name="compromised_user" _time>=[successful_login_time]
| transaction Account_Name maxspan=1h
| table _time, EventCode, Process_Name, Object_Name
```

**Query 4:** Check for data exfiltration
```spl
index=proxy src_ip=[compromised_workstation] 
| stats sum(bytes_out) as total_bytes by dest, user
| where total_bytes > 100000000
```

#### Step 6: Determine Root Cause

**Key Questions:**
- How did the attacker gain initial access?
- What vulnerability or weakness was exploited?
- What systems were compromised?
- What data was accessed or exfiltrated?
- Is the threat still active?

### Investigation Tools

#### SIEM Queries
Primary investigation tool for searching logs

#### Threat Intelligence Platforms
- VirusTotal: File/URL/IP/domain reputation
- AlienVault OTX: Community threat intelligence
- AbuseIPDB: IP address reputation
- Shodan: Internet-connected device information

#### OSINT (Open Source Intelligence)
- WHOIS lookups for domain ownership
- DNS history (SecurityTrails, DNSDumpster)
- Google searches for IOCs
- Social media reconnaissance

#### Endpoint Investigation
- EDR platform for detailed host forensics
- Memory dumps for malware analysis
- File system timeline analysis
- Network connection analysis

## Phase 4: Containment and Response

### Containment Strategies

#### Immediate Containment (Active Attack)
**Goal:** Stop ongoing attack as quickly as possible

**Actions:**
1. **Isolate affected systems** from network
   - Disable network adapter
   - Block at firewall
   - Remove from VLAN

2. **Disable compromised accounts**
   - Disable in Active Directory
   - Revoke authentication tokens
   - Reset passwords

3. **Block malicious indicators**
   - Add IPs to firewall deny list
   - Update IDS/IPS signatures
   - Block domains at DNS/proxy
   - Quarantine malicious files

4. **Preserve evidence**
   - Take memory dumps
   - Capture network traffic
   - Copy logs before isolation
   - Document all actions with timestamps

#### Short-term Containment (Stabilization)
**Goal:** Prevent re-infection while allowing business operations

**Actions:**
1. **Patch vulnerabilities** that were exploited
2. **Strengthen authentication** (MFA, password policies)
3. **Segment network** to limit lateral movement
4. **Enhance monitoring** for similar attacks
5. **Deploy additional controls** (EDR, DLP)

### Response Actions by Incident Type

#### Malware Infection
1. Isolate infected systems
2. Identify malware family (hash analysis)
3. Check for lateral spread
4. Remove malware (EDR, antivirus)
5. Reimage if necessary
6. Restore from clean backup

#### Account Compromise
1. Disable compromised account
2. Force password reset for user
3. Review account activity
4. Check for unauthorized changes (permissions, email rules)
5. Verify other accounts not compromised
6. Enable MFA

#### Data Breach
1. Identify what data was accessed
2. Determine if data was exfiltrated
3. Block exfiltration channels
4. Assess business/legal impact
5. Notify stakeholders (legal, PR, management)
6. Consider regulatory notification requirements

#### Insider Threat
1. Coordinate with HR immediately
2. Preserve evidence carefully (legal considerations)
3. Disable access discreetly
4. Review all user activity
5. Identify accomplices if any
6. Document thoroughly for legal proceedings

### Escalation Criteria

**When to Escalate to Level 2/3:**
- Incident involves critical systems
- Widespread compromise detected
- Advanced persistent threat indicators
- Requires specialized forensics
- Potential data breach with regulatory implications
- Unable to contain with standard procedures
- Incident duration exceeds 2 hours without resolution

**Escalation Process:**
1. Document all findings clearly
2. Provide timeline of events
3. List systems/accounts affected
4. Note containment actions already taken
5. Transfer via ticketing system with full context
6. Remain available for questions
7. Continue monitoring related systems

## Phase 5: Documentation

### Why Documentation Matters

- **Legal Requirements:** Evidence for potential legal action
- **Compliance:** Regulatory reporting obligations
- **Lessons Learned:** Improve future detection and response
- **Knowledge Sharing:** Help other analysts handle similar incidents
- **Metrics:** Track SOC performance and effectiveness
- **Audit Trail:** Demonstrate due diligence

### What to Document

#### Incident Summary
- **Incident ID:** Unique ticket number
- **Date/Time:** When alert was received and when investigation started
- **Alert Name:** Original SIEM alert title
- **Severity:** Critical/High/Medium/Low
- **Systems Affected:** Hostnames, IPs, applications
- **Users Affected:** Account names
- **Incident Type:** Malware, phishing, unauthorized access, etc.

#### Investigation Details
- **Initial Findings:** What was observed in triage
- **Analysis Performed:** Queries run, tools used
- **IOCs Identified:** All indicators of compromise found
- **Timeline:** Chronological sequence of events
- **Root Cause:** How the incident occurred
- **Scope of Impact:** Full extent of compromise

#### Response Actions
- **Containment:** Steps taken to stop the attack
- **Eradication:** How threat was removed
- **Recovery:** Steps to restore normal operations
- **Notification:** Who was informed (management, users, external parties)

#### Outcome
- **Classification:** True positive, false positive, benign
- **Closure Reason:** Why ticket is being closed
- **Recommendations:** Improvements to prevent recurrence
- **Lessons Learned:** What could be done better

### Documentation Best Practices

1. **Document as you go** - Don't wait until the end
2. **Be objective** - Stick to facts, avoid assumptions
3. **Include timestamps** - For every action and finding
4. **Use screenshots** - Visual evidence of findings
5. **Quote exact messages** - Don't paraphrase error messages
6. **Note all queries** - So others can reproduce your work
7. **Record dead ends** - What you checked that was negative
8. **Maintain chain of custody** - For potential legal evidence
9. **Use clear language** - Avoid jargon when possible
10. **Proofread** - Ensure clarity and accuracy

### Sample Incident Report Template

```
INCIDENT REPORT

Incident ID: INC-2026-0128-001
Date Reported: 2026-01-28 14:30 UTC
Reported By: SIEM Alert - Brute Force Detection
Analyst: [Your Name]
Status: CLOSED

=== INCIDENT SUMMARY ===
Alert Name: Brute Force Login Attack Detected
Severity: HIGH
Systems Affected: WEBSERVER01 (10.0.0.50)
Users Affected: admin, root, administrator
Classification: TRUE POSITIVE - Unauthorized Access Attempt

=== TIMELINE ===
14:15 UTC - First failed login attempt from 203.0.113.50
14:16 UTC - 50+ failed login attempts within 60 seconds
14:17 UTC - SIEM alert generated
14:30 UTC - Alert assigned to analyst
14:32 UTC - Triage completed, confirmed true positive
14:35 UTC - Source IP blocked at firewall
14:40 UTC - Reviewed target system logs
14:45 UTC - No successful logins detected
14:50 UTC - Incident documented and closed

=== INVESTIGATION DETAILS ===
Initial Alert:
- 87 failed SSH login attempts from 203.0.113.50
- Targeting accounts: admin, root, administrator
- Time window: 14:15-14:16 UTC (60 seconds)
- Target: WEBSERVER01 (10.0.0.50)

Analysis Performed:
- Queried all auth logs for source IP 203.0.113.50
- Verified no successful logins occurred
- Checked threat intelligence: IP on multiple blacklists
- Confirmed IP is not from authorized network ranges
- Reviewed firewall logs for other activity from this IP
- Checked other systems for similar attempts from this IP

Findings:
- Dictionary attack pattern detected
- IP address 203.0.113.50 is known malicious (confirmed via AbuseIPDB)
- No successful authentication occurred
- No other systems targeted by this IP
- Attack stopped after initial burst (likely automated)

IOCs:
- Source IP: 203.0.113.50
- Targeted Usernames: admin, root, administrator
- Service: SSH (port 22)
- User Agent: libssh2_1.8.0

=== RESPONSE ACTIONS ===
Immediate Containment:
1. Blocked 203.0.113.50 at perimeter firewall (14:35 UTC)
2. Verified block successful via firewall logs

Verification:
1. Confirmed no successful logins occurred
2. Verified system integrity - no compromise detected
3. Checked user account status - all accounts secure

=== OUTCOME ===
Classification: TRUE POSITIVE - Brute Force Attack Attempt
Impact: None - Attack blocked by strong passwords, no compromise
Closure Reason: Incident successfully contained, no further action required

=== RECOMMENDATIONS ===
1. Consider implementing fail2ban or similar on SSH servers
2. Evaluate disabling root SSH login
3. Implement SSH key-based authentication
4. Add 203.0.113.0/24 to permanent blocklist
5. Review SSH access logs weekly for suspicious patterns

=== LESSONS LEARNED ===
- SIEM detection worked as expected
- Response time was acceptable (15 minutes to containment)
- Strong password policy prevented successful compromise
- Could improve with automated IP blocking
```

## Phase 6: Closure and Follow-up

### Closure Checklist

Before closing a ticket, ensure:
- [ ] Investigation is complete and thorough
- [ ] All questions answered or escalated
- [ ] Containment actions documented
- [ ] IOCs added to threat intelligence
- [ ] Affected parties notified
- [ ] Incident report completed
- [ ] Recommendations documented
- [ ] Ticket status updated
- [ ] Handoff notes for next shift (if ongoing)

### Post-Incident Activities

#### Lessons Learned Review
Hold review meeting for significant incidents:
- What happened?
- What went well?
- What could be improved?
- What additional tools/training needed?
- How can we prevent similar incidents?

#### Detection Tuning
- If false positive: Adjust rule to reduce noise
- If missed detection: Create new rule
- If delayed detection: Optimize rule logic
- Document all rule changes

#### Threat Intelligence Updates
- Add new IOCs to blocklists
- Update threat intelligence platform
- Share IOCs with information sharing groups (ISACs)
- Document TTPs observed

#### Metric Tracking
- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- True positive vs. false positive ratio
- Incident severity distribution
- Alert volume trends

## Common Investigation Scenarios

### Scenario 1: Phishing Email Investigation

**Alert:** User reported suspicious email

**Investigation Steps:**
1. Obtain email headers and body
2. Analyze sender (SPF, DKIM, DMARC)
3. Check links and attachments (VirusTotal, URL sandbox)
4. Determine if email is malicious
5. Search for other users who received same email
6. Check if anyone clicked links or opened attachments
7. If malicious, quarantine email from all mailboxes
8. Monitor users who interacted with email
9. Document IOCs and update email filters

### Scenario 2: Suspicious Outbound Traffic

**Alert:** Unusual large data transfer to external IP

**Investigation Steps:**
1. Identify source system and user
2. Check destination IP reputation
3. Review proxy/firewall logs for connection details
4. Determine what data was transferred
5. Check if data is sensitive/confidential
6. Review user activity before and after transfer
7. Check for malware on source system
8. Interview user if necessary
9. If malicious, contain and investigate data breach procedures

### Scenario 3: Privilege Escalation

**Alert:** User gained administrative privileges

**Investigation Steps:**
1. Identify what privileges were gained
2. Determine how privileges were obtained
3. Check if escalation was authorized (ticket/change request)
4. Review user's actions after privilege escalation
5. Check for lateral movement or suspicious activity
6. Verify current privilege level
7. If unauthorized, revoke privileges immediately
8. Document and escalate if policy violation

## Key Performance Indicators (KPIs)

### Individual Analyst Metrics
- **Tickets Closed per Shift:** Productivity measure
- **Mean Time to Triage:** Speed of initial assessment
- **Mean Time to Resolution:** Incident handling efficiency
- **False Positive Identification Rate:** Accuracy in triage
- **Escalation Rate:** Percentage of tickets escalated

### SOC Team Metrics
- **Alert Volume:** Total alerts per day/week
- **True Positive Rate:** Percentage of real incidents
- **False Positive Rate:** Noise in detection
- **Coverage:** Percentage of systems sending logs
- **Detection Time:** How quickly threats are identified

## Tools and Resources for Investigation

### Essential Tools
- SIEM platform (Splunk, Elastic, QRadar, Sentinel)
- EDR solution (CrowdStrike, Carbon Black, Defender)
- Threat intelligence (VirusTotal, AlienVault, MISP)
- Packet capture (Wireshark, tcpdump)
- Sandbox (Any.run, Joe Sandbox, Cuckoo)

### Investigation Commands

**Windows:**
```powershell
# Check running processes
Get-Process | Sort-Object CPU -Descending

# Review recent events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625; StartTime=(Get-Date).AddHours(-1)}

# Check network connections
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}

# Review scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
```

**Linux:**
```bash
# Check active connections
netstat -tunap | grep ESTABLISHED

# Review authentication logs
grep "Failed password" /var/log/auth.log | tail -20

# Check running processes
ps aux --sort=-%cpu | head

# Review recent logins
last -20
```

## Key Takeaways

1. **Follow a systematic workflow** - Don't skip steps in the investigation process
2. **Document everything** - Your notes may be needed for legal proceedings
3. **Context is critical** - Asset criticality and threat intelligence inform prioritization
4. **Think like an attacker** - Consider what an adversary would do next
5. **Correlation is key** - Single events rarely tell the full story
6. **Time is valuable** - Efficient triage saves time for deep investigations
7. **Communication matters** - Keep stakeholders informed appropriately
8. **Learn continuously** - Every incident teaches something new
9. **Trust but verify** - Validate findings before taking drastic actions
10. **Teamwork wins** - Don't hesitate to escalate or ask for help
