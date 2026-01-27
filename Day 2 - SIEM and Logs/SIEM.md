# SIEM: Security Information and Event Management

## What is SIEM?

**SIEM (Security Information and Event Management)** is a comprehensive security solution that aggregates, normalizes, analyzes, and correlates log data from across an organization's entire IT infrastructure to detect threats, investigate incidents, and maintain compliance.

SIEM combines two key capabilities:
- **SIM (Security Information Management):** Long-term storage, analysis, and reporting of log data
- **SEM (Security Event Management):** Real-time monitoring, correlation, and alerting

## Why Organizations Need SIEM

### 1. Centralized Visibility
- **Single pane of glass** for all security events
- Aggregates data from hundreds or thousands of sources
- Provides holistic view of security posture
- Eliminates security blind spots

### 2. Threat Detection
- Identifies suspicious patterns across multiple systems
- Correlates events that seem unrelated
- Detects advanced persistent threats (APTs)
- Recognizes known attack signatures

### 3. Faster Incident Response
- Reduces investigation time from days to hours/minutes
- Provides context and timeline of security events
- Enables rapid containment and remediation
- Automates initial triage and response

### 4. Compliance and Reporting
- Meets regulatory requirements (PCI-DSS, HIPAA, GDPR, SOX)
- Generates audit reports automatically
- Maintains required log retention
- Demonstrates security controls to auditors

### 5. Forensic Analysis
- Preserves evidence for investigation
- Reconstructs attack timelines
- Identifies patient zero and lateral movement
- Supports legal and HR investigations

## Core SIEM Components

### 1. Log Collection
**How it works:**
- **Agents:** Software installed on endpoints/servers that forward logs
- **Agentless:** Direct API integration or network-based collection
- **Syslog:** Standard protocol for log transmission
- **API Connectors:** Cloud service integrations

**What gets collected:**
- Operating system logs
- Application logs
- Network device logs
- Security tool logs (firewall, IDS/IPS, EDR, AV)
- Cloud service logs (AWS CloudTrail, Azure Activity, GCP Audit)
- Authentication systems (Active Directory, SSO)

### 2. Log Aggregation
**Purpose:** Centralize logs from all sources into single repository

**Process:**
- Receive logs from various sources
- Queue logs for processing
- Ensure reliable delivery and prevent data loss
- Handle high volumes (millions of events per second)

### 3. Normalization and Parsing
**Purpose:** Convert different log formats into common schema

**Example:**

**Before Normalization:**
```
Windows: User "john.doe" logged on to WORKSTATION01 from 192.168.1.100
Linux: sshd: Accepted password for jdoe from 192.168.1.100
Firewall: ALLOW TCP 192.168.1.100:52341 -> 10.0.0.50:22
```

**After Normalization:**
```
| Timestamp           | Event_Type | User     | Source_IP     | Dest_IP   | Action  |
|---------------------|------------|----------|---------------|-----------|---------|
| 2026-01-28 10:15:30 | Login      | john.doe | 192.168.1.100 | N/A       | Success |
| 2026-01-28 10:15:30 | Login      | jdoe     | 192.168.1.100 | N/A       | Success |
| 2026-01-28 10:15:30 | Connection | N/A      | 192.168.1.100 | 10.0.0.50 | Allowed |
```

### 4. Indexing and Storage
- **Hot storage:** Recent data (last 30-90 days) for fast querying
- **Warm storage:** Older data (90 days - 1 year) with slower access
- **Cold storage:** Archive data (1+ years) for compliance
- **Compression:** Reduce storage requirements
- **Retention policies:** Automatic data lifecycle management

### 5. Correlation Engine
**Purpose:** Identify patterns and relationships between events

**Correlation Types:**

#### Simple Correlation
Single condition triggers alert:
- Failed login count > 5 within 5 minutes
- Critical severity event detected
- Known malicious IP connection

#### Complex Correlation
Multiple conditions across different sources:
```
IF (Failed Login attempts > 5 from same IP)
AND (Successful login from same IP within 10 minutes)
AND (Privilege escalation within 30 minutes)
THEN Alert: "Potential Account Compromise"
```

#### Time-based Correlation
Events within specific timeframe:
- User VPN login from Country A
- Then same user login from Country B within 30 minutes
- Impossible travel scenario

#### Statistical Correlation
Deviation from baseline:
- User normally accesses 10 files/day, suddenly accesses 1000
- Database typically has 100 queries/hour, suddenly 10,000
- Workstation never accessed before connects to domain controller

### 6. Alerting and Notifications
**Alert Severity Levels:**
- **Critical:** Immediate threat requiring urgent action
- **High:** Serious security event requiring prompt investigation
- **Medium:** Suspicious activity warranting investigation
- **Low:** Informational or minor security concern
- **Informational:** Normal security-relevant events

**Notification Methods:**
- Email alerts
- SMS/text messages
- SIEM dashboard pop-ups
- Integration with ticketing systems (ServiceNow, Jira)
- SOAR platform integration for automation
- Slack/Teams notifications

### 7. Dashboards and Visualization
**Purpose:** Present security data in digestible, actionable format

**Common Dashboards:**
- **Executive Dashboard:** High-level metrics, trends, compliance status
- **SOC Operations Dashboard:** Real-time alerts, queue status, analyst workload
- **Threat Intelligence Dashboard:** Threat actor activity, IOCs, campaigns
- **Compliance Dashboard:** Audit requirements, policy violations
- **Network Traffic Dashboard:** Bandwidth usage, top talkers, protocols

**Visualization Types:**
- Real-time event feeds
- Geographic heat maps (attack origins)
- Time series graphs (trends over time)
- Pie charts (event distribution by type/severity)
- Tables (top users, IPs, applications)

### 8. Search and Investigation
**Purpose:** Enable analysts to query historical data for investigation

**Search Capabilities:**
- Full-text search across all log data
- Field-specific searches (source IP, user, event type)
- Time range filtering
- Regular expressions and wildcards
- Boolean operators (AND, OR, NOT)
- Statistical functions (count, average, sum)

**Investigation Workflow:**
1. Receive alert about suspicious activity
2. Search for related events across all log sources
3. Build timeline of attacker activities
4. Identify scope of compromise
5. Determine indicators of compromise (IOCs)
6. Document findings for remediation

### 9. Reporting
**Purpose:** Generate compliance reports and security metrics

**Report Types:**
- **Compliance Reports:** PCI-DSS, HIPAA, SOX, GDPR requirements
- **Executive Reports:** Security posture, trends, incidents summary
- **Operational Reports:** Analyst performance, MTTR, alert statistics
- **Threat Reports:** Attack trends, threat actor activity
- **Custom Reports:** Specific investigations or metrics

**Scheduling:**
- Daily, weekly, monthly, quarterly reports
- Automated generation and distribution
- Exportable formats (PDF, CSV, Excel)

## Popular SIEM Platforms

### 1. Splunk
**Overview:** Market-leading SIEM known for powerful search and analytics

**Strengths:**
- Extremely powerful Search Processing Language (SPL)
- Extensive app marketplace
- Excellent data visualization
- Strong community support

**Key Features:**
- Enterprise Security (ES) app for SIEM functionality
- User Behavior Analytics (UBA)
- SOAR capabilities (Phantom, now Splunk SOAR)
- Cloud and on-premises deployment

**Query Example (SPL):**
```
index=windows EventCode=4625
| stats count by src_ip
| where count > 5
| sort -count
```

### 2. IBM QRadar
**Overview:** Enterprise SIEM with strong correlation capabilities

**Strengths:**
- Advanced correlation engine
- Network flow analysis
- Built-in threat intelligence
- Good for compliance reporting

**Key Features:**
- Offense management (similar to cases)
- Risk-based prioritization
- Network and log-based analysis
- User Behavior Analytics

**Query Example (AQL):**
```
SELECT sourceip, COUNT(*) as attempts
FROM events
WHERE eventname = 'Failed Login'
GROUP BY sourceip
HAVING attempts > 5
```

### 3. Elastic Stack (ELK)
**Overview:** Open-source SIEM solution

**Components:**
- **Elasticsearch:** Search and analytics engine
- **Logstash:** Log processing and forwarding
- **Kibana:** Visualization and dashboards
- **Beats:** Lightweight data shippers

**Strengths:**
- Open source and cost-effective
- Highly scalable
- Flexible and customizable
- Strong community

**Query Example (KQL - Kibana Query Language):**
```
event.code: 4625 AND event.outcome: failure
```

### 4. Microsoft Sentinel
**Overview:** Cloud-native SIEM built on Azure

**Strengths:**
- Deep Microsoft 365 integration
- AI and machine learning for threat detection
- Cloud-native architecture
- Pay-as-you-go pricing model

**Key Features:**
- Integrated threat intelligence
- Automation and orchestration (Logic Apps)
- Jupyter notebooks for investigation
- Hunting queries with KQL

**Query Example (KQL - Kusto Query Language):**
```
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| where FailedAttempts > 5
```

### 5. ArcSight
**Overview:** Enterprise SIEM from OpenText (formerly Micro Focus, HP)

**Strengths:**
- Mature platform with extensive connectors
- Strong compliance reporting
- Complex event processing
- Enterprise scalability

### 6. LogRhythm
**Overview:** Unified SIEM, UEBA, and SOAR platform

**Strengths:**
- Built-in case management
- Machine learning analytics
- SmartResponse automation
- Integrated network and host forensics

## SIEM Use Cases

### 1. Brute Force Attack Detection
**Scenario:** Attacker attempting to guess passwords

**SIEM Detection:**
```
Rule: Multiple Failed Login Attempts
IF failed_login_count >= 5
AND time_window <= 300 seconds (5 minutes)
AND same_source_ip
THEN ALERT: "Brute Force Attack Detected"
```

**Investigation Steps:**
1. Identify source IP and targeted accounts
2. Check if attack was successful
3. Review subsequent activity from compromised account
4. Block source IP at firewall
5. Reset passwords for targeted accounts

### 2. Insider Threat Detection
**Scenario:** Employee accessing sensitive data before resignation

**SIEM Detection:**
```
Rule: Abnormal File Access
IF file_access_count > (baseline * 10)
AND file_category = "Sensitive"
AND time = after_hours
THEN ALERT: "Potential Data Exfiltration"
```

**Correlation:**
- HR system: Employee resignation submitted
- File server: Unusual file access patterns
- Network: Large data upload to external site
- Email: Files sent to personal email

### 3. Lateral Movement Detection
**Scenario:** Attacker moving between systems after initial compromise

**SIEM Detection:**
```
Rule: Lateral Movement Pattern
IF new_logon_to_multiple_systems
AND account_not_admin
AND psexec OR wmi OR rdp
AND time_window <= 3600 seconds
THEN ALERT: "Lateral Movement Detected"
```

**IOCs to Track:**
- Remote execution tools (PsExec, WMI, PowerShell remoting)
- Unusual authentication patterns
- Admin tools used by non-admin accounts
- Network shares accessed

### 4. Malware Infection
**Scenario:** Ransomware spreading through network

**SIEM Detection:**
```
Rule: Ransomware Indicators
IF (file_extension_change_count > 100)
OR (process_name IN ransomware_signature_list)
OR (C2_communication_detected)
THEN ALERT: "Potential Ransomware Activity"
```

**Correlation:**
- Endpoint: Mass file encryption
- Network: Beaconing to known C2 server
- DNS: Queries to suspicious domains
- Email: Malicious attachment opened

### 5. Compliance Monitoring
**Scenario:** PCI-DSS requirement for monitoring access to cardholder data

**SIEM Use:**
- Alert on any access to cardholder data environment
- Track privileged user activities
- Monitor system configuration changes
- Generate quarterly compliance reports
- Detect policy violations in real-time

## SIEM Implementation Challenges

### 1. Data Volume
**Challenge:** Millions of events per second
**Solution:**
- Prioritize critical log sources
- Implement filtering at collection point
- Use tiered storage
- Optimize queries and searches

### 2. False Positives
**Challenge:** Overwhelming number of irrelevant alerts
**Solution:**
- Tune correlation rules regularly
- Implement context-aware alerting
- Use threat intelligence feeds
- Create whitelists for known-good activity
- Leverage machine learning for anomaly detection

### 3. Skill Gap
**Challenge:** SIEM platforms are complex
**Solution:**
- Invest in training for SOC analysts
- Create playbooks and standard procedures
- Use vendor professional services initially
- Build internal expertise gradually

### 4. Integration Complexity
**Challenge:** Hundreds of different log sources
**Solution:**
- Start with critical systems
- Use out-of-the-box connectors when available
- Develop custom parsers as needed
- Leverage vendor support

### 5. Cost
**Challenge:** SIEM can be expensive (licensing, storage, personnel)
**Solution:**
- Right-size deployment based on needs
- Consider cloud-native options (pay-as-you-go)
- Evaluate open-source alternatives
- Focus ROI on reduced breach impact

## SIEM Best Practices

### 1. Define Clear Use Cases
- Identify what you want to detect
- Prioritize based on risk
- Document detection logic
- Test and validate rules

### 2. Establish Baseline
- Understand normal behavior
- Document typical patterns
- Update baselines regularly
- Use for anomaly detection

### 3. Tune Regularly
- Review alerts weekly
- Disable noisy rules
- Refine thresholds
- Eliminate false positives

### 4. Enrich Data
- Integrate threat intelligence
- Add asset criticality
- Include user context
- Correlate with vulnerability data

### 5. Document Everything
- Create runbooks for common alerts
- Document investigation procedures
- Maintain up-to-date system inventory
- Track changes to correlation rules

### 6. Continuous Improvement
- Regular review of SIEM effectiveness
- Update rules based on new threats
- Incorporate lessons learned from incidents
- Benchmark against industry standards

## Hands-On: SIEM Query Examples

### Splunk SPL Examples

**Find failed SSH logins:**
```spl
index=linux sourcetype=syslog "Failed password"
| stats count by src_ip, user
| where count > 5
| sort -count
```

**Detect privilege escalation:**
```spl
index=windows EventCode=4672
| where Special_Privileges="*SeDebugPrivilege*"
| table _time, user, Computer, Special_Privileges
```

**Identify large file transfers:**
```spl
index=proxy
| stats sum(bytes_out) as total_bytes by user
| where total_bytes > 1000000000
| eval total_GB = round(total_bytes/1024/1024/1024, 2)
| table user, total_GB
```

### Elastic/Kibana KQL Examples

**Failed login attempts:**
```
event.code: 4625 AND event.outcome: failure
```

**Web application attacks:**
```
http.response.status_code: 500 AND url.path: *admin* AND source.ip: NOT "192.168.1.0/24"
```

**PowerShell execution:**
```
process.name: "powershell.exe" AND process.command_line: *-enc* OR *-encoded*
```

## Key Takeaways

1. **SIEM is essential** for modern SOC operations - provides centralized visibility
2. **Correlation is key** - connecting disparate events reveals the full attack story
3. **Tuning is ongoing** - reducing false positives is continuous work
4. **Context matters** - enrich events with threat intel, asset data, user info
5. **Know your tools** - master the SIEM query language for efficient investigations
6. **Automation helps** - but human analysis is still critical
7. **Start focused** - implement use cases incrementally, prioritize by risk
8. **Documentation is crucial** - playbooks and procedures ensure consistency

