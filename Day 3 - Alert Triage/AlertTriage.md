# Alert Triage: The First Line of Defense

## What is Alert Triage?

**Alert Triage** is the critical first step in the SOC analyst workflow where incoming security alerts are quickly assessed, classified, and prioritized for investigation. It's the process of separating signal from noise, determining what requires immediate attention, and routing alerts to the appropriate team members.

Think of triage like an emergency room: not every patient needs immediate surgery, but you need to quickly identify who does and who can wait.

## Why Alert Triage Matters

### The Alert Overload Problem

Modern SOCs face significant challenges:
- **Volume:** Large organizations can receive 10,000+ alerts per day
- **Alert Fatigue:** Analysts become desensitized to constant alerts
- **Time Constraints:** Can't deeply investigate every alert
- **Resource Limitation:** Limited analysts, unlimited alerts
- **Business Impact:** Missing real threats while chasing false positives

**Statistics:**
- Average SOC receives 11,000 alerts daily (Ponemon Institute)
- 52% of alerts are false positives
- 27% of alerts are never investigated due to volume
- Average time to triage: 5-15 minutes per alert

### The Cost of Poor Triage

**If you investigate everything:**
- Analysts burn out
- Response times increase
- Real threats get buried
- Operational costs skyrocket

**If you ignore alerts:**
- Real incidents go undetected
- Breaches occur and persist
- Compliance violations
- Reputation damage

**Good triage balances speed and accuracy**

## The Triage Mindset

### Key Principles

#### 1. Speed Matters
- Make quick but informed decisions
- Don't get stuck in analysis paralysis
- Set time limits (5 minutes for initial triage)
- Move to investigation if you need more time

#### 2. Context is King
- Who is involved? (Admin vs. regular user)
- What system? (Production vs. test)
- When did it happen? (Business hours vs. 3 AM)
- Where from? (Internal vs. external)

#### 3. Risk-Based Approach
Not all alerts are equal:
- Critical asset + High severity = Immediate action
- Test system + Low severity = Low priority
- Known good behavior = Quick close

#### 4. Trust Your Gut (But Verify)
- Experience builds intuition
- If something feels off, investigate further
- Document why you escalated or closed
- Learn from mistakes

## The Triage Process: Step-by-Step

### Step 1: Initial Alert Review (1-2 minutes)

**Read the Alert Title and Description**
```
Example Alert:
Title: Multiple Failed Login Attempts Detected
Severity: HIGH
System: WEBSERVER01
User: admin
Source IP: 203.0.113.50
Time: 2026-01-28 14:15:30 UTC
Description: 87 failed SSH login attempts within 60 seconds
```

**Immediate Questions:**
- What type of alert is this?
- What is the stated severity?
- When did it trigger?
- What system/user is involved?

### Step 2: Gather Context (2-3 minutes)

#### System/Asset Context

**Check Asset Inventory:**
- Is this a production server or test/dev system?
- What is the asset criticality rating?
- What data/services does it host?
- Who owns/manages this system?

**Asset Criticality Levels:**
- **Critical:** Core business systems (payment processing, customer database)
- **High:** Important but not mission-critical (HR systems, internal tools)
- **Medium:** Standard workstations, non-critical applications
- **Low:** Test systems, development environments, personal devices

#### User/Account Context

**Check User Information:**
- Is this a real user or service account?
- What is their role and department?
- What access level do they have?
- Is the account currently active?
- Any recent HR changes? (termination, leave, role change)

**Red Flags:**
- Recently terminated employee
- Generic admin accounts (admin, administrator, root)
- Service accounts with unusual activity
- VIP/executive accounts
- Privileged accounts

#### Temporal Context

**Time-Based Analysis:**
- Is this during business hours or after hours?
- Does the time make sense for this user?
  - Developer accessing code repo at 2 AM = Maybe normal
  - HR staff accessing payroll at 3 AM = Suspicious
- Weekend vs. weekday activity
- Holiday activity (system should be idle)

#### Geographic Context

**Location Analysis:**
- Where is the source IP located? (GeoIP lookup)
- Does this match user's normal location?
- Is travel involved? (check VPN logs, email calendar)
- Impossible travel scenario?
  - User logs in from NYC at 9 AM
  - Same user logs in from London at 9:15 AM
  - **Physically impossible = Account compromise**

#### Threat Intelligence Context

**Check IOCs (Indicators of Compromise):**

**IP Reputation:**
- VirusTotal: https://www.virustotal.com
- AbuseIPDB: https://www.abuseipdb.com
- Talos Intelligence: https://talosintelligence.com
- AlienVault OTX: https://otx.alienvault.com

**Domain/URL Reputation:**
- URLhaus: Known malicious URLs
- PhishTank: Phishing sites
- Google Safe Browsing

**File Hash Reputation:**
- VirusTotal
- Hybrid Analysis
- Any.run sandbox

**Known Campaigns:**
- Is this part of an ongoing campaign?
- Have we seen similar activity before?
- Industry-specific threats?

### Step 3: Quick Investigation (2-5 minutes)

**Run Basic Queries:**

#### Check for Related Activity

**Same Source IP:**
```
index=* src_ip="203.0.113.50" earliest=-24h
| stats count by sourcetype, dest_ip, user
| sort -count
```

**Same User:**
```
index=* user="admin" earliest=-24h
| stats count by src_ip, dest_ip, action
| sort -count
```

**Same Destination:**
```
index=* dest_ip="10.0.0.50" earliest=-24h
| stats count by src_ip, user, action
| sort -count
```

#### Look for Patterns

**Frequency Analysis:**
- Is this a one-time event or recurring?
- Similar alerts in the past hour/day/week?
- Increasing or decreasing trend?

**Volume Analysis:**
- Normal volume for this alert type?
- Spike compared to baseline?
- Gradual increase suggesting reconnaissance?

### Step 4: Classification (1 minute)

Determine the alert category:

#### True Positive (TP)
**Confirmed malicious or policy-violating activity**

**Characteristics:**
- Multiple suspicious indicators align
- Known attack pattern/signature
- Violates security policy
- Threat intelligence confirms malicious IOCs
- No legitimate business justification

**Examples:**
- Login from known malicious IP
- Malware detected on workstation
- Data exfiltration to external site
- Unauthorized privilege escalation
- Access to prohibited websites

**Action:** Escalate for full investigation and response

#### False Positive (FP)
**Legitimate activity incorrectly flagged as malicious**

**Characteristics:**
- Known business process
- Authorized activity
- Misconfigured detection rule
- Legitimate but unusual (but explainable) behavior

**Examples:**
- Scheduled backup causing "large data transfer" alert
- Penetration test triggering attack alerts
- System administrator performing authorized maintenance
- Application behavior misidentified as malicious
- Developer testing triggering vulnerability scan alerts

**Action:** Document reason, tune rule if needed, close ticket

#### Benign Positive (BP)
**Real alert but not a security concern**

**Characteristics:**
- Alert is accurate but expected
- Low risk activity
- Informational only
- No policy violation

**Examples:**
- User reset own password (expected behavior)
- VPN connection from known location
- Software update process
- Routine system maintenance alerts

**Action:** Document and close

#### Inconclusive / Needs Investigation
**Insufficient information to classify**

**Characteristics:**
- Ambiguous indicators
- Could be legitimate or malicious
- Need deeper analysis
- Context is unclear

**Examples:**
- New file created in system directory (could be malware or update)
- Unusual but not impossible user behavior
- Network connection to unknown IP (need to research)
- Process execution with unclear purpose

**Action:** Promote to full investigation or escalate

### Step 5: Prioritization (1 minute)

**Priority Matrix:**

```
┌─────────────┬──────────────┬──────────────┬──────────────┐
│  Severity   │   Critical   │     High     │    Medium    │
│  vs Asset   │    Asset     │    Asset     │    Asset     │
├─────────────┼──────────────┼──────────────┼──────────────┤
│  Critical   │      P1      │      P1      │      P2      │
│   Alert     │  (Immediate) │  (15 min)    │  (30 min)    │
├─────────────┼──────────────┼──────────────┼──────────────┤
│    High     │      P1      │      P2      │      P3      │
│   Alert     │  (15 min)    │  (30 min)    │  (1 hour)    │
├─────────────┼──────────────┼──────────────┼──────────────┤
│   Medium    │      P2      │      P3      │      P4      │
│   Alert     │  (30 min)    │  (1 hour)    │  (4 hours)   │
├─────────────┼──────────────┼──────────────┼──────────────┤
│    Low      │      P3      │      P4      │      P5      │
│   Alert     │  (1 hour)    │  (4 hours)   │  (24 hours)  │
└─────────────┴──────────────┴──────────────┴──────────────┘
```

**Priority Modifiers:**

**Increase Priority If:**
- Active data breach in progress
- Ransomware detected
- Multiple systems affected
- Executive/VIP user involved
- Regulatory compliance implications
- Attack in progress (real-time)
- Known APT indicators

**Decrease Priority If:**
- Test/development environment
- Known scheduled activity
- Isolated incident
- No data at risk
- Historical alert (not current)

### Step 6: Assignment and Documentation (1 minute)

**Assign to Appropriate Queue:**
- **Tier 1 Queue:** Standard alerts, routine investigation
- **Tier 2 Queue:** Complex incidents, require deep analysis
- **Tier 3 Queue:** Advanced persistent threats, major incidents
- **Specialized Teams:** Malware analysis, forensics, threat hunting

**Document Triage Decision:**

**Minimum Documentation:**
```
Triage Summary:
- Classification: [TP/FP/BP/Inconclusive]
- Priority: [P1/P2/P3/P4/P5]
- Justification: [Brief reason for classification]
- Initial Findings: [Key observations]
- Recommended Action: [Next steps]
- Assigned To: [Queue/Analyst]
```

**Example:**
```
Triage Summary:
- Classification: True Positive
- Priority: P1
- Justification: Brute force attack from known malicious IP, 87 failed 
  attempts within 60 seconds. Source IP (203.0.113.50) appears on 
  multiple threat intelligence blacklists.
- Initial Findings: No successful logins detected. Attack stopped after 
  initial burst. Target system is production web server (CRITICAL asset).
- Recommended Action: Block source IP at firewall, investigate for any 
  successful authentication, check other systems for similar activity.
- Assigned To: Tier 1 Incident Response Queue
```

## Common Triage Scenarios

### Scenario 1: Multiple Failed Login Attempts

**Alert Details:**
- 10 failed RDP login attempts
- User: administrator
- Source: 192.168.10.50
- Target: FILESERVER01
- Time: Tuesday, 2:30 PM

**Triage Process:**

**Context Gathering:**
- Source IP 192.168.10.50 = Internal network
- Time: Business hours
- User: Generic admin account
- Target: Production file server (HIGH criticality)

**Quick Investigation:**
- Check who normally uses admin account
- Verify 192.168.10.50 is a legitimate workstation
- Look for successful login after failed attempts
- Check if this is normal troubleshooting behavior

**Possible Classifications:**

**Scenario A - False Positive:**
- Source IP belongs to IT administrator workstation
- Admin was troubleshooting account lockout issue
- Change ticket exists for this activity
- **Action:** Document, close as FP

**Scenario B - True Positive:**
- Source IP is unknown workstation
- No change ticket or authorization
- Account became locked after attempts
- Similar attempts on other servers
- **Action:** Escalate as unauthorized access attempt

### Scenario 2: Malware Detection

**Alert Details:**
- Endpoint protection flagged suspicious file
- File: invoice_2026.pdf.exe
- Path: C:\Users\jsmith\Downloads\
- User: John Smith (Sales)
- Action: Quarantined
- Hash: [MD5 hash]

**Triage Process:**

**Immediate Actions:**
1. Check file hash on VirusTotal
2. Verify quarantine was successful
3. Check if file executed before quarantine
4. Review user's recent email

**Hash Check Results:**

**If VirusTotal shows 40/70 AV vendors detect as malware:**
- **Classification:** True Positive - Malware
- **Priority:** P1 (malware on production system)
- **Action:** Isolate system, full malware investigation

**If VirusTotal shows 0/70 detections:**
- Possibly false positive or new/unknown malware
- Check file behavior (sandbox analysis)
- Review email source
- **Classification:** Inconclusive, promote to investigation

### Scenario 3: Large Data Transfer

**Alert Details:**
- 15 GB data transfer to external IP
- User: Sarah Johnson (Marketing)
- Destination: 93.184.216.34
- Protocol: HTTPS
- Time: Friday, 11:30 PM

**Triage Process:**

**Red Flags:**
- Large volume
- After hours activity
- External destination
- Marketing user (not typical for large transfers)

**Investigation Steps:**
1. GeoIP lookup on destination IP
   - Result: 93.184.216.34 = Dropbox IP range
2. Check user's normal behavior baseline
   - User never transfers this much data
   - User normally offline by 6 PM
3. Review authentication logs
   - User VPN session from home IP (normal)
   - No concurrent logins from other locations
4. Contact user (if business hours)
   - User working late on campaign deadline
   - Uploading video assets to Dropbox for client
   - Authorized by manager

**Classification Options:**

**If activity is authorized:**
- **Classification:** Benign Positive
- **Action:** Document, update user baseline, close

**If cannot reach user or activity unexplained:**
- **Classification:** Inconclusive
- **Priority:** P2
- **Action:** Escalate for investigation, possible account compromise

### Scenario 4: Impossible Travel

**Alert Details:**
- User: michael.chen@company.com
- Event 1: VPN login from New York at 9:00 AM
- Event 2: VPN login from London at 9:15 AM
- Time difference: 15 minutes
- Distance: ~3,500 miles

**Triage Process:**

**Physics Check:**
- 3,500 miles in 15 minutes = Impossible
- Fastest commercial flight: ~7 hours

**Possible Explanations:**

**Legitimate:**
1. User has VPN configured on multiple devices
2. User travels frequently (check if actually in London)
3. Corporate VPN endpoint misconfigured (showing wrong location)

**Malicious:**
1. Account compromise
2. Credential theft
3. Shared credentials (policy violation)

**Investigation:**
1. Check both session details
   - Device types? (Phone + Laptop = possibly legitimate)
   - User agents? (Different OS versions)
2. Review email/calendar for travel plans
3. Check MFA status on both logins
4. Look at activity from both sessions
   - Normal behavior or suspicious?

**Classification:**
- **If MFA was used on both:** Likely legitimate (shared devices)
- **If no MFA or suspicious activity:** True Positive - Account compromise
- **Priority:** P1 or P2 depending on findings

## Triage Efficiency Tips

### Use Keyboard Shortcuts
- Learn your SIEM's keyboard shortcuts
- Quick filters and saved searches
- Hotkeys for common actions

### Create Templates
```
Triage Templates:

Failed Login Template:
- Source IP reputation: [Check VirusTotal/AbuseIPDB]
- User account status: [Active/Inactive/Generic]
- Successful login after failures: [Yes/No]
- Related activity: [Other systems/users affected]
- Classification: [TP/FP/BP]

Malware Detection Template:
- File hash reputation: [VirusTotal score]
- File path/name: [Suspicious indicators]
- User context: [Department/Role]
- Quarantine status: [Successful/Failed]
- Execution evidence: [Process creation logs]
- Classification: [TP/FP]
```

### Leverage Automation

**Pre-Triage Automation:**
- Auto-enrich alerts with threat intelligence
- Automatic IP/domain/hash reputation lookups
- User context injection (department, role, manager)
- Asset criticality tagging
- Similar alert grouping

**Auto-Close Criteria:**
- Known false positives (documented)
- Alerts from decommissioned systems
- Test system alerts below certain severity
- Duplicate alerts within timeframe

### Maintain Triage Playbooks

**Playbook Example - Brute Force Attack:**

```
Alert: Multiple Failed Login Attempts

Step 1: Verify Alert (30 seconds)
□ Confirm failed attempt count exceeds threshold
□ Note time window of attempts
□ Identify targeted account and system

Step 2: Context Check (60 seconds)
□ Is source IP internal or external?
□ Is targeted account generic (admin) or specific user?
□ Is system production or test environment?
□ Check IP reputation (VirusTotal/AbuseIPDB)

Step 3: Quick Search (60 seconds)
□ Were any login attempts successful?
□ Is same source targeting other systems?
□ Is same user being targeted from other IPs?
□ Any successful activity after failed attempts?

Step 4: Classification (30 seconds)
□ TRUE POSITIVE if:
  - External malicious IP
  - Generic admin account targeted
  - High volume of attempts
  → ESCALATE for blocking and investigation

□ FALSE POSITIVE if:
  - Internal IP with change ticket
  - User locked out, IT troubleshooting
  - Known application behavior
  → DOCUMENT and close

□ INCONCLUSIVE if:
  - Unclear business context
  - New pattern not seen before
  → ESCALATE for investigation

Total Time: ~3 minutes
```

## Common Triage Mistakes

### 1. Confirmation Bias
**Mistake:** Making decision too quickly based on first impression

**Example:**
- See "failed login" alert
- Assume brute force without checking details
- Miss that it's internal user who forgot password

**Fix:** Follow checklist every time, verify assumptions

### 2. Alert Title Fixation
**Mistake:** Relying only on alert title without reading details

**Example:**
- Alert: "Malware Detected"
- Close without checking if quarantine was successful
- Miss that malware actually executed before detection

**Fix:** Always review full alert details and raw events

### 3. Ignoring Context
**Mistake:** Treating all alerts equally regardless of context

**Example:**
- Large data transfer alert
- Close as normal without checking user/time/destination
- Miss data exfiltration because "backups transfer data too"

**Fix:** Always gather context (who, what, when, where)

### 4. Analysis Paralysis
**Mistake:** Spending too long on triage instead of escalating

**Example:**
- Spending 30 minutes trying to determine if alert is valid
- Should have escalated after 5 minutes of uncertainty

**Fix:** Set time limits, escalate when uncertain

### 5. Not Documenting
**Mistake:** Closing alerts without explanation

**Example:**
- Close alert as false positive
- No notes on why
- Same alert triggers next week, have to start over

**Fix:** Always document your reasoning, even briefly

### 6. Ignoring Patterns
**Mistake:** Treating each alert in isolation

**Example:**
- Close 5 separate "failed login" alerts as FP
- Don't notice they're all from same IP targeting different users
- Miss coordinated attack

**Fix:** Look for related alerts before closing

## Metrics and Improvement

### Individual Metrics

**Speed:**
- Average triage time per alert
- Target: 3-5 minutes for standard alerts

**Accuracy:**
- False positive identification rate
- True positive catch rate
- Escalation appropriateness

**Volume:**
- Alerts triaged per shift
- Ticket closure rate

### Quality Indicators

**Good Triage:**
- Consistent classification accuracy
- Appropriate prioritization
- Clear documentation
- Timely escalation when needed
- Effective communication

**Poor Triage:**
- Frequent reclassification by Tier 2
- Missing critical incidents
- Excessive false positive closures
- Incomplete documentation
- Unnecessary escalations

### Continuous Improvement

**Weekly Review:**
- Review escalated tickets that were downgraded
- Review closed tickets that should have been escalated
- Identify patterns in mistakes
- Update playbooks

**Monthly Metrics:**
- Triage accuracy percentage
- Average triage time
- Escalation rate
- False positive closure rate

**Feedback Loop:**
- Get feedback from Tier 2 analysts
- Review incident post-mortems
- Share lessons learned with team
- Update triage procedures

## Key Takeaways

1. **Triage is a skill** - Improves with practice and experience
2. **Speed and accuracy must balance** - Don't sacrifice one for the other
3. **Context changes everything** - Same activity can be normal or malicious
4. **Documentation is essential** - Your future self (and team) will thank you
5. **Patterns matter** - Connect the dots across multiple alerts
6. **Trust your instincts** - But verify with data
7. **Know when to escalate** - Better safe than sorry
8. **Continuous learning** - Every alert teaches something
9. **Playbooks are your friend** - Consistency prevents mistakes
10. **Metrics drive improvement** - Track your performance

## Practical Exercise Reflection

**Total Alerts Triaged:** [Number]

**Classifications:**
- True Positives: [Number]
- False Positives: [Number]
- Benign Positives: [Number]
- Escalated as Inconclusive: [Number]

**Average Triage Time:** [Time]

**Most Challenging Alert:** [Description]

**Key Learning:** [Your insight]

**Improvement Goal:** [What you'll work on]

---

**Date Completed:** [Add Date]  
**Time Spent:** [Add Time]  
**Key Skills Developed:** Rapid assessment, context gathering, classification accuracy, prioritization  
**Next Focus:** Advanced investigation techniques and handling complex incidents