Gasha (SafeGuard) — Cybersecurity Threat Glossary

A practical reference for understanding cybersecurity terminology, investigating suspicious activity, and communicating findings clearly.

1. Threat Intelligence and Investigation

Threat Intelligence

Information about potential or existing cyber threats that helps organizations understand risks and make informed security decisions.

Example: Learning that a phishing campaign is targeting employees and using that information to improve email detection.

Indicator of Compromise (IoC)

An observable artifact that may indicate malicious activity. Examples include suspicious file hashes, domains, IP addresses, or unusual processes.

Remember: An indicator is evidence to investigate, not automatic proof of compromise.

Tactics, Techniques, and Procedures (TTPs)

- Tactics: The adversary's objective — why an action is performed.
- Techniques: The general method used — how an objective is pursued.
- Procedures: The specific implementation of a technique in a particular operation.

Attack Surface

The collection of points where an unauthorized person could potentially attempt to access or affect a system.

Example: Public-facing applications, exposed services, user accounts, and remote-access interfaces.

Incident Response

The organized process of identifying, analyzing, containing, and recovering from a security incident, followed by lessons learned.

2. Network and Access Security

IP Address

A numerical address used to identify an interface on an IP network. An address alone does not reliably identify the person using it.

DNS (Domain Name System)

A system that translates domain names into information such as IP addresses.

Investigation tip: Unexpected domain lookups may warrant review, but legitimate software can also generate unfamiliar DNS requests.

Firewall

A security control that filters network traffic according to defined rules.

Authentication

The process of verifying a claimed identity, such as through a password, security key, or other authentication factor.

Authorization

The process of determining what an authenticated identity is permitted to access or do.

Key distinction: Authentication asks, "Who are you?" Authorization asks, "What are you allowed to do?"

Least Privilege

The principle of granting users and systems only the permissions necessary for their tasks.

3. Common Threats

Phishing

A deceptive attempt to persuade someone to reveal sensitive information, open a harmful attachment, or follow an unsafe link.

Warning signs: Unexpected credential requests, misleading sender details, suspicious links, and pressure to act urgently.

Malware

Software designed to perform harmful or unauthorized actions. Common categories include ransomware, spyware, worms, and trojans.

Ransomware

Malware that typically encrypts data or otherwise prevents access and demands payment. Some incidents also involve threats to disclose stolen information.

Brute-Force Attack

An attempt to discover credentials by repeatedly trying possible passwords or combinations.

Denial of Service (DoS)

An attack intended to make a service unavailable by overwhelming it or exhausting its resources.

Distributed Denial of Service (DDoS)

A denial-of-service attack generated from multiple systems or sources.

SQL Injection

A vulnerability that can occur when an application handles untrusted input unsafely in database queries, potentially allowing unintended database operations.

Defensive principle: Use parameterized queries, appropriate permissions, and safe error handling.

4. Detection and Evidence

Log

A recorded event produced by a system, application, or security device.

Example: A login record may contain a timestamp, account identifier, source address, and authentication result.

SIEM (Security Information and Event Management)

A platform that collects and analyzes security-relevant events from multiple sources to help detect and investigate potential incidents.

False Positive
False Negative

A failure to detect activity that genuinely meets a detection rule or represents a threat.

Hash

A fixed-length value generated from data by a hash function. Cryptographic hashes such as SHA-256 are commonly used to compare file contents and support integrity checks.

Important: A matching hash supports the conclusion that two files have matching content under the chosen algorithm, but it does not prove that a file is safe.

File Integrity

The property of data remaining complete and unchanged except through authorized modifications.

Digital Forensics

The disciplined collection, preservation, examination, and reporting of digital evidence.

Chain of Custody

A record of how evidence was collected, transferred, accessed, stored, and handled.

Why it matters: Proper documentation helps establish the integrity and traceability of evidence.

5. Vulnerabilities and Risk

Vulnerability

A weakness in software, hardware, configuration, or process that could be exploited or otherwise create risk.

Exploit

A method, code, or sequence of actions that takes advantage of a vulnerability.

Patch

A software update intended to fix defects, including security vulnerabilities.

CVE (Common Vulnerabilities and Exposures)

A system for assigning identifiers to publicly disclosed cybersecurity vulnerabilities.

CVSS (Common Vulnerability Scoring System)

A framework for communicating the technical severity of vulnerabilities using a standardized scoring methodology.

Remember: A severity score is not the same as an organization's complete risk assessment. Exposure, business impact, and existing controls also matter.

Risk

The potential for harm, commonly evaluated by considering the likelihood of an event and its consequences.

6. The MITRE ATT&CK Framework

MITRE ATT&CK is a knowledge base of observed adversary tactics and techniques. It helps security teams describe and investigate attacker behavior.

- Tactic: The adversary's goal at a stage of activity.
- Technique: The method used to pursue that goal.
- Sub-technique: A more specific form of a technique.
- Procedure: A particular real-world implementation.

ATT&CK can support detection engineering, threat hunting, incident analysis, and security assessments. A technique mapping is an analytical aid, not proof that a particular adversary was responsible.

7. Commonly Confused Terms

Term A| Term B| Difference
Threat| Vulnerability| A threat may cause harm; a vulnerability is a weakness that may contribute to that harm.
Authentication| Authorization| Verifying identity versus determining permitted actions.
IoC| Proof of compromise| An indicator supports investigation but may have legitimate explanations.
Hashing| Encryption| Hashing produces a digest; encryption protects data using a reversible process with the appropriate key.
Vulnerability scan| Penetration test| A scan identifies potential weaknesses; a penetration test evaluates security through an authorized, scoped assessment.
DoS| DDoS| A denial-of-service attack versus one distributed across multiple sources.
Event| Incident| An event is an observable occurrence; an incident is an occurrence assessed as requiring a security response.

8. Analyst's Reminder

When investigating suspicious activity:

1. Establish what the available evidence actually shows.
2. Separate confirmed facts from assumptions.
3. Consider legitimate explanations and alternative hypotheses.
4. Correlate relevant records before drawing conclusions.
5. Document uncertainty and identify what additional evidence is needed.
6. Follow authorized procedures when collecting or handling evidence.

The core principle: Investigate the evidence before deciding what it means.

---

This glossary is an educational reference. Definitions are simplified for learning and should be supplemented with authoritative technical documentation for operational decisions.


An alert that identifies activity as suspicious when it is actually legitimate.
