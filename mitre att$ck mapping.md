Gasha — MITRE ATT&CK Mapping

«Mapping observed evidence to documented adversary behaviors to support structured cybersecurity investigations.»

1. Purpose

MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on real-world observations. Security analysts use it to describe and understand behaviors that may occur during cyberattacks.

Gasha uses ATT&CK mapping as an educational exercise: learners examine evidence, identify potentially relevant behaviors, and explain whether the evidence supports a particular mapping.

Important: A mapping is an analytical hypothesis, not proof that an attack occurred.

2. Understanding the Framework

- Tactic: The adversary's goal, or what they are trying to achieve.
- Technique: A method used to pursue that goal.
- Sub-technique: A more specific variation of a technique.
- Procedure: The particular way an adversary implements a technique.

ATT&CK mappings should be based on observed behavior rather than assumptions about an attacker's identity or intentions.

3. Mapping Methodology

Use the following process when evaluating a case.

Step 1 — Identify the behavior

Describe what the evidence directly shows without adding assumptions.

Step 2 — Find a relevant technique

Search the official ATT&CK knowledge base for techniques that describe the observed behavior.

Step 3 — Verify the evidence

Determine whether the available logs, artifacts, or other observations support the proposed mapping.

Step 4 — Record uncertainty

Identify missing information, alternative explanations, and evidence that would strengthen or weaken the mapping.

Step 5 — Document the result

Record the technique, its official reference, supporting evidence, and confidence in the assessment.

4. Example Case Mappings

These examples demonstrate the reasoning process. They do not claim that the fictional events represent confirmed attacks.

Case A — Unusual Login Time

Observed evidence: An account successfully authenticated outside its usual recorded activity window.

Potential ATT&CK mapping: None established from timing alone.

Reasoning: An unusual login time is an anomaly, not a specific adversary technique. Additional evidence is needed to determine whether the event involved unauthorized access.

Evidence that could change the assessment:

- Confirmation that the account owner did not authorize the login
- Evidence of stolen credentials
- Related suspicious authentication or session activity

Analyst conclusion: Investigate the anomaly before assigning an ATT&CK technique.

Case B — Suspicious Credential Request

Observed evidence: A message urgently asks a user to provide credentials through an unverified link.

Potential ATT&CK mapping: "T1566.002 — Spearphishing Link" (https://attack.mitre.org/techniques/T1566/002/)

Tactic: Initial Access.

Reasoning: The observed behavior may be consistent with a phishing link intended to facilitate access. However, the message alone does not prove that an adversary sent it or that the recipient's account was compromised.

Evidence that could strengthen the mapping:

- A verified malicious destination
- Email authentication and sender-analysis results
- Evidence connecting the message to an attempted compromise

Analyst conclusion: Potential phishing behavior; verify the sender, link, and surrounding evidence.

Case C — File Integrity Mismatch

Observed evidence: A file's current hash differs from a trusted reference value.

Potential ATT&CK mapping: None established from the hash mismatch alone.

Reasoning: A hash difference indicates that the compared file contents differ. Legitimate edits, software updates, or an outdated reference could explain the change.

Evidence that could change the assessment:

- An unauthorized modification
- Related execution or persistence artifacts
- Logs connecting the change to suspicious activity

Analyst conclusion: Investigate the change before associating it with a specific adversary technique.
Case ID:
Observed behavior:
Evidence sources:
ATT&CK tactic:
ATT&CK technique and ID:
Official reference:
Supporting evidence:
Contradicting evidence:
Alternative explanations:
Assessment confidence: Low / Medium / High
Reason for confidence rating:
Additional evidence required:

6. Confidence Guidelines

Confidence| Meaning
Low| The mapping is plausible, but important supporting evidence is missing.
Medium| Multiple observations support the mapping, but uncertainty remains.
High| Strong, corroborated evidence closely matches the documented behavior.

These ratings describe confidence in the proposed mapping, not the severity of an incident or the identity of an adversary.

7. Common Mapping Mistakes

- Assigning a technique based on an unusual event alone.
- Confusing a tactic with a technique.
- Treating an alert as confirmation of malicious activity.
- Selecting a technique because it sounds plausible rather than because evidence supports it.
- Ignoring benign explanations or contradictory evidence.
- Claiming an attacker's identity without reliable attribution evidence.

8. Official Resources

- "MITRE ATT&CK — Enterprise Matrix" (https://attack.mitre.org/matrices/enterprise/)
- "MITRE ATT&CK — Techniques" (https://attack.mitre.org/techniques/enterprise/)
- "MITRE ATT&CK — Getting Started" (https://attack.mitre.org/resources/)

Use the official ATT&CK website to verify technique names, identifiers, and descriptions before adding new mappings.

---

Gasha — Learn to investigate. Think critically. Follow the evidence.

5. Mapping Record Template

Use this template when documenting a proposed mapping.
