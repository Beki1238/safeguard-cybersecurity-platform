Gasha — Detection Rulebook

«A practical reference for designing, testing, and improving cybersecurity detection logic.»

1. Purpose

Detection rules help analysts identify activity that may indicate a security threat. A useful rule describes what to look for, which data is required, why the activity matters, and how to investigate an alert.

Core principle: A detection identifies suspicious behavior; it does not automatically prove malicious intent.

2. Anatomy of a Detection Rule

Each rule should define:

- Rule ID: A unique identifier.
- Rule name: A clear description of the behavior.
- Objective: What the rule aims to detect.
- Data source: The logs or telemetry required.
- Detection logic: The conditions that trigger an alert.
- Severity: The initial priority of the alert.
- False-positive considerations: Legitimate behavior that may match.
- Investigation steps: How an analyst should validate the alert.

3. Example Detection Rules

DET-001 — Unusual Login Time

Objective: Identify successful logins outside an account's expected activity window.

Data source: Authentication logs containing account identity, timestamp, and login result.

Detection logic:

- Identify successful authentication events.
- Compare event times with the account's established activity pattern.
- Generate an alert when a login falls outside the expected window.

Initial severity: Low to Medium, depending on context.

Possible false positives:

- Different work schedules
- Travel or time-zone differences
- Authorized maintenance or emergency access

Investigation steps:

1. Verify the event timestamp and time zone.
2. Review related authentication events.
3. Check whether the activity was authorized.
4. Escalate if corroborating evidence suggests unauthorized access.

Limitation: Unusual timing alone does not establish account compromise.

DET-002 — Repeated Failed Logins

Objective: Identify repeated authentication failures that may indicate password guessing or another authentication issue.

Data source: Authentication logs containing account, timestamp, source, and outcome.

Detection logic:

- Count failed authentication attempts within a defined time window.
- Alert when the count exceeds a documented threshold.
- Group related events by account and, where appropriate, source.

Initial severity: Low to High, depending on volume, affected accounts, and supporting evidence.

Possible false positives:

- A user repeatedly entering an incorrect password
- An outdated application using expired credentials
- Misconfigured automated services

Investigation steps:

1. Check the number and timing of failures.
2. Determine whether multiple accounts or systems are involved.
3. Look for a successful login following the failures.
4. Review surrounding events before assigning a conclusion.

Limitation: Repeated failures can have benign explanations and do not independently confirm an attack.

DET-003 — File Integrity Mismatch

Objective: Detect a difference between a file's current hash and a trusted reference hash.

Data source: File-integrity monitoring records or a trusted baseline.

Detection logic:

- Calculate the file's hash using an approved algorithm.
- Compare it with the trusted reference.
- Alert when the values differ.

Initial severity: Medium, adjusted for the file's importance and the context of the change.

Possible false positives:

- An authorized software update
- An approved document edit
- A changed or outdated reference baseline

Investigation steps:

1. Verify that the reference hash is authentic and current.
2. Check whether a change was authorized.
3. Review file metadata and related system logs.
4. Escalate unexplained changes affecting critical files.

Limitation: A hash mismatch proves that the compared file contents differ; it does not, by itself, prove malware.
- [ ] The detection objective is clearly defined.
- [ ] Required log fields are available.
- [ ] Thresholds and time windows are documented.
- [ ] Expected benign matches have been considered.
- [ ] Test events produce the expected results.
- [ ] Analysts have clear investigation steps.
- [ ] Rule changes are version-controlled and reviewed.

5. Measuring Detection Performance

True positive: The alert correctly identifies activity that meets the defined malicious-behavior criteria.

False positive: The alert fires on activity that does not meet those criteria.

False negative: Relevant malicious activity occurs without the rule generating an alert.

Detection coverage: The range of behaviors a rule or collection of rules is designed to identify.

Detection quality depends on more than alert volume. Rules should be evaluated for accuracy, coverage, data quality, and usefulness to analysts.

6. Detection Rule Lifecycle

1. Define: Identify the behavior and threat scenario.
2. Design: Specify data requirements and detection conditions.
3. Test: Validate the rule against representative events.
4. Deploy: Release through the authorized change process.
5. Monitor: Review alert quality and missed detections.
6. Refine: Adjust logic as systems and threats change.
7. Retire: Document and remove obsolete rules through the approved process.

7. Important Limitations

These examples describe detection concepts, not production-ready rules. Real deployments require environment-specific fields, tested thresholds, reliable log collection, access controls, and ongoing validation.

---

Gasha — Learn to investigate. Think critically. Follow the evidence.
4. Detection Quality Checklist

Before deploying a rule, verify that:
