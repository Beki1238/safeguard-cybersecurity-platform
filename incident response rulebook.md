Gasha — Incident Response Runbook

«Purpose: A practical guide for investigating, assessing, and responding to potential cybersecurity incidents using evidence-based decisions.»

1. Core Principles

- Evidence first: Base conclusions on available evidence, not assumptions.
- Preserve integrity: Keep original logs and evidence intact whenever possible.
- Least privilege: Perform only actions authorized for your role.
- Document everything: Record observations, decisions, timestamps, and actions.
- Verify before concluding: A suspicious event is not automatically a confirmed attack.

2. Incident Response Workflow

Phase 1 — Identify

Recognize and record the suspicious activity.

Collect relevant details, such as:

- Alert name and unique reference ID
- Date and time, including the time zone
- Affected account, host, application, or service
- Relevant log entries and indicators
- Source of the alert

Output: An initial incident record.

Phase 2 — Triage and Assess

Determine the potential severity and urgency of the event.

Consider:

- Is there evidence of unauthorized access?
- Which systems or accounts may be affected?
- Is the activity ongoing?
- Could the event have a legitimate explanation?
- What additional evidence is needed?

Use the following initial severity guide:

Severity| Description
Critical| Credible evidence of a major, ongoing incident affecting critical systems
High| Strong indicators of compromise or significant potential impact
Medium| Suspicious activity requiring further investigation
Low| Limited-risk event or an alert with little supporting evidence

Severity is provisional and should be updated as evidence changes.

Phase 3 — Investigate

Build a timeline and test possible explanations.

1. Review relevant authentication, network, endpoint, and application logs.
2. Correlate timestamps and events across available sources.
3. Compare observed activity with the account or system's expected behavior.
4. Identify supporting and conflicting evidence.
5. Record alternative explanations and remaining uncertainties.

Investigation rule: An indicator is a clue, not proof by itself.

Phase 4 — Contain

If a genuine incident is reasonably suspected, escalate to the authorized security team and follow the organization's response procedures.

Depending on the incident, authorized responders may:

- Restrict a compromised account.
- Isolate an affected device.
- Block a confirmed malicious indicator.
- Limit access to an affected service.

Before taking action, consider business impact, evidence preservation, and approval requirements. Do not make disruptive changes to systems you are not authorized to manage.

Phase 5 — Eradicate and Recover

After the incident has been assessed and containment is approved:

- Remove the confirmed cause of the incident.
- Address exploited vulnerabilities or unsafe configurations.
- Reset affected credentials when appropriate.
- Restore systems using trusted recovery procedures.
- Validate system functionality and monitor for recurring activity.

Recovery should be verified rather than assumed complete.

Phase 6 — Report and Improve

Close the investigation only when the evidence and remaining risks have been reviewed.

Document:

- What happened and when
- Which systems or accounts were affected
- Evidence supporting the conclusion
- Actions taken and their authorization
- Recovery and verification results
- Outstanding risks and recommended improvements

Record lessons learned to improve future detection and response.

3. Evidence Handling Checklist

- [ ] Record the evidence source and collection time.
- [ ] Preserve original records where possible.
- [ ] Document who collected or handled the evidence.
- [ ] Record hashes when appropriate to help verify file integrity.
- [ ] Restrict access to sensitive evidence.
- [ ] Maintain a clear chain of custody when formal evidence handling is required.
- [ ] Incident ID:
Date and time detected:
Analyst:
Affected asset or account:
Initial severity:
Current status:

Observed Evidence

List the facts directly supported by logs, alerts, or other sources.

Assessment

Explain what the evidence suggests, including alternative explanations and confidence level.

Actions Taken

Record actions, timestamps, authorization, and results.

Conclusion

State whether the incident is confirmed, suspected, a false positive, or unresolved. Explain the reasoning.

Recommendations

List follow-up actions, monitoring needs, and improvements.

5. Example Investigation

Scenario: A fictional account successfully logs in at 02:14 UTC, outside its usual recorded working hours.

Observed evidence

- The authentication log records a successful login.
- The timestamp differs from the account's usual activity pattern.
- The available record does not establish who controlled the session.

Assessment

The login is unusual and warrants investigation. However, the timestamp alone does not prove account compromise. A different work schedule, time-zone issue, or authorized activity could explain the event.

Recommended next steps

1. Verify the timestamp and source of the log.
2. Review related authentication events and available session details.
3. Check whether the activity was authorized.
4. Escalate if additional evidence indicates unauthorized access.
5. Document the final assessment and its supporting evidence.

Example conclusion: Suspicious activity requiring verification; compromise is not yet confirmed.

6. Operational Reminders

- Do not confuse an alert with a confirmed incident.
- Do not treat a single indicator as conclusive proof.
- Do not delete, alter, or expose evidence unnecessarily.
- Do not perform containment or recovery actions without appropriate authorization.
- Reassess severity when new evidence becomes available.

7. References

- "NIST Computer Security Incident Handling Guide — SP 800-61 Rev. 2" (https://csrc.nist.gov/pubs/sp/800/61/r2/final)
- "CISA — Incident Response" (https://www.cisa.gov/topics/cyber-threats-and-advisories/incident-response)

---

Gasha — Learn to investigate. Think critically. Follow the evidence.

4. Analyst Incident Report Template

Use this structure for each investigation.
