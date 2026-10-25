Gasha — Analyst Field Manual

«Observe carefully. Question assumptions. Follow the evidence.»

1. The Analyst's Mission

A cybersecurity analyst investigates suspicious activity, evaluates evidence, and communicates findings clearly.

The goal is not to prove that every alert is an attack. It is to determine what the available evidence supports, what remains uncertain, and what should happen next.

2. The Five-Step Investigation Method

Step 1 — Observe

Record what actually happened before interpreting it.

Ask:

- What event was recorded?
- When did it occur?
- Which account, system, or resource was involved?
- Where did the information come from?
- Is the timestamp reliable and in the expected time zone?

Field rule: Separate directly observed facts from assumptions.

Step 2 — Form Hypotheses

Develop plausible explanations for the observation.

For example, an unusual login might indicate:

- Legitimate activity outside normal working hours
- A different work schedule or time zone
- Unauthorized use of an account

Do not select a conclusion merely because it sounds alarming.

Step 3 — Correlate Evidence

Look for related events that help distinguish between competing explanations.

Depending on the case, review:

- Authentication records
- Application and system logs
- Network activity
- File integrity records
- Relevant changes or maintenance history

Check timestamps, data sources, and inconsistencies before drawing conclusions.

Step 4 — Assess

Evaluate the strength and limitations of the evidence.

Consider:

- Does the evidence support the hypothesis?
- Is there independent corroboration?
- Are there plausible alternative explanations?
- What information is missing?
- What would change the current assessment?

Use confidence ratings consistently. High confidence should reflect strong supporting evidence, not simply a large quantity of weak indicators.

Step 5 — Report

Communicate the result so another analyst can understand and review the investigation.

A useful report includes:

- The original observation
- Relevant supporting and conflicting evidence
- The assessment and confidence level
- Actions taken and their authorization
- Unresolved questions
- Recommended next steps

A conclusion should be traceable to the evidence that supports it.

3. Evidence vs. Interpretation

One of the most important analyst skills is distinguishing facts from what those facts might mean.

Example observation: An authentication log records a successful login at 02:14 UTC.

Interpretation: The login occurred outside the account's usual activity window.

Possible hypothesis: The account may have been used without authorization.

What is not yet established: Who controlled the session or whether the activity was malicious.

The investigation should seek additional evidence before confirming compromise.

4. Evaluating Evidence Quality

Assess each piece of evidence using these questions:

Factor| Question to ask
Reliability| Is the source trustworthy and functioning correctly?
Relevance| Does the evidence relate directly to the question being investigated?
Integrity| Has the evidence been preserved without unauthorized alteration?
Corroboration| Do independent sources support the same conclusion?
Context| Could normal activity explain the observation?
Limitations| What can this evidence not establish?

No single factor automatically determines the value of evidence. Consider the full context.

5. Confidence Levels

Low confidence

The explanation is plausible, but supporting evidence is limited or important information is missing.

Medium confidence

Several observations support the explanation, although alternative explanations or evidence gaps remain.

High confidence

Strong, relevant, and preferably corroborated evidence supports the assessment, with major alternatives reasonably addressed.

Confidence is not the same as severity. An incident may have potentially serious consequences while the evidence is still uncertain.

6. Common Analyst Traps


The trap: Looking only for evidence that supports the first theory.

Better approach: Actively search for contradictory evidence and plausible alternatives.

Alert equals attack

The trap: Treating every alert as a confirmed security incident.

Better approach: Validate the alert against the available evidence and context.

Single-indicator reasoning

The trap: Declaring a compromise based on one unusual login, hash mismatch, or suspicious message.

Better approach: Correlate relevant observations before reaching a conclusion.

Unsupported attribution

The trap: Claiming to know who conducted an attack without sufficient evidence.

Better approach: Describe the observed behavior and clearly state the limits of attribution.

False certainty

The trap: Reporting a definitive conclusion when evidence remains incomplete.

Better approach: Communicate uncertainty and identify what additional evidence is needed.

7. Practical Case Review

Scenario: A file's current hash differs from its trusted reference hash.

Observation: The two hash values do not match.

Possible explanations:

- An authorized file update
- A legitimate document modification
- An outdated reference hash
- An unauthorized change

Next steps:

1. Verify that the reference hash is authentic and current.
2. Establish whether the file was expected to change.
3. Review available file metadata and relevant logs.
4. Preserve evidence and escalate unexplained changes when appropriate.

Defensible conclusion: The file contents differ from the trusted reference. The reason for the difference remains unconfirmed.

8. Analyst Report Template

Case ID:
Analyst:
Date and time:
Investigation question:

Observations

What do the available records directly show?

Hypotheses

What are the plausible explanations?

Supporting Evidence

Which observations support each explanation?

Conflicting Evidence

What contradicts the leading hypothesis?

Assessment

What conclusion is currently justified, and with what confidence?

Limitations

What remains unknown?

Recommended Actions

What should be verified, monitored, or escalated next?

9. Final Field Checklist

Before closing an investigation, confirm that:

- [ ] Observations are separated from interpretations.
- [ ] Important evidence sources are documented.
- [ ] Plausible alternative explanations were considered.
- [ ] The conclusion is supported by the evidence.
- [ ] Uncertainty and limitations are stated clearly.
- [ ] Recommended actions are appropriate and authorized.
- [ ] Another analyst could review the reasoning.

---
Gasha, learnt to investigate. Think critically. follow the evidenvce 







ha — Learn to investigate. Think critically. Follow the evidence.
Confirmation bias
