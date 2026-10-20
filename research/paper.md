# From SSH Honeypot Telemetry to Digital Forensic Evidence: Session Reconstruction, Timeline Consistency, and Integrity Checks in HyShield

**Manuscript status:** finalized research draft; author metadata, legal review, and venue-specific formatting remain before submission  
**Date:** 21 October 2026

## Abstract

SSH honeypots produce detailed records of authentication attempts and interactive commands, but operational telemetry is not automatically a reliable forensic record. This paper evaluates the forensic handling of Cowrie JSON-lines telemetry in HyShield, a research prototype that routes SSH interactions through a Docker-based command-execution environment and ingests Cowrie events into a SQLite-backed security information and event management (SIEM) dashboard. We combine source-code inspection, ingestion regression tests, and a controlled offline examination of one available log file. The log contains 55 parseable records across six sessions, including 11 command-input events, and all observed source addresses are loopback addresses; it is therefore treated as a local test trace rather than a representative external-attack dataset. A SHA-256 baseline was used to detect changes in controlled copies, while separate simulations examined an appended marker, a deleted event, and a backward-shifted timestamp. The observed copy-integrity check detected the tested modifications, the deletion simulation reduced the event count from 55 to 54 and command-input count from 11 to 10, and the timestamp simulation introduced one chronological decrease in the modified copy. Repository-level regression tests passed in GitHub Actions for repeated polling, incomplete final lines, malformed records, truncation, oversized lines, and source-path switching. Additional source-to-SQLite tests passed for synthetic sessions, including event-payload reconciliation, missing/invalid timestamp retention, duplicate content at different byte offsets, and the inability to infer an event omitted before ingestion without an independent manifest. The repository's read-only audit utility was run against the preserved local trace: its SHA-256 matched the recorded baseline and its counts agreed with the independent profile. These findings demonstrate the value of combining structural validation, timeline checks, and baseline hashing, but do not establish end-to-end forensic soundness or tamper-proof logging. A baseline hash supports comparison against a trusted recorded value; it does not establish event truth, completeness, origin, or legal admissibility.

**Keywords:** digital forensics; SSH honeypot; Cowrie; SIEM; event reconstruction; log integrity; SHA-256; chain of custody

## 1. Introduction

Security logs are routinely used to reconstruct activity after an incident, yet logs are often designed for operations rather than evidential requirements. Their value depends on what is recorded, how events are ordered and correlated, whether missing or malformed records are visible, and whether the records can be related to a preserved source. Recent research has highlighted shortcomings in open-source application logging for security tasks, the need to reason about causal information, and the risks of treating timestamps as unquestionable ground truth [1–4].

SSH honeypots provide a distinctive but bounded observation point. They record activity directed at a decoy service, including connection metadata, authentication attempts, and commands submitted during interactive sessions. These records can support behavioural analysis and hypothesis generation, but they do not automatically prove that a real victim host was compromised or identify the human or organization behind a connection. Source addresses may be proxies, shared infrastructure, local test addresses, or artifacts of a lab topology. Command records show what was submitted to the honeypot, not necessarily what would happen on a production host.

HyShield is a research and educational SSH honeypot framework built around Cowrie. Its command path uses a custom bridge and Docker-based Ubuntu environment, sanitizes selected output, and can optionally refine responses through an AI service. A separate Python SIEM ingests Cowrie JSON-lines records into SQLite and derives session and alert information. The repository documentation characterizes the project as a research prototype and states that the current implementation does not provide blockchain-based logging or a verified privacy-preserving analytics mechanism [8]. The research question is therefore not whether HyShield is already a tamper-proof evidence platform, but which properties of its telemetry and ingestion path can be tested, what the current controls reveal, and what additional controls would be required.

### 1.1 Research questions

- **RQ1:** How do controlled event omissions and timestamp inconsistencies affect reconstruction of SSH honeypot sessions?
- **RQ2:** How effectively do structural validation, chronological consistency checks, and SHA-256 baseline comparison detect faults introduced into copies of honeypot logs?
- **RQ3:** What additional validation is required before the complete HyShield ingestion and SIEM pipeline can be described as forensically reliable?

### 1.2 Contributions

This study provides (i) a source-grounded description of HyShield's telemetry path and relevant ingestion behavior; (ii) a descriptive examination of a 55-record local Cowrie trace and controlled offline fault simulations; (iii) repository-level regression tests for common ingestion edge cases; and (iv) a proposed validation protocol that separates source-file integrity, parser correctness, database retention, event chronology, and evidential provenance.

## 2. Related work

### 2.1 Logging sufficiency

A 2024 study of open-source application logging assessed log relevance across security tasks and reviewed logging practices in 60 applications, emphasizing that ordinary application logs may not contain what forensic or incident-response tasks require [1]. Structured fields alone do not guarantee that records are complete, causally sufficient, or independently verifiable. In 2025, research on logging sufficiency proposed recording causal information through “gretel numbers” and an eBPF/Nginx prototype, arguing that cross-application correlation is difficult when conventional records omit causal links [2]. HyShield's session identifiers and event identifiers are useful for grouping and ingestion, but they are not cryptographic provenance proofs.

### 2.2 Timeline reconstruction

Timeline reconstruction commonly sorts records by timestamps, but timestamps can be skewed or manipulated. Vanini et al. discuss time anchors and time anomalies as a way to reason about clock correctness during event reconstruction [3]. Work on implicit timing information demonstrates that line position, sequence numbers, and relations between events may provide ordering evidence even where timestamps are absent or unreliable [4]. These studies motivate checking both timestamp order and source-file order. A backward timestamp is an anomaly to investigate, not proof of malicious tampering: clock skew, buffering, concurrent event production, or collection effects may also explain it.

### 2.3 Evidence integrity and honeypots

ECo-Bag applies Merkle-tree structures to a digital evidence container to support integrity checking and provenance tracking [5]. This is a possible future direction, but HyShield's current implementation must not be described as using a Merkle tree or blockchain for evidence integrity. Q-Cowrie explores reinforcement learning to adapt honeypot behavior [6], and a 2026 dataset paper documents large-scale interactive SSH honeypot telemetry [7]. These works illustrate ongoing interest in honeypot behavior and datasets; they do not validate HyShield's forensic pipeline. The trace examined here is much smaller and locally generated, and its results must not be generalized to Internet-scale attacks.

## 3. System and threat model

### 3.1 System overview

The repository describes the following logical path: an authorized SSH client interacts with Cowrie; a modified backend sends command requests over a local TCP socket to the HyShield bridge; the bridge invokes a Docker command executor; selected output is sanitized and may optionally be passed through an AI refiner; Cowrie records the interaction in a JSON-lines log; and the Python SIEM tails the log, stores records in SQLite, and displays investigation information. The honeypot response path and SIEM ingestion path are distinct components. The SIEM ingests telemetry; it is not the component that executes submitted commands.

The SIEM ingestor tracks a source-file checkpoint using inode, file path, and byte offset. It reads complete newline-terminated records, waits for incomplete trailing records, applies a line-size limit, records malformed or oversized input as ingestion errors, and inserts parsed records into a raw-events table. Event IDs are generated from file path, inode, byte offset, and line content for deduplication; the oversized-record marker uses a SHA-256 digest of location metadata. These generated identifiers are not hashes of the source evidence and must not be represented as proof that the source log is unchanged. Downstream session processing orders events by timestamp, making timestamp anomalies relevant to interpretation.

### 3.2 Adversary and failure model

We consider accidental or deliberate changes to a working copy of a log after collection, including append, deletion, timestamp alteration, malformed JSON, duplicated polling, truncation, oversized lines, and source-path changes. We also consider ordinary collection and software failures such as incomplete final writes and source-file replacement. Not every failure is assumed to be malicious. An adversary who can modify the log, the database, the baseline hash, and the system recording custody is outside the protection provided by a plain local SHA-256 comparison.

### 3.3 Trust boundaries

Three boundaries must remain distinct:

1. **Honeypot observation:** the event describes activity as recorded by the decoy service.
2. **Ingestion and storage:** the event is parsed, deduplicated, and persisted by the SIEM.
3. **Forensic preservation:** an examiner preserves a source copy, records acquisition metadata, calculates a digest, documents custody, and protects the baseline independently.

Passing a test at one boundary does not prove the next boundary is sound.

## 4. Materials and methods

### 4.1 Study design

We used three evidence sources: (1) inspection of repository source and documentation on branch audit/forensic-ingestion-tests; (2) GitHub Actions results for the Python SIEM regression tests; and (3) offline inspection and controlled modification of an available cowrie.json JSON-lines trace. The offline experiments operated on disposable copies; the original file was retained unchanged during the reported tests. No live Internet attack campaign was conducted, and the tests do not exercise the entire deployed stack.

### 4.2 Trace and privacy

The trace contains 55 parseable JSON records, six distinct session identifiers, and 11 cowrie.command.input records. The observed timestamp range is 2026-05-18 21:58:44.672 UTC to 22:13:26.631 UTC. All observed source IP values are 127.0.0.1; connection records also use loopback context. This is consistent with a local test trace and prevents treating it as evidence of remote adversary activity. The trace includes submitted credential values, which must be redacted from any public artifact or manuscript supplement. The raw log is not reproduced here.

The recorded SHA-256 fingerprint of the examined source file is:

    43F659EB94216AC20BFB8A17EB7043341295AC8ADD435DCDB25E1C8A4DF13DA4

This digest is a reproducibility identifier for the specific examined file, not a public proof of provenance or a substitute for a custody record. On 21 October 2026, the repository audit utility was executed against the preserved working copy with this value supplied as the baseline. It reported a match, 55 JSON-object records, zero malformed/non-object lines, zero missing event IDs, zero missing or invalid timestamps, zero timestamp decreases in file order, six sessions, and 11 command-input events. This establishes consistency with the supplied digest; the digest's trustworthiness depends on how the baseline was originally recorded and protected.

### 4.3 Descriptive profiling

We counted JSON records by event type and summarized per-session counts and timestamp spans. The six sessions had 4, 4, 12, 10, 14, and 11 records, respectively. Command-input counts per session were 0, 0, 2, 1, 6, and 2. The reported session spans were 0.045 s, 2.694 s, 36.607 s, 12.272 s, 184.046 s, and 13.075 s. These descriptive values characterize only this trace.

### 4.4 Controlled fault simulations

Four copy-level checks were reported:

1. **Append detection:** a marker was appended to a disposable copy and its digest recalculated.
2. **Event omission:** one command-input record from anonymized Session E was removed from a disposable copy.
3. **Timestamp anomaly:** the timestamp of one command-input event in a disposable copy was changed to 2026-05-18T22:00:00.000000Z, creating one backward chronological step in file order.
4. **Baseline preservation:** hashes of the preserved source and unmodified working copy were compared; controlled copies were not written back to the preserved source.

These are offline copy-level simulations. They are not an end-to-end test of database tampering, log rotation under concurrent writes, clock synchronization, or the deployed Docker/Cowrie environment.

### 4.5 Repository regression tests

The test module python-siem/tests/test_forensic_ingestion.py exercises repeated polling, incomplete final lines, malformed records followed by valid records, truncation, oversized lines, valid JSON values that are not objects, appending an event, and switching source paths. The additional python-siem/tests/test_forensic_pipeline_reconciliation.py exercises the actual Ingestor-to-SQLite path with synthetic events, including source/database row reconciliation, missing and invalid timestamp retention, repeated identical JSON content at different byte offsets, and an intentionally omitted upstream event. The tests demonstrate a key limit: without an independent upstream manifest, an event absent before ingestion cannot be inferred from the rows that were ingested. Tests use an isolated temporary SQLite database. A separate read-only utility, python-siem/scripts/forensic_audit.py, reports a file SHA-256, optional baseline match, event counts, session counts, malformed-line counts, missing/invalid timestamp and event-ID counts, and timestamp decreases in file order. It deliberately omits command contents, passwords, and IP addresses from its report. Timestamp parsing requires an explicit timezone and normalizes accepted timestamps to UTC; timezone-naive values are counted as invalid rather than compared ambiguously. The utility's automated tests cover baseline matches and mismatches, chronology anomalies, malformed records, missing fields, and payload redaction. GitHub Actions run the test suite, dependency audit, and static security scan. The configured test suite, dependency audit, and static security scan passed on the commit that added the source-to-SQLite reconciliation tests (run 39483080807). Subsequent changes to the manuscript and reproducibility ledger are documentation-only. The CI tests use synthetic records and do not claim to validate the live Docker/Cowrie deployment end to end. The successful workflow covering the source-to-SQLite reconciliation tests is available at [GitHub Actions run 39483080807](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/39483080807). The CI outcome demonstrates that the configured checks passed on that branch and commit; it does not prove all possible behaviors have been tested.

### 4.6 Measures

The evaluation uses descriptive event counts, session summaries, observed backward timestamp steps, and digest comparisons. For each controlled fault, we record whether the specific check reacted as expected. We do not calculate generalized detection rates or false-positive rates because the current set of manually conducted copy simulations is too small and lacks a defined representative sample of fault-free and faulted cases.

## 5. Results

### 5.1 Source-trace profile

| Event type | Count |
|---|---:|
| cowrie.session.connect | 6 |
| cowrie.session.closed | 6 |
| cowrie.client.version | 6 |
| cowrie.client.kex | 6 |
| cowrie.client.var | 8 |
| cowrie.client.size | 4 |
| cowrie.login.success | 4 |
| cowrie.login.failed | 1 |
| cowrie.command.input | 11 |
| cowrie.log.closed | 3 |
| **Total** | **55** |

The loopback-only source context means the trace is best interpreted as a local integration/test artifact.

| Session ID | Records | Command-input events | Span (s) |
|---|---:|---:|---:|
| Session A | 4 | 0 | 0.045 |
| Session B | 4 | 0 | 2.694 |
| Session C | 12 | 2 | 36.607 |
| Session D | 10 | 1 | 12.272 |
| Session E | 14 | 6 | 184.046 |
| Session F | 11 | 2 | 13.075 |

The original file order had zero observed timestamp decreases. This is a consistency observation only; it does not establish that the source clock was correct. Session spans are calculated from recorded timestamps and have not been independently validated against an external time source.

### 5.2 Copy-level integrity and fault observations

The preserved source and its unmodified working copy had matching SHA-256 values in the recorded experiment. Appending a marker changed the copy digest from 43F659...4DF13DA4 to BFFDF7EE0654C994E2022DB3FE9D46A1CEDBD2241182D505A5EDA95226411352. This is consistent with the expected behavior of a cryptographic digest when file content changes.

The event-omission simulation changed the copy from 55 to 54 records and reduced command-input events from 11 to 10. The altered copy's digest was 09E13730D0320483905446133D7A96324CF95AF69C44FA9D2961F3C752EDB3AE, while the original baseline remained unchanged. This demonstrates that the recorded comparison detects the changed copy and that a count comparison can expose the simulated omission when the expected baseline counts are known. It does not show that an investigator can detect an omission when no trusted baseline or independent source exists.

The timestamp simulation changed the number of observed timestamp decreases from zero in the original to one in the modified copy. This demonstrates that a chronological consistency check can flag the particular introduced anomaly. It does not determine whether an unexplained anomaly in a real trace is caused by clock drift, concurrency, delayed writes, tampering, or another factor.

### 5.3 Automated regression checks

The GitHub Actions run completed successfully for all configured stages: Python test suite, dependency audit, and static security scan. The forensic-oriented tests cover eight ingestion edge cases plus four source-to-SQLite reconciliation/fault-boundary cases using synthetic records. Their scope is limited to the ingestion component and does not validate the full deployed SIEM pipeline. These tests provide regression protection for the specified cases, not proof of completeness or security.

## 6. Discussion

### 6.1 Interpretation of a hash

A cryptographic hash is useful when the examiner has a trusted reference digest, records when and how it was calculated, and protects that reference independently from the evidence. If a later digest differs, the bytes being compared differ with overwhelming practical likelihood. If the digests match, that supports byte-for-byte consistency with the hashed reference. Neither outcome establishes that the source was truthful when created, that it recorded every event, that the asserted source identity is genuine, or that the evidence was acquired lawfully. A local hash stored beside a modifiable log can be replaced by an adversary with access to both.

### 6.2 Session reconstruction is not identity attribution

Session IDs and timestamps support grouping and ordering. They do not independently identify a human actor. The examined trace's loopback-only IP addresses are a clear reason not to characterize the observed sessions as remote attacks. Even when a production deployment records routable source addresses, attribution requires corroboration and careful treatment of NAT, VPNs, proxies, shared infrastructure, and compromised hosts.

### 6.3 Database ingestion creates a second evidential layer

The SIEM stores parsed events and derived session information. A reliable evaluation should compare the preserved source file with database rows and document the mapping between each source record and each stored record. Existing ingestion tests verify important behaviors, including that repeated polling does not duplicate rows and that an incomplete trailing record is not checkpointed prematurely. Further testing is required for database alteration, retention cleanup, inode reuse, concurrent truncation or rotation, partial batch boundaries, timestamp ties, and timezone parsing. The new source/database reconciliation tests cover selected synthetic cases only. The event ID used for deduplication is derived from file location and line content rather than a signed evidence chain, so it should be treated as an application-level identifier.

### 6.4 Implications for forensic practice

A practical evidence workflow should preserve the original log read-only; record acquisition time, system clock and timezone, source path, file size, collector version, and operator; calculate SHA-256 at acquisition; protect the baseline in a separate access-controlled location; record every transfer and transformation; maintain the raw log alongside parsed derivatives; and document known gaps and parser errors. Timeline interpretation should combine timestamps with file order, session relations, and independent time anchors where available. A Merkle-tree evidence container is a possible future direction, but it must be implemented and evaluated rather than claimed as an existing HyShield feature.

### 6.5 Legal and evidential caution

This paper does not give a legal opinion or assert admissibility in any jurisdiction. In Pakistan, Article 164 of the Qanun-e-Shahadat Order 1984 may be relevant to evidence made available through modern devices or techniques, but application to a particular electronic record depends on facts, procedure, and current judicial interpretation. In the United States, Federal Rules of Evidence 901 and 902(13)–(14) address authentication of evidence and certain electronic processes or copied data; authentication is not the same as satisfying hearsay, relevance, reliability, or other requirements. In England and Wales, the Criminal Justice Act 2003 includes statutory provisions governing hearsay, including section 114, but hearsay rules are only one part of evidential analysis. A honeypot log may be useful as an investigative lead while still requiring a witness or expert to explain collection, system behavior, limitations, and continuity of custody. Specialist legal review against current law and case law is required before real proceedings.

## 7. Limitations

The evaluation is limited in several respects. First, the available trace is small (55 records), local, and loopback-only; it is not a representative external-attack dataset. Second, the offline fault simulations are controlled examples, not a statistically designed benchmark. Third, the successful CI run validates only the configured environment and synthetic tests. Fourth, source-to-database reconciliation covers selected synthetic cases rather than a comprehensive fault matrix; database tampering by a privileged adversary, production clock synchronization, and full live Docker/Cowrie/SIEM operation were not evaluated. Fifth, the legal discussion is a high-level comparison and not jurisdiction-specific legal advice. Finally, results from one repository branch and one trace cannot establish that every deployment or version of HyShield behaves identically.

## 8. Future work

The next stage should implement a repeatable test harness that generates known-good and fault-injected JSONL traces, records ground truth, runs them through the actual SIEM ingestor, and compares source events with SQLite rows and dashboard output. The matrix should include deletion, duplication, reordering, missing timestamps, invalid timestamps, malformed JSON, oversized lines, truncation, log rotation, inode reuse, source-path switching, database modification, and retention cleanup. Each test should report detection outcome, false alarms on fault-free inputs, records accepted/rejected, source-to-database retention, session reconstruction differences, and runtime. A larger evaluation should use a public or ethically collected SSH honeypot dataset and document whether it represents lab, simulated, or external activity. Further engineering could add append-only audit records, signed manifests, independent timestamping, access-controlled baseline storage, and a Merkle-based evidence package, followed by tests against a threat model that includes compromise of the SIEM host.

## 9. Conclusion

This study provides an initial, bounded forensic evaluation of HyShield's Cowrie telemetry and SIEM ingestion path. The examined trace contained 55 parseable records across six sessions, but loopback-only source addresses require it to be treated as a local test trace. Controlled copy modifications changed the expected SHA-256 digest; an event-omission simulation reduced record and command counts; and a timestamp modification introduced a chronological decrease. Repository regression tests and configured CI audits passed for the tested ingestion edge cases. These results support a modest conclusion: combining a trusted hash baseline, structural checks, and chronology checks can expose certain changes and inconsistencies in honeypot log copies. They do not establish that telemetry is complete, truthful, tamper-proof, attributable to a real-world actor, or legally admissible. The complete SIEM pipeline still requires systematic source-to-database fault injection and stronger provenance controls before stronger forensic claims can be justified.

## Data and code availability

HyShield code and forensic-oriented ingestion tests are maintained in the [project repository](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution). The examined trace contains credential material and is not reproduced here. Any public release should use a reviewed, credential-redacted derivative and document the transformation and digest separately. The branch used for this draft is audit/forensic-ingestion-tests; the cited CI run is linked in the Methods section.

## Ethics and security

The work uses an existing honeypot trace and controlled offline copies. No public target was attacked. Credential values are intentionally omitted. Future external data collection should be limited to authorized honeypot infrastructure and should include privacy review, retention rules, and safe publication practices.

## References

1. Azahari, A., & Balzarotti, D. (2024). “On the inadequacy of open-source application logs for digital forensics.” *Forensic Science International: Digital Investigation*, 49, 301750. https://doi.org/10.1016/j.fsidi.2024.301750
2. Olegård, J., Axelsson, S., & Li, Y. (2025). “When is logging sufficient? Tracking event causality for improved forensic analysis and correlation.” *Forensic Science International: Digital Investigation*, 52, 301877. https://doi.org/10.1016/j.fsidi.2025.301877
3. Vanini, C., Hargreaves, C. J., van Beek, H., & Breitinger, F. (2024). “Was the clock correct? Exploring timestamp interpretation through time anchors for digital forensic event reconstruction.” *Forensic Science International: Digital Investigation*, 49, 301759. https://doi.org/10.1016/j.fsidi.2024.301759
4. Dreier, L. M., Vanini, C., Hargreaves, C. J., Breitinger, F., & Freiling, F. (2024). “Beyond timestamps: Integrating implicit timing information into digital forensic timelines.” *Forensic Science International: Digital Investigation*, 49, 301755. https://doi.org/10.1016/j.fsidi.2024.301755
5. Han, J., Han, M. L., Lee, S., & Park, J. (2024). “ECo-Bag: An elastic container based on Merkle tree as a universal digital evidence bag.” *Forensic Science International: Digital Investigation*, 49, 301725. https://doi.org/10.1016/j.fsidi.2024.301725
6. Var Naseri, M., Welch, I., Haseeb, J., & Mansoori, M. (2026). “Q-Cowrie: An adaptive honeypot to analyse attackers' behaviour.” *International Journal of Information Security*, 25, article 60. https://doi.org/10.1007/s10207-026-01221-5
7. Boiko, V., & Niiakyi, O. (2026). “A 4-month dataset of interactive SSH honeypot logs and command payloads.” *Data in Brief*, 66, 112860. https://doi.org/10.1016/j.dib.2026.112860
8. HyShield Project. “HyShield: Hybrid AI-Driven SSH Honeypot with Dockerized Command Execution and Python SIEM Dashboard.” GitHub repository documentation and source code, accessed 21 October 2026. https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution

9. Pakistan. *Qanun-e-Shahadat Order, 1984*, Article 164. The current official text and relevant judicial interpretation must be checked before submission.
10. Pakistan. *Electronic Transactions Ordinance, 2002*. Official Gazette/current consolidated text should be checked before relying on a particular provision.
11. United States. *Federal Rules of Evidence*, Rules 901 and 902(13)–(14). Official rules: https://www.uscourts.gov/rules-policies/current-rules-practice-procedure/federal-rules-evidence
12. United Kingdom. *Criminal Justice Act 2003*, Part 11, Chapter 2, including section 114. Official legislation: https://www.legislation.gov.uk/ukpga/2003/44/part/11/chapter/2

## Author submission checklist

- Confirm author order, affiliations, correspondence details, and contributions.
- Select the target journal/conference and reformat to its template and citation style.
- Re-verify every reference and current legal authority before submission.
- Redact credential material from any dataset, screenshot, or appendix.
- The repository audit utility and selected source-to-SQLite tests have been run; re-run and archive the manually reported copy-level fault simulations because those simulations are not automatically reproduced by CI.
- Add quantitative fault-injection metrics only after executing a defined test matrix and retaining its raw outputs.
- Have a supervisor/co-author review the interpretation and legal section.
