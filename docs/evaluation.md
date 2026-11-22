# Evaluation

How well Trailsight's six rules work on CloudTrail data I did not write myself.
Run on 2026-11-22 against Trailsight 0.1.0 (commit 84b727c). No rule was
changed for or during this evaluation.

## Summary

| Question | Result |
|---|---|
| Labelled attacks the rules claim to cover, caught by the intended rule | 6 of 9 |
| Same attacks, caught by at least one correct finding from any rule | 8 of 9 |
| All 53 labelled attack samples, at least one correct finding | 17 of 53 |
| Findings on the attack samples that were correct (TP and BTP over all decided) | 38 of 206 (18%) |
| Findings on 1.9 million real events from a public AWS challenge | 11,319 (5.8 per 1,000 events) |
| Of those, attacker activity / correct but authorised / wrong | 56 / 8,328 / 2,935 |
| Detection speed, 1.9 million events | 2.3 s for the rules, 20 s including reading the files |

In short: the rules for disabled logging and root activity are accurate. The MFA
rule is mostly wrong because it fires on failed logins and federated sessions.
The leaked credentials rule misses the attacks it is named for and fires on
Lambda. Root activity is reported once per API call, which buries everything
else. The first three fixes have since been made (see Fixed since); the rest
are listed at the end. All of them still need testing on data that was not
used to find them.

## Data

**Splunk attack_data** ([github.com/splunk/attack_data](https://github.com/splunk/attack_data),
Apache-2.0). Splunk's threat research team publishes CloudTrail recorded while
simulating attacks, labelled by MITRE ATT&CK technique. I took every
raw AWS CloudTrail sample in the repository: 56 files. Two were Splunk search
exports rather than CloudTrail and one was a byte-identical copy of another, so
53 samples remain (29,893 events). The samples are short and come from the
attack itself, with some normal background activity in a few of them.

**flaws.cloud logs** ([summitroute.com](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/)).
Scott Piper's public AWS security challenges flaws.cloud and flaws2.cloud hand
out deliberately leaked credentials, and he published the account's full
CloudTrail from February 2017 to October 2020: 1,939,207 events from 9,402
source addresses. It is real traffic: strangers attacking the account, the owner maintaining it, and AWS's own services. It has
no labels and the IP addresses are anonymised.

`evaluation/fetch_data.py` downloads both and checks every file against
`evaluation/checksums.sha256`.

## Method

1. **Labels first.** Before running anything, I labelled each Splunk sample in
   [`evaluation/labels.csv`](../evaluation/labels.csv) from its name and
   contents: *in scope* when one of Trailsight's rules is documented as
   covering that attack (9 samples), otherwise *out of scope* (44). Seven out
   of scope samples are marked as adjacent to a rule, for example privilege
   escalation through a new policy version, which the privilege escalation
   rule does not look for.
2. **Run unchanged.** Each sample and the whole flaws.cloud set went through
   the normal rule engine.
3. **Triage every finding.** Each finding got one verdict, using the usual
   security operations terms:
   - **TP**: fired on attacker activity
   - **BTP** (benign true positive): what the rule says is true, but the
     activity was authorised, such as the account owner using root
   - **FP**: what the rule says is wrong, such as "login without MFA" for a
     login that failed
   - **UNCLEAR**: the data cannot settle it

   The triage criteria are code ([`evaluation/triage.py`](../evaluation/triage.py)),
   so every verdict is reproducible and carries its reason. I wrote them after
   reading the findings, so they are my judgement, not ground truth.

## Detection on labelled attacks

| Attack sample | Rule that should fire | Caught | Why not |
|---|---|---|---|
| Console login with one factor | console_mfa | yes | |
| CloudTrail stopped and deleted | security_controls | yes | |
| GuardDuty and WAF deleted | security_controls | yes | |
| Cloud security scanner | recon | yes | |
| Enumeration producing access denied | recon | yes | |
| Excessive List calls | recon | yes | |
| Bedrock model enumeration | recon | no | 12 calls, the threshold is 15 |
| One session from two addresses | leaked_credentials | no | each session has its own temporary key, and the rule groups by key |
| Console logins from several addresses | leaked_credentials | no | console logins have no access key, so the rule never sees them |

The two leaked credentials misses still produced a correct finding from another
rule (root activity, and a root login without MFA), which is why 8 of 9 had at
least one correct finding.

Across all 53 samples, 17 got at least one correct finding. Of the 7 samples
next to a rule's territory, 2 were caught, both because the file also contained
a `DeleteTrail` or `StopLogging` call. Weakening a trail with `UpdateTrail`,
deleting its log group, expiring the log bucket, and both policy version
escalations were missed.

## Accuracy of findings on the attack samples

| Rule | TP | FP | Unclear | Correct |
|---|---|---|---|---|
| security_controls | 9 | 0 | 0 | 100% |
| root_usage | 10 | 1 | 0 | 91% |
| recon | 9 | 4 | 7 | 69% of decided |
| console_mfa | 10 | 162 | 0 | 6% |
| leaked_credentials | 0 | 1 | 4 | 0 of 1 decided |
| **All** | **38** | **168** | **11** | **18%** |

- **console_mfa**: 70 of the false positives were failed logins, where nobody
  signed in. The other 92 were federated or role sessions, where MFA happens at
  the identity provider and CloudTrail records `MFAUsed: No` regardless.
- **recon**: four of the nine true positives were real attacks with the wrong
  name. Downloading 100 S3 objects, pulling 650 log batches or reading Windows
  passwords counts as "enumeration" because the API names start with `Get`.
  The false positives were AWS Auto Scaling, AWS Config and a Kubernetes
  cluster. The unclear ones are administrators clicking around the EC2 console,
  which makes dozens of `Describe` calls a page.
- **leaked_credentials**: the one false positive counted `AWS Internal` as a
  second location.

## Real traffic: flaws.cloud

| Rule | Findings | TP | BTP | FP |
|---|---|---|---|---|
| root_usage | 10,935 | 0 | 8,304 | 2,631 |
| leaked_credentials | 346 | 47 | 14 | 285 |
| console_mfa | 19 | 0 | 2 | 17 |
| recon | 15 | 7 | 6 | 2 |
| security_controls | 3 | 2 | 1 | 0 |
| privilege_escalation | 1 | 0 | 1 | 0 |
| **All** | **11,319** | **56** | **8,328** | **2,935** |

- **root_usage** produced 97% of all findings. It makes one finding per API
  call, so the owner's 61 days of root use became 10,935 findings. 2,631 of
  them were AWS Support, sign-in or CloudTrail acting on the account's behalf.
- **leaked_credentials** caught 47 real uses of the challenge's leaked keys
  from several places. 279 of its false positives were a Lambda function:
  Lambda runs each invocation on different hosts with a fresh key, so every
  invocation looked like a stolen key.
- **recon** fired on 7 challenge players and on the owner's own audit tools
  (Security Monkey, CloudSploit). It only reports the first burst for each
  identity, so the challenge's EC2 role, used from 651 addresses, produced one
  finding over three years.
- **security_controls**: two of the three were `StopLogging` calls that AWS
  denied. They are worth seeing, but the finding says logging was stopped,
  which is not true.

A useful alert stream would have shown the 56 attacks. This one buried them
under 11,263 other findings.

## Speed

On an Intel Core i7-14700F with 32 GB of RAM, Python 3.14, the whole
flaws.cloud set (1,939,207 events, 241 MB gzipped):

| Stage | Time | Rate |
|---|---|---|
| Read and decompress JSON | 12.7 s | |
| Build events | 4.7 s | |
| Run all six rules | 2.3 s | 856,000 events a second |
| End to end | 19.7 s | 98,000 events a second |

Peak Python memory was about 7.8 GB (4 KB an event), measured in a separate
run, because every raw record is kept in memory twice. Fine for a small account, a problem for years of logs from a busy one.

## Fixed since

Changes 1 to 3 below were made on 2026-11-22, with tests. Everything else in
this document describes 0.1.0 before them.

| Measure | 0.1.0 | After fixes 1 to 3 |
|---|---|---|
| In scope attacks caught by the intended rule | 6 of 9 | 8 of 9 |
| Findings on attack samples | 217 | 49 |
| Of those, TP / FP / unclear | 38 / 168 / 11 | 32 / 4 / 13 |
| flaws.cloud findings | 11,319 | 145 |
| Of those, TP / BTP / FP | 56 / 8,328 / 2,935 | 56 / 85 / 4 |

- Both leaked credentials misses are now caught: root and console sign-ins are
  grouped by identity as well as by key. Triage still marks them unclear,
  because it has no way to tell those two addresses were an attacker; the
  labels say they were.
- Root activity is one finding per day: 10,935 findings became 63, and the
  same 61 days of owner activity are all still there.
- No attack finding was lost on flaws.cloud: still 56.
- Two root findings are still false positives: days where every call came
  from an AWS console backend, which the rule does not yet recognise.
- To judge grouped root findings fairly, triage now checks every call in the
  day, not only the first. Re-running triage on 0.1.0 gives the same numbers
  as above.

This is the same data that exposed the problems, so these figures show the
fixes do what they were meant to, not how well they generalise. The fresh-data
check described below still applies.

## What to change

Each of these came from a finding above. 1 to 3 are done (see Fixed since).

1. **console_mfa**: ignore failed logins. Treat federated and role sessions
   separately, since CloudTrail cannot show their MFA.
2. **root_usage**: ignore calls AWS makes on the account's behalf
   (`invokedBy`, `aws-internal`). Group root activity into one finding per
   session or day instead of one per call.
3. **leaked_credentials**: only count real IP addresses. Leave out Lambda
   execution roles. Group by identity and session as well as access key, and
   include console logins, which would have caught both missed attacks.
4. **recon**: count only `Describe` and `List` calls, and move bulk reads of
   one API (`GetObject`, `GetLogEvents`, `GetPasswordData`) to a collection
   rule. Skip AWS service roles. Report every burst, not just the first per
   identity. Consider a lower threshold when most calls are denied.
5. **security_controls**: say "attempted" when AWS denied the call. Add
   `UpdateTrail`, `DeleteLogGroup` and log bucket lifecycle changes.
6. **privilege_escalation**: add `CreatePolicyVersion` and
   `SetDefaultPolicyVersion`.
7. **Loader**: accept one event per line (NDJSON), the format Splunk, Athena
   and CloudTrail Lake exports use. The evaluation had to convert it.
8. **Memory**: stop keeping two copies of every record.

These numbers came from the same data used to find the problems, so re-running
the fixes on it would flatter them. The plan is to check each fix on attacks
detonated in a test account with [Stratus Red Team](https://github.com/DataDog/stratus-red-team)
and on a week of normal activity from a real small account.

## Limits of this evaluation

- **No clean baseline.** Neither dataset is a normal small business account, so
  the false positive rate a real user would see is not measured. flaws.cloud is
  unusually noisy, and mostly attackers.
- **Small labelled set.** Nine in scope samples is enough to find failure
  modes, not to give a reliable detection rate.
- **One person triaged.** I wrote the triage criteria myself after seeing the
  findings. The code and reasons are published so anyone can disagree with a
  verdict.
- **Short samples.** Most Splunk samples hold only the attack, which makes
  detection easier than finding it inside a day of normal traffic.

## Reproduce

    python -m pip install -e .
    python evaluation/fetch_data.py
    python evaluation/run_splunk.py
    python evaluation/run_flaws.py
    python evaluation/run_flaws.py --memory

Results are written to `evaluation/results/`. The committed results match the
current code; check out commit a1a5503 to reproduce the 0.1.0 figures.
