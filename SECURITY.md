# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please do not open a public issue for security problems.

Use GitHub's private vulnerability reporting: go to the **Security** tab of this repository and select **Report a vulnerability**.

Include:
- what you found and where
- steps to reproduce
- the impact you think it has

I will acknowledge reports within 7 days and aim to ship a fix or a mitigation within 30 days, depending on severity.

## Scope

TrailSight parses AWS CloudTrail logs and runs detection rules over them. Reports about log parsing, rule bypasses, the optional Flask dashboard, and dependency issues are all in scope.
