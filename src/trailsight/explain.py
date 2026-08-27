from dataclasses import replace

INSTRUCTION = (
    "You are a security analyst. Explain the finding below using ONLY the "
    "evidence provided. Do not invent facts, names, or events that are not "
    "listed. Cover what happened, why it is suspicious, and how to respond. "
    "Be concise and concrete.\n\n"
)


def _event_line(event):
    parts = [
        f"- {event.time.isoformat()} {event.name}",
        f"from {event.source_ip}",
        f"in {event.region}",
    ]
    if event.access_key_id:
        parts.append(f"using key {event.access_key_id}")
    if event.error_code:
        parts.append(f"failed with {event.error_code}")
    return " ".join(parts)


def build_prompt(finding):
    lines = [
        f"Rule: {finding.rule}",
        f"Severity: {finding.severity}",
        f"Title: {finding.title}",
        f"Identity: {finding.identity}",
        f"Summary: {finding.description}",
        "Evidence events:",
    ]
    lines.extend(_event_line(event) for event in finding.events)
    return INSTRUCTION + "\n".join(lines)


class ExplanationError(Exception):
    pass


def explain_finding(finding, provider):
    return provider.complete(build_prompt(finding))


def explain_all(findings, provider):
    return [replace(finding, explanation=explain_finding(finding, provider))
            for finding in findings]
