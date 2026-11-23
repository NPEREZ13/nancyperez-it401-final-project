"""Threat name choices shared by the HTML forms."""

THREAT_NAME_OPTIONS = (
    "Phishing attack",
    "Ransomware attack",
    "Malware infection",
    "Data breach",
    "Credential theft",
    "Business email compromise",
    "Denial-of-service attack",
    "Unauthorized account access",
    "Software vulnerability exploitation",
    "Insider threat",
)


def selected_threat_name(form):
    choice = form.get("name_choice")
    if choice is None or choice == "other":
        return form.get("name", "")
    if choice not in THREAT_NAME_OPTIONS:
        raise ValueError("Choose a threat name or select Other.")
    return choice
