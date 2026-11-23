"""Mitigation choices shared by both HTML threat forms."""

MITIGATION_OPTIONS = (
    "Reset passwords and revoke active sessions.",
    "Enable multifactor authentication.",
    "Install security updates and patches.",
    "Block malicious senders, domains, and IP addresses.",
    "Isolate affected devices and remove malicious software.",
    "Restore affected systems from verified backups.",
    "Review access permissions and restrict unnecessary access.",
    "Train users to recognize phishing and social engineering.",
)


def selected_mitigation(form):
    choice = form.get("mitigation_choice")
    # Preserve compatibility with existing form submissions and integrations.
    if choice is None or choice == "other":
        return form.get("mitigation", "")
    if choice not in MITIGATION_OPTIONS:
        raise ValueError("Choose a mitigation option or select Other.")
    return choice
