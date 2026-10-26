"""Category choices shared by both threat forms."""

CATEGORY_OPTIONS = (
    "Phishing", "Ransomware", "Malware", "Data Breach", "Credential Theft",
    "Social Engineering", "Vulnerability", "Denial of Service",
    "Unauthorized Access", "Insider Threat",
)


def selected_category(form):
    choice = form.get("category_choice")
    if choice is None or choice == "other":
        return form.get("category", "")
    if choice not in CATEGORY_OPTIONS:
        raise ValueError("Choose a category or select Other.")
    return choice
