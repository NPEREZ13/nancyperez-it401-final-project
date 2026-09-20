# ThreatLense

- **Application:** ThreatLense
- **Student:** Nancy Perez
- **Course:** IT401
- **Assignment:** Semester Project

## Project Overview

ThreatLense is a Flask-based cybersecurity intelligence dashboard for students, junior analysts, and small organizations. It combines local demonstration threats with two external information sources so users can explore common threats, check the reputation of a public IP address, and review historical data breaches in one responsive interface.

ThreatLense is an educational project, not a replacement for a security operations platform or a definitive security advisory. Results should be verified with additional trusted sources before action is taken.

## External Information Sources

### API Freaks IP Threat Intelligence API

The IP Threat Checker acquires real-time external IP-security information from the [API Freaks IP Threat Intelligence API](https://apifreaks.com/api/ip-threat-intelligence). The server sends a validated public IPv4 or IPv6 address to the API and requests only the threat score, VPN, proxy, Tor, anonymity, known-attacker, bot, spam, and cloud-provider fields.

The API key is read from the `APIFREAKS_API_KEY` environment variable and sent in the server-side `X-apiKey` header. It is never placed in frontend code or an API query parameter.

### Wikipedia Data Breach List

The Data Breach Intelligence section acquires external public breach data by scraping the tables on Wikipedia's [List of data breaches](https://en.wikipedia.org/wiki/List_of_data_breaches). The application keeps only the organization or entity, year, records affected, organization type, and breach method. It removes citation markers and formatting, converts missing values to `Unknown`, removes empty and duplicate rows, and never displays raw HTML.

Successful scraped results are cached in memory for one hour. Scraping failures are cached for one minute to prevent repeated requests during a temporary outage.

## Application Workflow

1. A visitor opens the Flask dashboard.
2. Local demonstration threats are loaded from `data/threats.json` for the Explore page.
3. The dashboard requests the cleaned breach dataset from the scraper service. A recent cached copy is reused when available.
4. The user can search breach organizations or filter records by year and organization type. The initial table is limited to 15 records.
5. On the Analyze IP page, the user enters an IPv4 or IPv6 address.
6. The server validates that the input is a publicly routable address before making an external request.
7. The server calls API Freaks with the IP as the `ip` query parameter and the secret API key in the `X-apiKey` header.
8. ThreatLense validates the JSON response, calculates Low, Medium, or High Risk, and displays security findings and a short recommendation.

Risk classifications are:

| Threat score | Classification |
| --- | --- |
| 0–19 | Low Risk |
| 20–74 | Medium Risk |
| 75–100 | High Risk |

## Information Model

ThreatLense currently uses three logical record types.

### Local threat record

| Attribute | Description |
| --- | --- |
| `id` | Unique local threat identifier |
| `name` | Human-readable threat name |
| `category` | Threat category |
| `severity` | Critical, high, medium, or another supported level |
| `target` | Commonly affected industries, systems, or users |
| `description` | Summary of the behavior or risk |
| `mitigation` | Recommended defensive action |

### IP threat result

| Attribute | Description |
| --- | --- |
| `ip` | Validated public IPv4 or IPv6 address |
| `score` | API Freaks threat score from 0 to 100 |
| `risk_level` | Low Risk, Medium Risk, or High Risk |
| `findings` | Boolean VPN, proxy, Tor, anonymity, attacker, bot, spam, and cloud signals |
| `cloud_provider` | Cloud-provider name when available |
| `recommendation` | Short action based on the score and findings |

### Data breach record

| Attribute | Description |
| --- | --- |
| `entity` | Organization, agency, or other affected entity |
| `year` | Reported breach year |
| `records_affected` | Reported number or description of affected records |
| `organization_type` | Sector or organization classification |
| `breach_method` | Reported cause or method |

## Environment Variables

Create a `.env` file in the project root. A safe template is provided in `.env.example`.

```dotenv
APIFREAKS_API_KEY=your-api-key-here
```

| Variable | Required | Purpose |
| --- | --- | --- |
| `APIFREAKS_API_KEY` | Required for IP analysis | Authenticates server-side API Freaks requests |
| `SECRET_KEY` | Recommended for deployment | Overrides Flask's development secret |
| `FLASK_ENV` | Optional | Selects `development`, `production`, or the default configuration |
| `AI_SERVICE_API_KEY` | Not currently used | Reserved for a possible future AI service |

The `.env` file is ignored by Git. Never commit real keys, paste them into templates, or expose them in browser-side JavaScript.

## Installation Instructions

### Prerequisites

- Python 3.10 or newer
- Git
- An API Freaks account and key for the IP Threat Checker
- Internet access for API and Wikipedia requests

### 1. Clone the repository

```bash
git clone https://github.com/NPEREZ13/nancyperez-it401-final-project.git
cd nancyperez-it401-final-project
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

macOS or Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure the API key

Copy `.env.example` to `.env`, then replace the placeholder with your API Freaks key.

### 5. Run the application

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

### 6. Run the tests

```bash
python -m pytest
```

## Current Features

- Responsive cybersecurity dashboard, navigation, and shared page layout
- Local JSON threat cards with keyword, severity, and category filtering
- Threat brief and About pages
- IPv4 and IPv6 input with public-address validation
- Server-side API Freaks integration using a protected request header
- Threat scoring, risk badges, security-signal cards, and recommendations
- Loading indicator and disabled Analyze IP button during requests
- Wikipedia breach-table scraping and cleanup into structured dictionaries
- Organization search plus year and organization-type breach filters
- Fifteen-record initial breach display with responsive table styling
- One-hour successful scrape cache and one-minute failure cache
- Automated route, API-client, parser, filtering, error, and caching tests

## Error Handling

The interface displays helpful messages instead of raw exceptions for:

- Empty, malformed, private, reserved, loopback, or link-local IP addresses
- Missing API configuration
- API authentication, authorization, credit, rate-limit, and server failures
- Network failures and request timeouts
- Empty API responses, invalid JSON, malformed fields, and out-of-range scores
- Wikipedia request and timeout failures
- Missing Wikipedia tables
- Changed tables with missing expected columns
- Valid tables that contain no usable breach records

External response bodies and secret values are not displayed to users. Both external requests use explicit timeouts.

## Ethical Considerations

- IP reputation is contextual and can change. A high score is an indicator, not proof that a person or organization is malicious.
- Shared networks, VPNs, proxies, Tor, and cloud infrastructure can produce legitimate traffic. Decisions should not rely on this tool alone.
- The IP checker performs a passive reputation lookup; it does not scan, probe, or attack the submitted address.
- Wikipedia data is public, attributed to its source, requested with an identifying user agent, and cached to reduce unnecessary traffic.
- Wikipedia is community-maintained and may contain incomplete, disputed, or outdated information.
- API keys and other credentials must remain private and must not be committed to source control.
- Breach information should be used for education and defensive awareness, not harassment or unauthorized activity.

## Known Limitations

- API Freaks requires a valid key, available account credits, and network access.
- Threat scores and security flags depend on the external provider's coverage and update schedule.
- Only publicly routable IP addresses are accepted; internal network addresses cannot be analyzed.
- Wikipedia's list is dynamic and non-exhaustive, and its table structure may change.
- The in-memory scrape cache resets whenever the Flask process restarts and is not shared across multiple server processes.
- Only the first 15 matching breach records are displayed; there is no pagination yet.
- Local threat records are demonstration data rather than live advisories.
- The project does not currently use a database or retain IP-analysis history.

## Screenshots

The repository currently includes these screenshot files:

### Homepage

![ThreatLense homepage](docs/screenshots/homepage.png)

### Explore Page

![ThreatLense Explore page](docs/screenshots/explore.png)

### Filtering Feature

![ThreatLense severity filtering](docs/screenshots/filter.png)

Screenshots for the new **IP Threat Checker** and **Data Breach Intelligence** sections have not been provided yet and still need to be captured and added to `docs/screenshots/`.

## Future Work

- Add pagination or incremental loading for the breach dataset
- Store optional IP-analysis history in a database without retaining unnecessary personal data
- Add timestamps showing when external information was retrieved
- Add persistent caching suitable for multi-process production deployments
- Add more local threat records and detail pages
- Add charts for breach years, organization types, and methods
- Add screenshots for the IP Threat Checker and Data Breach Intelligence sections
- Expand integration and accessibility testing

## Project Structure

```text
threatlense/
|-- app.py
|-- config.py
|-- requirements.txt
|-- data/
|   `-- threats.json
|-- routes/
|   `-- main.py
|-- services/
|   |-- data_breaches.py
|   `-- ip_threat.py
|-- static/
|   |-- ip_checker.js
|   `-- style.css
|-- templates/
|   |-- analyze_ip.html
|   |-- base.html
|   |-- index.html
|   |-- explore.html
|   |-- menu.html
|   `-- about.html
|-- tests/
|   |-- test_app.py
|   |-- test_data_breaches.py
|   `-- test_ip_threat.py
`-- README.md
```
