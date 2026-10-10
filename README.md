# ScamSathi — Digital Scam First-Response & Evidence Assistant

ScamSathi is a student hackathon prototype that helps users screen suspicious messages with transparent rules, organize incident records, preserve uploaded evidence files with SHA-256 hashes, track incident events, verify file integrity, and export a PDF report.

> **Important:** ScamSathi is an educational prototype, not a definitive scam detector, malware scanner, legal opinion, or replacement for official cybercrime reporting. A low score does not prove a message is safe. A hash match does not prove where a file came from or establish legal admissibility.

## Features

- **Explainable message screening:** flags configured text patterns such as urgency, requests for OTP/PIN/CVV, prize claims, payment requests, account threats, and selected URL warning signs.
- **Incident management:** create and review local incident records.
- **Evidence vault:** attach PNG, JPG/JPEG, WEBP, PDF, TXT, and EML files (8 MB request limit).
- **File integrity checks:** computes a SHA-256 hash on upload and can compare the current file against the recorded hash.
- **Incident timeline:** add timestamped events.
- **PDF export:** download a structured report containing incident information, evidence inventory, hashes, and timeline.
- **Local-first storage:** SQLite database and uploaded files are stored under `data/`.

## Requirements

- Python 3.10 or newer
- pip
- Internet connection for the Bootstrap stylesheet and JavaScript CDN when viewing the default UI; the app logic itself does not require an external detection API.

## Setup on Windows (PowerShell)

1. Download or clone this repository and open PowerShell in the project folder.
2. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Start the app:

   ```powershell
   python app.py
   ```

5. Open **http://127.0.0.1:5000** in your browser.

### Setup on macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Then visit `http://127.0.0.1:5000`.

## Run tests

With the virtual environment activated:

```bash
python -m unittest discover -s tests -v
```

## Quick demo script

1. Open **Analyze** and paste the sample message below.
2. Review the risk score and the exact indicators that were triggered.
3. Create an incident using the same message.
4. Upload a test screenshot or a harmless `.txt` file.
5. Verify the SHA-256 hash from the incident page.
6. Add an event to the timeline.
7. Download the PDF report.

Sample text for testing only:

```text
URGENT: Your account will be suspended today. Verify your account immediately.
You have won a prize. Click here: http://example.invalid/claim
Never enter real credentials or follow sample links.
```

The `.invalid` domain is reserved for examples and should not resolve to a real website.

## Repository structure

```text
ScamSathi/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── data/
│   └── .gitkeep
├── static/
│   └── style.css
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── analyze.html
│   ├── new_incident.html
│   ├── incident.html
│   └── verify.html
└── tests/
    └── test_analysis.py
```

Runtime data and generated reports are created inside `data/`. The `.gitignore` excludes runtime files so incident data and uploaded evidence are not committed accidentally.

## How the screening score works

The screening engine uses visible regular-expression rules and adds configured points for matching indicators. The score is capped at 100 and grouped into broad indicator levels. It is not trained machine learning and it does not query threat-intelligence services.

- **High (60–100):** multiple warning indicators; do not interact before independent verification.
- **Elevated (30–59):** pause and verify through a trusted channel.
- **Lower indicator count (0–29):** fewer configured patterns matched; this is not a safety guarantee.

False positives and false negatives are possible. Attackers can use new wording or legitimate-looking infrastructure. The app should be presented as a first-response aid, not an automated verdict.

## Evidence integrity limitations

- SHA-256 helps detect whether the bytes in the stored file differ from the bytes hashed at upload time.
- A matching hash alone does not prove the original source, capture time, sender identity, authenticity, or chain of custody.
- This prototype does not digitally sign logs, use trusted timestamps, encrypt the evidence vault, or implement multi-user access control.
- Do not use it as a production forensic evidence system without security review and stronger custody controls.

## Privacy and security notes

- Do not enter passwords, OTPs, payment card details, or unnecessary personal data.
- Uploaded evidence is saved on the machine running the app. Anyone with filesystem access may be able to read it.
- The built-in Flask server is for local development only. Do not expose it directly to the public internet.
- Before deploying publicly, add authentication and authorization, CSRF protection, encrypted storage, rate limits, audit controls, a production WSGI server, HTTPS, and a retention/deletion policy.
- Files are restricted by extension and request size, but this is not full malware scanning. Use harmless test files for demos.

## Suggested future improvements

- Optional reputation checks through a trusted threat-intelligence API (with user consent and clear disclosure).
- More robust URL parsing and IDN/domain similarity analysis.
- Secure user authentication and encrypted evidence storage.
- Signed, append-only audit events and trusted timestamps.
- Multilingual scam-pattern packs and accessible local-language guidance.
- Integration links to official reporting resources with clear disclaimers.

## Official reporting (India)

For suspected financial cyber fraud in India, contact your bank/payment provider immediately and use official government cybercrime reporting channels. The national cybercrime helpline **1930** is used for reporting financial cyber fraud. Verify current procedures through official government sources before relying on them.

## License

MIT License — see `LICENSE`.
