# 🔐 Password Strength Analyzer

A beginner-friendly cybersecurity mini project built with **Python** and **Streamlit**.
It analyzes a password locally, explains its rating with a transparent scoring system,
and gives specific tips for improving it.

> ⚠️ **Educational estimate only.** This tool cannot guarantee that a password will
> resist real-world cracking attempts.

## Features

- Password input with show/hide (eye icon) and a Clear button
- Checks: length, uppercase, lowercase, numbers, special characters
- Detects repeated characters, sequences (`abc`, `123`), keyboard patterns (`qwer`),
  and "Word + Numbers" shapes (`Summer2024`)
- Compares against a small local list of common passwords and words (including simple
  leetspeak such as `p@ssw0rd`)
- Five labels: Very Weak, Weak, Moderate, Strong, Very Strong
- Dark navy / teal cybersecurity dashboard with strength meter, checklist, and recommendations
- Educational section: password strength, length, unique passwords, password managers, MFA
- Unit tests with made-up example passwords

## Tech Stack

Python 3.9+, Streamlit, `re` (regular expressions), `unittest`

## Project Structure

```
password-strength-analyzer/
├── .streamlit/config.toml
├── app.py
├── tests.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation (Windows + VS Code)

```powershell
cd password-strength-analyzer
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

```powershell
streamlit run app.py
```

Open the local URL shown in the terminal (usually http://localhost:8501), type a
password, and press **Enter**. Do not test real passwords you use.

## Run the Tests

```powershell
python tests.py
```

## How Scoring Works

| Category | Max points | How points are earned |
|---|---|---|
| Length | 50 | <6: 0, 6-7: 5, 8-9: 15, 10-11: 25, 12-15: 40, 16+: 50 |
| Character variety | 20 | 5 points each for uppercase, lowercase, digit, special |
| Pattern avoidance | 30 | Start at 30, minus 10 for each: repeats, sequences, keyboard patterns, "Word+Numbers" shape |

**Caps** can lower the final score:

| Condition | Maximum score / label |
|---|---|
| Under 6 characters | 20 (Very Weak) |
| Under 8 characters | 44 (Weak) |
| Exactly matches a common password | 10 (Very Weak) |
| Contains a very common word | 44 (Weak) |
| Under 12 characters | 84 (cannot be Very Strong) |

**Labels:** 0-24 Very Weak · 25-44 Weak · 45-64 Moderate · 65-84 Strong · 85-100 Very Strong

## Privacy & Security

- Passwords are never written to files, databases, logs, or browser storage.
- No external APIs or AI services are used.
- The analysis result object never contains the password.
- Streamlit usage statistics are disabled in `.streamlit/config.toml`.
- Strength is estimated with rules, **not** by hashing the password.

## Limitations

- Rule-based estimate, not a real cracking simulation (not a replacement for tools like zxcvbn).
- The common-password list is small and local, so many leaked passwords will not be detected.
- Does not detect names, birthdays, or personal information.
- Streamlit sends the typed text from your browser to the Python process. **Run it locally.**
  If you deploy it publicly, passwords would travel to that server, so do not do that
  without understanding the risks.
- The result updates when you press Enter or click away, not on every keystroke.

## Screenshots

| Dashboard | Strong password result |
|---|---|
| ![Dashboard](screenshots/dashboard.png) | ![Strong result](screenshots/strong.png) |

*(Create a `screenshots/` folder and add your own images.)*

## Future Improvements

- Larger offline common-password list
- Estimated "time to crack" ranges with clear caveats
- Passphrase generator

## License

MIT
