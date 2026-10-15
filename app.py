"""
Password Strength Analyzer
--------------------------
An educational tool that estimates password strength using transparent rules.

PRIVACY: The password is only analyzed in memory while the app runs. It is
never printed, logged, saved to a file/database, or sent to any API.

This is an EDUCATIONAL ESTIMATE, not a guarantee against password cracking.
"""

import re
from dataclasses import dataclass, field

import streamlit as st

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

MIN_RECOMMENDED_LENGTH = 12
MAX_INPUT_LENGTH = 128

# Small local list of very common passwords (examples only, not real users').
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "qwerty", "qwerty123", "qwertyuiop", "abc123", "111111", "000000",
    "123123", "654321", "666666", "121212", "admin", "admin123",
    "letmein", "welcome", "welcome1", "iloveyou", "iloveu", "monkey",
    "dragon", "football", "baseball", "master", "sunshine", "princess",
    "login", "starwars", "trustno1", "shadow", "superman", "qazwsx",
    "changeme", "default", "test123", "hello123", "freedom", "whatever",
    "zaq12wsx", "1q2w3e4r",
}

# Very common words that make a password easy to guess when they appear inside it.
COMMON_WORDS = (
    "password", "qwerty", "letmein", "welcome", "admin", "login",
    "iloveyou", "monkey", "dragon", "football", "sunshine", "princess",
)

# Keyboard rows, used to detect patterns like "qwer" or "asdf".
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")

# Maps common "leetspeak" substitutions back to letters (p@ssw0rd -> password).
LEET_MAP = str.maketrans(
    {"@": "a", "4": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t",
     "1": "i", "!": "i"}
)

# Score ranges: (exclusive upper bound, label)
LABEL_THRESHOLDS = [
    (25, "Very Weak"),
    (45, "Weak"),
    (65, "Moderate"),
    (85, "Strong"),
]

LABEL_COLORS = {
    "Very Weak": "#ef4444",
    "Weak": "#f97316",
    "Moderate": "#eab308",
    "Strong": "#14b8a6",
    "Very Strong": "#22c55e",
}

# Maximum points per scoring category (total = 100)
MAX_LENGTH_POINTS = 50
MAX_VARIETY_POINTS = 20
MAX_PATTERN_POINTS = 30


# ----------------------------------------------------------------------------
# Result container
# ----------------------------------------------------------------------------

@dataclass
class PasswordAnalysis:
    """Holds the results of an analysis. It never stores the password itself."""
    score: int
    label: str
    length: int
    checklist: list = field(default_factory=list)     # [(description, passed)]
    suggestions: list = field(default_factory=list)   # [text, ...]
    length_points: int = 0
    variety_points: int = 0
    pattern_points: int = 0
    cap_reason: str = ""   # Explains if a rule lowered the final score


# ----------------------------------------------------------------------------
# Individual checks (each one is a small, simple function)
# ----------------------------------------------------------------------------

def has_uppercase(password: str) -> bool:
    """True if the password contains at least one A-Z letter."""
    return bool(re.search(r"[A-Z]", password))


def has_lowercase(password: str) -> bool:
    """True if the password contains at least one a-z letter."""
    return bool(re.search(r"[a-z]", password))


def has_digit(password: str) -> bool:
    """True if the password contains at least one 0-9 digit."""
    return bool(re.search(r"[0-9]", password))


def has_special(password: str) -> bool:
    """True if the password has a character that is not a letter or digit."""
    return bool(re.search(r"[^A-Za-z0-9]", password))


def has_repeated_chars(password: str) -> bool:
    """
    True if the same character appears 3+ times in a row (e.g. 'aaa'),
    or if the whole password is one chunk repeated (e.g. 'abcabc').
    """
    triple = re.search(r"(.)\1{2,}", password)
    repeated_chunk = re.fullmatch(r"(.+?)\1+", password)
    return bool(triple or repeated_chunk)


def has_sequence(password: str, run_length: int = 3) -> bool:
    """
    True if the password has an ascending or descending run of letters or
    digits, such as 'abc', 'cba', '123' or '987'.
    """
    text = password.lower()
    for i in range(len(text) - run_length + 1):
        chunk = text[i:i + run_length]
        if not chunk.isalnum():
            continue
        steps = [ord(chunk[j + 1]) - ord(chunk[j]) for j in range(run_length - 1)]
        if all(s == 1 for s in steps) or all(s == -1 for s in steps):
            return True
    return False


def has_keyboard_pattern(password: str, run_length: int = 4) -> bool:
    """True if the password contains 4+ neighbouring keys, e.g. 'qwer'."""
    text = password.lower()
    for row in KEYBOARD_ROWS:
        for line in (row, row[::-1]):  # check both directions
            for i in range(len(line) - run_length + 1):
                if line[i:i + run_length] in text:
                    return True
    return False


def _normalize(password: str) -> str:
    """Lowercase and undo simple substitutions (p@ssw0rd -> password)."""
    return password.lower().translate(LEET_MAP)


def is_common_password(password: str) -> bool:
    """True if the whole password is in our small common-password list."""
    return password.lower() in COMMON_PASSWORDS or _normalize(password) in COMMON_PASSWORDS


def contains_common_word(password: str) -> bool:
    """True if the password contains a very common word like 'password'."""
    lowered, normalized = password.lower(), _normalize(password)
    return any(word in lowered or word in normalized for word in COMMON_WORDS)


def has_word_digit_structure(password: str) -> bool:
    """
    True for the very predictable shape 'Letters + Digits (+ symbols)',
    such as 'Summer2024' or 'Welcome1!'. Attackers try these shapes first.
    """
    return bool(re.fullmatch(r"[A-Za-z]+[0-9]+[^A-Za-z0-9]*", password))


# ----------------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------------

def length_points(password: str) -> int:
    """Length is the biggest factor, so it gets up to 50 of the 100 points."""
    n = len(password)
    if n >= 16:
        return 50
    if n >= 12:
        return 40
    if n >= 10:
        return 25
    if n >= 8:
        return 15
    if n >= 6:
        return 5
    return 0


def score_to_label(score: int) -> str:
    """Convert a 0-100 score into one of the five strength labels."""
    for upper_bound, label in LABEL_THRESHOLDS:
        if score < upper_bound:
            return label
    return "Very Strong"


def analyze_password(password: str) -> PasswordAnalysis:
    """
    Analyze a password and return a PasswordAnalysis.

    Score = length points (0-50) + variety points (0-20) + pattern points (0-30)
    Then "caps" may lower the score (e.g. a common password can never be strong).
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    n = len(password)

    # Nothing typed yet
    if n == 0:
        return PasswordAnalysis(
            score=0, label="Very Weak", length=0,
            suggestions=["Enter a password to see feedback."],
        )

    # --- Run all checks ---
    upper, lower = has_uppercase(password), has_lowercase(password)
    digit, special = has_digit(password), has_special(password)
    repeated = has_repeated_chars(password)
    sequence = has_sequence(password)
    keyboard = has_keyboard_pattern(password)
    structure = has_word_digit_structure(password)
    common_exact = is_common_password(password)
    common_word = contains_common_word(password)

    # --- Points ---
    len_pts = length_points(password)
    var_pts = 5 * sum([upper, lower, digit, special])           # max 20
    issues = sum([repeated, sequence, keyboard, structure])
    pat_pts = max(0, MAX_PATTERN_POINTS - 10 * issues)          # 30 minus 10 per issue
    raw_score = len_pts + var_pts + pat_pts

    # --- Caps: rules that limit the score no matter how many points were earned ---
    caps = []  # (maximum allowed score, explanation)
    if n < 6:
        caps.append((20, "Passwords shorter than 6 characters are capped at Very Weak."))
    elif n < 8:
        caps.append((44, "Passwords shorter than 8 characters are capped at Weak."))
    if common_exact:
        caps.append((10, "This matches a very common password, so it is capped at Very Weak."))
    elif common_word:
        caps.append((44, "It contains a very common word, so it is capped at Weak."))
    if n < MIN_RECOMMENDED_LENGTH:
        caps.append((84, "Passwords shorter than 12 characters cannot reach Very Strong."))

    score, cap_reason = raw_score, ""
    if caps:
        limit, reason = min(caps, key=lambda c: c[0])
        if raw_score > limit:
            score, cap_reason = limit, reason

    # --- Checklist (shown in the dashboard) ---
    checklist = [
        (f"At least {MIN_RECOMMENDED_LENGTH} characters", n >= MIN_RECOMMENDED_LENGTH),
        ("Contains an uppercase letter (A-Z)", upper),
        ("Contains a lowercase letter (a-z)", lower),
        ("Contains a number (0-9)", digit),
        ("Contains a special character (!@#$...)", special),
        ("No repeated characters or repeated chunks", not repeated),
        ("No obvious sequences (abc, 123)", not sequence),
        ("No keyboard patterns (qwer, asdf)", not keyboard),
        ("Not a common password / common word", not (common_exact or common_word)),
        ("Not a predictable 'Word + Numbers' shape", not structure),
    ]

    # --- Suggestions (static text only; the password is never echoed) ---
    suggestions = []
    if n < MIN_RECOMMENDED_LENGTH:
        suggestions.append(
            "Make it longer: aim for 12+ characters. A passphrase of 4+ random "
            "words is long and easier to remember."
        )
    if not (upper and lower):
        suggestions.append("Mix uppercase and lowercase letters.")
    if not digit:
        suggestions.append("Add one or more numbers, placed unpredictably (not just at the end).")
    if not special:
        suggestions.append("Add a symbol or separator such as - _ ! or a space.")
    if repeated:
        suggestions.append("Avoid repeating the same character (aaa) or repeating a chunk (abcabc).")
    if sequence:
        suggestions.append("Avoid predictable sequences like abc, 123 or 987.")
    if keyboard:
        suggestions.append("Avoid keyboard patterns such as qwer or asdf.")
    if common_exact:
        suggestions.append("This is a commonly used password. Choose something completely different.")
    elif common_word:
        suggestions.append("Avoid common words (like 'password' or 'welcome'), even with extra characters.")
    if structure:
        suggestions.append(
            "Avoid the 'Word + Numbers + Symbol' shape (like Summer2024!). "
            "Attackers try it early."
        )
    if not suggestions:
        suggestions.append(
            "Looks good! Use it for ONE account only, store it in a password "
            "manager, and turn on multi-factor authentication."
        )

    return PasswordAnalysis(
        score=score, label=score_to_label(score), length=n,
        checklist=checklist, suggestions=suggestions,
        length_points=len_pts, variety_points=var_pts, pattern_points=pat_pts,
        cap_reason=cap_reason,
    )


# ----------------------------------------------------------------------------
# User interface (Streamlit)
# ----------------------------------------------------------------------------

def inject_css() -> None:
    """Add a little custom styling on top of the theme in .streamlit/config.toml."""
    st.markdown(
        """
        <style>
        .block-container {padding-top: 2rem; max-width: 1100px;}
        .app-title {font-size: 2.3rem; font-weight: 800; color: #e6f1ff; margin-bottom: 0;}
        .app-title span {color: #14b8a6;}
        .subtitle {color: #8ba3c7; margin-top: 0.2rem;}
        .meter-wrap {background: #0a192f; border: 1px solid #1d3557;
                     border-radius: 12px; height: 22px; overflow: hidden;}
        .meter-fill {height: 100%; border-radius: 12px; transition: width 0.4s ease;}
        .badge {display: inline-block; padding: 0.25rem 0.9rem; border-radius: 999px;
                font-weight: 700; color: #0a192f; font-size: 1.05rem;}
        .score-text {color: #8ba3c7; margin-left: 0.7rem;}
        .check-row {padding: 0.35rem 0; border-bottom: 1px solid #1d3557; color: #e6f1ff;}
        .ok {color: #22c55e; font-weight: 700;}
        .bad {color: #ef4444; font-weight: 700;}
        </style>
        """,
        unsafe_allow_html=True,
    )


def clear_password() -> None:
    """Button callback: empties the input box."""
    st.session_state["pw_input"] = ""


def render_meter(score: int, label: str) -> None:
    """Draw the colored strength bar. Only the score/label are used, never the password."""
    color = LABEL_COLORS[label]
    html = (
        f'<div class="meter-wrap"><div class="meter-fill" '
        f'style="width:{score}%;background:{color};"></div></div>'
        f'<p style="margin-top:0.7rem;"><span class="badge" style="background:{color};">'
        f'{label}</span><span class="score-text">Score: {score}/100</span></p>'
    )
    st.markdown(html, unsafe_allow_html=True)


def render_checklist(checklist: list) -> None:
    """Show each requirement with a green check or red cross."""
    rows = ""
    for description, passed in checklist:
        icon = '<span class="ok">✔</span>' if passed else '<span class="bad">✘</span>'
        rows += f'<div class="check-row">{icon}&nbsp;&nbsp;{description}</div>'
    st.markdown(rows, unsafe_allow_html=True)
    st.caption(
        "Character variety helps, but it does not guarantee security. "
        "Length and unpredictability matter most."
    )


def render_results(analysis: PasswordAnalysis) -> None:
    """Show the dashboard: meter, score breakdown, checklist, recommendations."""
    left, right = st.columns(2)

    with left:
        with st.container(border=True):
            st.subheader("Strength")
            render_meter(analysis.score, analysis.label)
            st.caption(f"Length: {analysis.length} characters")

            st.markdown("**Why this rating?**")
            st.progress(analysis.length_points / MAX_LENGTH_POINTS,
                        text=f"Length: {analysis.length_points}/{MAX_LENGTH_POINTS}")
            st.progress(analysis.variety_points / MAX_VARIETY_POINTS,
                        text=f"Character variety: {analysis.variety_points}/{MAX_VARIETY_POINTS}")
            st.progress(analysis.pattern_points / MAX_PATTERN_POINTS,
                        text=f"Pattern avoidance: {analysis.pattern_points}/{MAX_PATTERN_POINTS}")
            if analysis.cap_reason:
                st.warning(analysis.cap_reason)

    with right:
        with st.container(border=True):
            st.subheader("Requirements checklist")
            render_checklist(analysis.checklist)

    with st.container(border=True):
        st.subheader("Recommendations")
        st.markdown("\n".join(f"- {tip}" for tip in analysis.suggestions))


def render_education() -> None:
    """Short beginner-friendly explanations."""
    st.subheader("📚 Learn: password basics")

    with st.expander("What does 'password strength' mean?"):
        st.write(
            "Password strength describes how hard a password is for an attacker "
            "to guess. Attackers rarely type guesses by hand. They use software that "
            "tries millions of likely passwords (common words, leaked passwords, "
            "predictable patterns like Summer2024!). A strong password is long, "
            "unpredictable, and not on those lists."
        )

    with st.expander("Why are longer passwords generally safer?"):
        st.write(
            "Every extra character multiplies the number of possible passwords. "
            "A random 16-character password has vastly more combinations than a "
            "random 8-character one. Long passphrases made of several random words "
            "are both strong and easier to remember."
        )

    with st.expander("Why should every password be unique?"):
        st.write(
            "When a website is breached, attackers try the leaked email and password "
            "on other sites ('credential stuffing'). If you reuse a password, one "
            "breach can unlock many of your accounts."
        )

    with st.expander("Why use a password manager and multi-factor authentication?"):
        st.write(
            "A password manager creates and remembers a unique, random password for "
            "every account, so you only memorize one strong master password. "
            "Multi-factor authentication (MFA) adds a second proof, like an app "
            "code or security key, so a stolen password alone is not enough."
        )


def main() -> None:
    st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔐", layout="wide")
    inject_css()

    st.markdown(
        '<p class="app-title">🔐 Password <span>Strength</span> Analyzer</p>'
        '<p class="subtitle">Learn what makes a password strong, with instant, '
        "transparent feedback.</p>",
        unsafe_allow_html=True,
    )
    st.info(
        "🔒 **Privacy:** Your password is analyzed only in memory by this app. It is "
        "never saved, logged, or sent to any API or AI service. Never enter a "
        "password you currently use for a real account. Test with similar-looking "
        "examples instead."
    )

    # --- Input ---
    with st.container(border=True):
        col_input, col_button = st.columns([5, 1], vertical_alignment="bottom")
        with col_input:
            # type="password" hides the text; Streamlit adds an eye icon to show/hide it.
            password = st.text_input(
                "Enter a password to analyze",
                type="password",
                key="pw_input",
                max_chars=MAX_INPUT_LENGTH,
                autocomplete="off",
                placeholder="Type a password, then press Enter",
            )
        with col_button:
            st.button("Clear", on_click=clear_password)

    # --- Analysis ---
    try:
        analysis = analyze_password(password)
    except Exception:
        # Deliberately generic: never print the password or details about it.
        st.error("Sorry, something went wrong while analyzing. Please try again.")
        st.stop()

    if analysis.length == 0:
        st.info("Enter a password above to see its strength, checklist, and recommendations.")
    else:
        render_results(analysis)

    render_education()
    st.caption(
        "⚠️ This tool gives an educational estimate only. It cannot guarantee that a "
        "password resists real-world cracking attempts."
    )


# Streamlit runs this file as "__main__"; tests.py can import it safely.
if __name__ == "__main__":
    main()
