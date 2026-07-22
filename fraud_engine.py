"""
fraud_engine.py

This module contains the core fraud-detection logic, kept separate from
app.py so the 'rules' of fraud scoring are easy to find, read, and change
without touching the web/routing code.
"""

# How many points each type of mismatch contributes to the risk score.
# Higher points = more serious mismatch.
SSN_MISMATCH_POINTS = 50
EMAIL_MISMATCH_POINTS = 20
PHONE_MISMATCH_POINTS = 15
ADDRESS_MISMATCH_POINTS = 15

# If the total score is >= this number, the application gets flagged
# instead of just going to "pending".
FLAG_THRESHOLD = 30


def calculate_risk_score(user, application):
    """
    Compares the info submitted on the application against what's
    actually on file for the real user, and returns:
      - a numeric risk score
      - a list of human-readable reasons explaining WHY it scored that way

    'user' is a User record (the real, on-file identity).
    'application' is a CreditApplication record (what was submitted).
    """
    score = 0
    reasons = []

    # .strip().lower() normalizes text so "Alex@Email.com" and
    # "alex@email.com" are still treated as a match -- we only want to
    # flag MEANINGFUL differences, not formatting differences.
    if application.ssn_last4_provided.strip() != user.ssn_last4.strip():
        score += SSN_MISMATCH_POINTS
        reasons.append("SSN last 4 digits do not match on-file record")

    if application.applicant_email.strip().lower() != user.email.strip().lower():
        score += EMAIL_MISMATCH_POINTS
        reasons.append("Email does not match on-file record")

    if application.applicant_phone.strip() != user.phone.strip():
        score += PHONE_MISMATCH_POINTS
        reasons.append("Phone number does not match on-file record")

    if application.applicant_address.strip().lower() != user.address.strip().lower():
        score += ADDRESS_MISMATCH_POINTS
        reasons.append("Mailing address does not match on-file record")

    is_flagged = score >= FLAG_THRESHOLD

    return {
        "score": score,
        "reasons": reasons,
        "flagged": is_flagged,
    }