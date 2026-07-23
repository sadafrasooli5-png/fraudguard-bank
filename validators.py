"""
validators.py

Input validation for the application form. The core security principle
here: NEVER trust data coming from a browser, even your own form. Anyone
can send a raw HTTP request straight to /apply with whatever data they
want, bypassing your HTML entirely (we've literally been doing this
ourselves with curl while testing). Validation happens on the SERVER,
not just in the browser.
"""

import re

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Very loose phone check: at least 7 digits, allows spaces/dashes/parens.
PHONE_DIGIT_PATTERN = re.compile(r"\d")


def validate_application_form(form_data):
    """
    Takes the raw form dictionary and returns a list of human-readable
    error strings. An empty list means the input passed validation.
    """
    errors = []

    name = form_data.get("applicant_name", "").strip()
    email = form_data.get("applicant_email", "").strip()
    phone = form_data.get("applicant_phone", "").strip()
    address = form_data.get("applicant_address", "").strip()
    ssn_last4 = form_data.get("ssn_last4_provided", "").strip()

    if not name:
        errors.append("Full name is required.")
    elif len(name) > 100:
        errors.append("Full name is too long.")

    if not email:
        errors.append("Email is required.")
    elif not EMAIL_PATTERN.match(email):
        errors.append("Email format looks invalid.")
    elif len(email) > 120:
        errors.append("Email is too long.")

    if not phone:
        errors.append("Phone is required.")
    else:
        digit_count = len(re.findall(r"\d", phone))
        if digit_count < 7:
            errors.append("Phone number must contain at least 7 digits.")

    if not address:
        errors.append("Address is required.")
    elif len(address) > 200:
        errors.append("Address is too long.")

    if not ssn_last4:
        errors.append("SSN last 4 digits are required.")
    elif not ssn_last4.isdigit():
        errors.append("SSN last 4 digits must be numeric.")
    elif len(ssn_last4) != 4:
        errors.append("SSN last 4 digits must be exactly 4 digits.")

    return errors