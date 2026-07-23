from flask_sqlalchemy import SQLAlchemy

# This 'db' object is the connection point between our Python code
# and the actual database. We'll import this same object into app.py.
db = SQLAlchemy()


class User(db.Model):
    """
    Represents a REAL, legitimate bank customer.
    This is the 'source of truth' -- the actual identity that a fraudster
    would be trying to impersonate.
    """
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)

    # NOTE: In a real system you would NEVER store a real SSN as plain text
    # like this. We're storing a masked/fake version for demo purposes only,
    # e.g. "XXX-XX-1234". This is a deliberate simplification we'll call
    # out again when we get to the security-hardening stage.
    ssn_last4 = db.Column(db.String(4), nullable=False)

    def __repr__(self):
        return f"<User {self.full_name}>"


class CreditApplication(db.Model):
    """
    Represents a credit card application submitted for a given user.
    This is what an attacker fills out when committing identity theft --
    notice it has ITS OWN address/email/phone fields, separate from the
    User table. That gap (applicant-entered info vs. on-file info) is
    exactly what fraud detection needs to check.
    """
    id = db.Column(db.Integer, primary_key=True)

    # Links this application to a real User record (foreign key)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # This relationship lets us write `application.real_user` in our code
    # and templates, and SQLAlchemy automatically fetches the matching
    # User record for us -- no manual lookup needed.
    real_user = db.relationship("User", backref="applications")

    # These are the details as ENTERED ON THE APPLICATION, which may or
    # may not match what's actually on file for the real user.
    applicant_name = db.Column(db.String(100), nullable=False)
    applicant_email = db.Column(db.String(120), nullable=False)
    applicant_phone = db.Column(db.String(20), nullable=False)
    applicant_address = db.Column(db.String(200), nullable=False)
    ssn_last4_provided = db.Column(db.String(4), nullable=False)

    status = db.Column(db.String(20), default="pending")  # pending, approved, denied, flagged
    risk_score = db.Column(db.Integer, default=0)  # we'll fill this in Step 3/4
    submitted_at = db.Column(db.DateTime, server_default=db.func.now())
    # Step 5: step-up verification fields.
    # verification_token is a unique, hard-to-guess string used like a
    # one-time link -- in a real system this would be emailed/texted to
    # the real user. verification_status tracks whether the real user
    # has confirmed or denied that THEY submitted this application.
    verification_token = db.Column(db.String(64), nullable=True)
    verification_status = db.Column(db.String(20), default="not_required")

    # SECURITY FIX (IDOR): confirmation pages used to be looked up by the
    # sequential integer 'id' (e.g. /confirmation/1, /confirmation/2...).
    # That let anyone view ANY application -- including other people's
    # submitted SSNs and addresses -- just by changing the number in the
    # URL. This unguessable token replaces the id for lookups, the same
    # pattern already used for verification_token.
    confirmation_token = db.Column(db.String(64), nullable=True)

    def __repr__(self):
        return f"<CreditApplication {self.applicant_name} - {self.status}>"