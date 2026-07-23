import os
import secrets
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db, User, CreditApplication
from fraud_engine import calculate_risk_score
from validators import validate_application_form

# Loads variables from the .env file into the environment, so we can
# read them with os.environ.get() below. This keeps secrets OUT of
# the code itself -- .env is in .gitignore, so it never gets pushed
# to GitHub, unlike everything in app.py which is fully public.
load_dotenv()

# This creates our Flask application object.
# __name__ tells Flask where to look for templates/static files.
app = Flask(__name__)

# SECRET_KEY is used by Flask internally to cryptographically sign
# session cookies and other security-sensitive data. If this were
# hardcoded and pushed to a public GitHub repo, anyone could forge
# valid-looking session data for your app. Reading it from the
# environment instead means the real value never appears in your code.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "insecure-fallback-key-for-dev-only")

# This tells Flask-SQLAlchemy where to store the database.
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///fraudguard.db")

# Connects our 'db' object (defined in models.py) to this specific app.
db.init_app(app)

# Admin password, read from the environment -- never hardcoded.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

# Flask-Limiter tracks how many requests come from each visitor's IP
# address, and blocks them with a 429 "Too Many Requests" response if
# they exceed the limit. This defends against both automated spam
# (bots flooding the application form) and brute-force password
# guessing (someone scripting thousands of login attempts).
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


def login_required(view_func):
    """
    A decorator: wraps a route so it checks for a logged-in admin
    session BEFORE running the actual view. If not logged in, it
    redirects to the login page instead. This is the standard pattern
    for protecting routes in Flask without a full auth library.
    """
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/apply", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def apply():
    """
    GET request  -> show the blank application form
    POST request -> save the submitted application to the database
    """
    if request.method == "POST":
        # SECURITY: validate everything before touching the database.
        # This form is public -- anyone can send a POST request straight
        # to this URL with any data, bypassing our HTML form entirely.
        errors = validate_application_form(request.form)

        if errors:
            # Re-show the form with the errors listed, and DON'T save
            # anything to the database. request.form.get(...) repopulates
            # the fields so the person doesn't have to retype everything.
            all_users = User.query.all()
            return render_template(
                "apply.html",
                users=all_users,
                errors=errors,
                form_data=request.form,
            )

        # request.form is a dictionary-like object holding everything
        # the person typed into the form fields, keyed by the "name"
        # attribute we set in apply.html (e.g. name="applicant_name").
        new_application = CreditApplication(
            user_id=request.form["user_id"],
            applicant_name=request.form["applicant_name"].strip(),
            applicant_email=request.form["applicant_email"].strip(),
            applicant_phone=request.form["applicant_phone"].strip(),
            applicant_address=request.form["applicant_address"].strip(),
            ssn_last4_provided=request.form["ssn_last4_provided"].strip(),
        )
        db.session.add(new_application)
        db.session.commit()

        # Now that the application is saved (and has an id), look up the
        # real user it claims to be, and run our fraud scoring logic
        # against it.
        real_user = db.session.get(User, new_application.user_id)
        result = calculate_risk_score(real_user, new_application)

        new_application.risk_score = result["score"]
        new_application.status = "flagged" if result["flagged"] else "pending"

        # Every application requires step-up verification now, regardless
        # of risk score. A high risk score makes fraud MORE likely, but a
        # low/zero score doesn't prove the real person applied -- someone
        # could get every field to match and still not be who they claim
        # to be. Verification is the actual identity check; the risk
        # score just controls how urgent/alarming that check looks.
        new_application.verification_token = secrets.token_urlsafe(16)
        new_application.verification_status = "pending_verification"

        # SECURITY FIX (IDOR): generate an unguessable token for viewing
        # this specific confirmation page, instead of relying on the
        # sequential database id.
        new_application.confirmation_token = secrets.token_urlsafe(16)

        db.session.commit()

        # redirect sends the browser to a NEW url after submission.
        # This prevents the classic "refresh the page and accidentally
        # resubmit the form" problem.
        return redirect(url_for("confirmation", token=new_application.confirmation_token))

    # If it's a GET request, just show the form.
    # We pass in the list of existing users so the dropdown can be built.
    all_users = User.query.all()
    return render_template("apply.html", users=all_users)


@app.route("/confirmation/<token>")
def confirmation(token):
    # SECURITY FIX (IDOR): look up by the unguessable confirmation_token
    # instead of the sequential integer id. Previously /confirmation/1,
    # /confirmation/2, etc. let anyone view any application, including
    # other people's submitted SSNs and addresses, just by changing the
    # number. A random token can't be guessed or enumerated.
    application = CreditApplication.query.filter_by(confirmation_token=token).first_or_404()

    # Recompute the fraud check so we can show the specific reasons
    # (the reasons list itself isn't stored in the database, only the
    # final score and status -- so we regenerate it here for display).
    real_user = db.session.get(User, application.user_id)
    result = calculate_risk_score(real_user, application)

    return render_template("confirmation.html", application=application, reasons=result["reasons"])

@app.route("/verify/<token>", methods=["GET", "POST"])
def verify(token):
    """
    This simulates the link the REAL user would click from an email/SMS
    alert. In a real bank, this page would live behind login + the
    user's actual inbox/phone -- here, we simulate it by just using an
    unguessable token as a stand-in for 'only the real user has this link'.
    """
    application = CreditApplication.query.filter_by(verification_token=token).first_or_404()
    real_user = db.session.get(User, application.user_id)

    if request.method == "POST":
        decision = request.form["decision"]  # "approve" or "deny"

        if decision == "approve":
            application.verification_status = "confirmed"
            application.status = "approved"
        else:
            application.verification_status = "denied"
            application.status = "denied_fraud"

        db.session.commit()
        return redirect(url_for("confirmation", token=application.confirmation_token))

    return render_template("verify.html", application=application, real_user=real_user)

@app.route("/admin")
@login_required
def admin_dashboard():
    """
    Shows every application in the system, most recent first, so bank
    staff can see risk scores and verification status at a glance.
    Protected by login_required -- previously this had NO authentication
    at all, meaning anyone with the URL could see every applicant's
    submitted personal info.
    """
    all_applications = CreditApplication.query.order_by(CreditApplication.submitted_at.desc()).all()
    return render_template("dashboard.html", applications=all_applications)


@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def admin_login():
    """
    Simple password-only login for the demo admin dashboard. A real
    bank system would use per-employee accounts, MFA, and proper
    password hashing -- this is a minimal stand-in just to demonstrate
    that /admin should never be reachable without SOME authentication.
    """
    error = None
    if request.method == "POST":
        submitted_password = request.form.get("password", "")
        if submitted_password == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        error = "Incorrect password."

    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))
@app.cli.command("seed-db")
def seed_db():
    """
    Custom command: creates one demo 'real' user so we have someone
    to test credit applications against.
    Run with: flask --app app seed-db
    """
    with app.app_context():
        existing = User.query.filter_by(email="alex.morgan@email.com").first()
        if existing:
            print("Demo user already exists.")
            return

        demo_user = User(
            full_name="Alex Morgan",
            email="alex.morgan@email.com",
            phone="555-010-1234",
            address="123 Maple Street, Springfield, IL",
            ssn_last4="6789",
        )
        db.session.add(demo_user)
        db.session.commit()
        print(f"Created demo user: {demo_user.full_name} (id={demo_user.id})")


@app.cli.command("init-db")
def init_db():
    """
    Custom command: creates all database tables based on our models.
    Run this once from the terminal with: flask --app app init-db
    """
    with app.app_context():
        db.create_all()
    print("Database tables created.")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)