import secrets
from flask import Flask, render_template, request, redirect, url_for
from models import db, User, CreditApplication
from fraud_engine import calculate_risk_score

# This creates our Flask application object.
# __name__ tells Flask where to look for templates/static files.
app = Flask(__name__)

# This tells Flask-SQLAlchemy where to store the database.
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///fraudguard.db"

# Connects our 'db' object (defined in models.py) to this specific app.
db.init_app(app)


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/apply", methods=["GET", "POST"])
def apply():
    """
    GET request  -> show the blank application form
    POST request -> save the submitted application to the database
    """
    if request.method == "POST":
        # request.form is a dictionary-like object holding everything
        # the person typed into the form fields, keyed by the "name"
        # attribute we set in apply.html (e.g. name="applicant_name").
        new_application = CreditApplication(
            user_id=request.form["user_id"],
            applicant_name=request.form["applicant_name"],
            applicant_email=request.form["applicant_email"],
            applicant_phone=request.form["applicant_phone"],
            applicant_address=request.form["applicant_address"],
            ssn_last4_provided=request.form["ssn_last4_provided"],
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

        db.session.commit()

        # redirect sends the browser to a NEW url after submission.
        # This prevents the classic "refresh the page and accidentally
        # resubmit the form" problem.
        return redirect(url_for("confirmation", application_id=new_application.id))

    # If it's a GET request, just show the form.
    # We pass in the list of existing users so the dropdown can be built.
    all_users = User.query.all()
    return render_template("apply.html", users=all_users)


@app.route("/confirmation/<int:application_id>")
def confirmation(application_id):
    # Look up the specific application that was just submitted, by its id.
    application = CreditApplication.query.get_or_404(application_id)

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
        return redirect(url_for("confirmation", application_id=application.id))

    return render_template("verify.html", application=application, real_user=real_user)

@app.route("/admin")
def admin_dashboard():
    """
    Shows every application in the system, most recent first, so bank
    staff can see risk scores and verification status at a glance.
    """
    all_applications = CreditApplication.query.order_by(CreditApplication.submitted_at.desc()).all()
    return render_template("dashboard.html", applications=all_applications)
    
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