import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL(os.getenv("DATABASE_URL"))

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index(action=0):
    """Show portfolio of stocks"""
    c = db.execute("SELECT * FROM owns WHERE id = ?", int(session["user_id"]))
    # return apology(f"{c} with {len(c)} j")
    s = 0
    for i in range(len(c)):
        l = c[i]
        k = (lookup(c[i]["symbol"])["price"])
        s += k*l['number']
        c[i].update({'price': round(k, 2), 'total': round(k*l['number'], 2), 'name': lookup(l["symbol"])["name"]})
    k = db.execute("SELECT cash FROM users WHERE id = ?", int(session["user_id"]))
    k = k[0]["cash"]
    s += k
    return render_template("index.html", name=c, number=int(len(c)), cash=round(k, 2), s=round(s, 2), action=action)


@app.route("/reset", methods=["GET", "POST"])
@login_required
def reset():
    """Sell shares of stock"""
    if request.method == "GET":
        return render_template("reset.html")
    else:
        if not request.form.get("current_password"):
            return apology("must provide current password", 403)
        elif not request.form.get("new_password"):
            return apology("must provide new password", 403)
        elif not request.form.get("confirm_password"):
            return apology("must provide confirm password", 403)
        elif (request.form.get("new_password") != request.form.get("confirm_password")):
            return apology("new password and confirm password do not match", 403)

        rows = db.execute("SELECT * FROM users WHERE id = ?", int(session["user_id"]))

        if not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
            return apology("current password do not match", 403)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(
            request.form.get("new_password")), int(session["user_id"]))

    return(index(3))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    global money
    if request.method == "GET":
        return render_template("buy.html")
    else:
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        elif not request.form.get("shares"):
            return apology("must provide shares number to buy", 403)
        elif lookup(request.form.get("symbol")) == None:
            return apology("must provide a valid symbol", 403)
        elif (int(request.form.get("shares")) <= 0):
            return apology("shares to buy must be greater than 1", 403)
        k = lookup(request.form.get("symbol"))["price"]
        if (int(request.form.get("shares"))*k > money):
            return apology("can't afford", 403)
        else:
            db.execute("insert into history (id, symbol, number, price) values (?, ?, ?, ?)", int(
                session["user_id"]), request.form.get("symbol").upper(), request.form.get("shares"), k)
            money = money - int(request.form.get("shares"))*k
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", money, int(session["user_id"]))
            rows = db.execute("SELECT count(*) FROM owns WHERE id = ? and symbol = ?",
                              session["user_id"], request.form.get("symbol").upper())
            rows = rows[0]["count(*)"]
            if rows == 1:
                db.execute("update owns set number = number + ? where id = ? and symbol = ?",
                           int(request.form.get("shares")), session["user_id"], request.form.get("symbol").upper())
            elif rows == 0:
                db.execute("insert into owns (id, symbol, number) values (?, ?, ?)", int(
                    session["user_id"]), request.form.get("symbol").upper(), int(request.form.get("shares")))
    return(index(action=1))


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    k = db.execute("select * from history where id = ? order by transacted desc", session["user_id"])
    return render_template("history.html", name=k, number=len(k))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        global money
        money = rows[0]["cash"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html", name=1)
    else:
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        elif (lookup(request.form.get("symbol")) == None):
            return apology("invalid symbol", 403)
        else:
            return render_template("quote.html", name=lookup(request.form.get("symbol")))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif (request.form.get("password") != request.form.get("confirmpassword")):
            return apology("password do not match", 403)

        # register database for username
        db.execute("insert into users (username, hash) values (?, ?)", request.form.get(
            "username"), generate_password_hash(request.form.get("password")))
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        return render_template("sell.html", name=db.execute("SELECT symbol FROM owns WHERE id = ?", int(session["user_id"])))
    else:
        if not request.form.get("symbol"):
            return apology("must provide symbol of share", 403)
        elif not request.form.get("number"):
            return apology("must provide number", 403)
        elif(int(request.form.get("number")) > int(db.execute("SELECT number FROM owns WHERE id = ? and symbol = ?", int(session["user_id"]), request.form.get("symbol"))[0]["number"])):
            return apology("you don't own that much shares ", 403)
        else:
            global money
            k = lookup(request.form.get("symbol"))["price"]
            db.execute("insert into history (id, symbol, number, price) values (?, ?, ?, ?)", int(
                session["user_id"]), request.form.get("symbol").upper(), -int(request.form.get("number")), k)
            money = money + int(request.form.get("number"))*k
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", money, int(session["user_id"]))
            rows = db.execute("SELECT count(*) FROM owns WHERE id = ? and symbol = ?",
                              session["user_id"], request.form.get("symbol").upper())
            rows = rows[0]["count(*)"]
            if rows == 1:
                db.execute("update owns set number = number + ? where id = ? and symbol = ?",
                           -int(request.form.get("number")), session["user_id"], request.form.get("symbol").upper())
            elif rows == 0:
                db.execute("insert into owns (id, symbol, number) values (?, ?, ?)", int(
                    session["user_id"]), request.form.get("symbol").upper(), -int(request.form.get("number")))
    return(index(action=2))


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)