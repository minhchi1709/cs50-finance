import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == "GET":
        id = session["user_id"]
        all = db.execute("SELECT * FROM purchases WHERE id = ?", id)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
        return render_template("index.html", cash=cash, products = all)
    return apology("")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        if not request.form.get("symbol"):
            return apology("Please provide a symbol!")
        if not request.form.get("shares"):
            return apology("Please provide a positive share!")
        for i in request.form.get("shares"):
            if i not in [str(j) for j in range(0, 10)]:
                return apology("Only give a positive and whole share!")
        shares = int(request.form.get("shares"))
        if shares < 0:
            return apology("Please provide a positive share!")
        symbol = request.form.get("symbol")
        product = lookup(symbol)
        if not product:
            return apology("Cannot find symbol!")
        id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
        price, name = product["price"], product["name"]
        prices = price * shares
        rows = db.execute("SELECT * FROM purchases WHERE id = ? AND name = ?", id, name)
        if cash < prices:
            return apology("You do not have enough money!")
        if len(rows) == 0:
            db.execute("INSERT INTO purchases (id, shares, prices, price, name) VALUES(?, ?, ?, ?, ?)",
                                               id , shares, prices, price, name)
        else:
            db.execute("UPDATE purchases SET shares = ?, prices = ? WHERE id = ? AND name = ?",
                       shares + rows[0]["shares"], prices + rows[0]["prices"], id, name)
        db.execute("INSERT INTO history (id, shares, prices, price, name) VALUES(?, ?, ?, ?, ?)",
                                            id, shares, prices, price, name)
        cash = db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - prices, id)
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM history WHERE id = ?", session["user_id"])
    return render_template("history.html", products = history)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Please input symbol(s)!", 400)
        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("Give valid symbol!", 400)
        return render_template("quoted.html", quote = quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Please provide a username!")
        accounts = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(accounts) > 0:
            return apology("This username already exists!")
        if not request.form.get("password"):
            return apology("Please provide a password!")
        if not request.form.get("confirmation"):
            return apology("Please confirm your password!")
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Confirm your password correctly!")
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"), generate_password_hash(request.form.get("password")))
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        stocks = db.execute("SELECT name FROM purchases WHERE id = ?", session["user_id"])
        stocks = [stock["name"] for stock in stocks]
        return render_template("sell.html", stocks = stocks)
    else:
        if not request.form.get("symbol"):
            return apology("Give a symbol!")
        product = lookup(request.form.get("symbol"))
        if not product:
            return apology("Cannot find symbol")
        if not request.form.get("shares"):
            return apology("Give a positive share!")
        shares = int(request.form.get("shares"))
        if shares < 0:
            return apology("Give a positive share!")
        id = session["user_id"]
        own_shares = db.execute("SELECT shares FROM purchases WHERE id = ?", id)[0]["shares"]
        if own_shares < shares:
            return apology("You do not have enough shares!")
        cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
        price, name = product["price"], product["name"]
        prices = price * shares
        rows = db.execute("SELECT * FROM purchases WHERE id = ? AND name = ?", id, name)
        if len(rows) == 0:
            return apology("You do not have this stock!")
        else:
            db.execute("UPDATE purchases SET shares = ?, prices = ? WHERE id = ? AND name = ?",
                       own_shares - shares, rows[0]["prices"] - prices, id, name)
            db.execute("DELETE FROM purchases WHERE shares = 0")
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + prices, id)
        db.execute("INSERT INTO history (id, shares, prices, price, name) VALUES(?, ?, ?, ?, ?)", id, -shares, prices, price, name)
        return redirect("/")
