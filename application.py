import os
# Try GitHub add

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

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
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # first, check how many company the user owns
    owned_stocks = db.execute("SELECT * FROM portfolio WHERE id = :userid", userid = session["user_id"])

    cash = db.execute("SELECT cash FROM users WHERE id = :userid", userid = session["user_id"])
    cash_onhand = cash[0]["cash"]  # total cash on hand

    # if own no company at all, return
    if  len(owned_stocks) == 0:
        return render_template("index.html", total_cash = cash_onhand, cash_onhand = cash_onhand)

    # create a "table", list of dictionaries that contain (symbol, quote["name"], shares, quote["price"], total) in each element of the list, i.e. row
    else:
        final_owned_stocks = []  # create a list, which will contain dictionaries!
        for i in range(len(owned_stocks)):  # for each row in the list[dictionary]

            # if shares = 0, meaning user has already sold all previously owned shares in this company, then no need to show this row
            if owned_stocks[i]["shares"] > 0:
                stocks_dict = {}  # create a dictionary for each row in the list
                quote = lookup(owned_stocks[i]["symbol"])
                stocks_dict["symbol"] = owned_stocks[i]["symbol"]
                stocks_dict["name"] = quote["name"]
                stocks_dict["shares"] = owned_stocks[i]["shares"]
                stocks_dict["price"] = quote["price"]
                stocks_dict["total"] = quote["price"] * owned_stocks[i]["shares"]

                final_owned_stocks.append(stocks_dict)  # fill in the list with dictionary of new key values


    cash_inbank = 0
    for row in final_owned_stocks:
        cash_inbank = cash_inbank + row["total"]
    total_cash = cash_inbank + cash_onhand

    return render_template("index.html", total_cash = total_cash, final_owned_stocks = final_owned_stocks, cash_onhand = cash_onhand)

    return apology("You have registered!")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        shares = request.form.get("shares")
        quote = lookup(request.form.get("symbol").upper())  # lookup upper case of symbol
        if not request.form.get("symbol"):
            return apology("Symbol missing!")

        elif quote == None:
            return apology("404 stock not found!")

        elif not request.form.get("shares"):
            return apology("Number of shares missing!")

        elif not (shares.isnumeric()):  # return apology if non numeric shares
            return apology("Shares must be numbers!")

        elif int(shares) <= 0 or (int(shares) % 1 != 0):  # return apology if -ve / fractional shares
            return apology("Invalid input for shares!")

        cash_dictionary = db.execute("SELECT cash FROM users WHERE id = :userid", userid = session["user_id"])  # use cash_dictionary to retrieve user's cash in dictionary var type

        cash = cash_dictionary[0]['cash']  # supposedly, get the cash value from dictionary cash_dictionary
        price = quote["price"]
        needed_shares = int(request.form.get("shares"))

        if cash < price * needed_shares:  # check if have enough money
            return apology("Money is not enough!!!")

        new_cash = cash - (price * needed_shares)  # remaining cash

        rows = db.execute("SELECT * FROM  portfolio WHERE id = :userid AND symbol = :stocksymbol", userid = session["user_id"], stocksymbol = quote["symbol"])

        if len(rows) == 0:  # if this user's have not bought this stock before
            # add a new row into table portfolio, setting initial value of column "symbol" too
            db.execute("INSERT INTO portfolio (id, symbol, shares) VALUES (:userid, :stocksymbol, :shares)", userid = session["user_id"], stocksymbol = quote["symbol"], shares = needed_shares);
        else:  # if user already holds shares in this stock
            # update table to add needed_shares into the value of column "shares"
            db.execute("UPDATE portfolio SET shares = (shares + :addshares) WHERE id = :userid AND symbol = :symbol", addshares = needed_shares, userid = session["user_id"], symbol = quote["symbol"])

        # update column "cash" in table users to remaining cash value
        db.execute("UPDATE users SET cash = :new_cash WHERE id = :userid", new_cash = new_cash, userid = session["user_id"])

        # insert buy transaction into table history
        time = str(datetime.datetime.now()).split('.')[0]
        db.execute("INSERT INTO history (soldbuy, symbol, price, shares, time, id) VALUES ('Buy', :symbol, :price, :shares, :time, :id)",
        symbol = quote["symbol"], price = price, shares = needed_shares, time = time, id = session["user_id"])
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])  # NO IDEA WHY CHECK50 gives everytime ":( /check route confirms whether username is available", this works like a charm to me n friends testing it
def check():
    """Return true if username available, else false, in JSON format"""
    q = request.args.get("q")
    usernames = db.execute("SELECT username FROM users")
    if not usernames:   # if table empty, meaning no user registered yet
        return jsonify(True)
    elif q == None:  # if user input has no value
        return jsonify(True)
    elif len(q) < 1:
        return jsonify(False)
    elif len(q) >= 1:   #if user input has at least 1 character
        for i in usernames:  # iterate over each usernames row
            if q == i["username"]:
                return jsonify(False)

    return jsonify(True)


@app.route("/history")
@login_required
def history():
    history_rows = db.execute("SELECT * FROM history WHERE id = :id", id = session["user_id"])  # get a row with all datas from history table of this user

    # if there is no history, just pass in no variable, so that in html will display empty table
    if len(history_rows) == 0:
        return render_template("history.html")
    else:
        return render_template("history.html", history_rows = history_rows)

    return apology("TODO")  # can delete later


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
            return apology("Symbol missing!")

        quote = lookup(request.form.get("symbol").upper())  # lookup upper case of symbol

        if quote == None:   # check for valid symbol
            return apology("404 stock not found!")
        else:
            return render_template("quotedisplay.html", company = quote["name"], symbol = request.form.get("symbol"), price = usd(quote["price"]))
    else:
        return render_template("quote.html")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    if request.method == "POST":

        if not request.form.get("username"):    # check for errors, human omissions
            return apology("Missing username!")
        elif not request.form.get("password"):
            return apology("Missing password!")
        elif not request.form.get("confirmation"):
            return apology("Missing confirmation password!")
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Password and confirmation password does not match!")

        hashed_pw = generate_password_hash(request.form.get("password"))    # hash the password
        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username = request.form.get("username"), hash = hashed_pw)
        if not result:  # if username has been taken
            return apology("That username has already been taken!")

        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)
        session["user_id"] = rows[0]["id"]  # Remember which user has locked in

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # get all fields for each stock the users own
    owned_stocks = db.execute("SELECT * FROM portfolio WHERE id = :userid", userid = session["user_id"])

    if request.method == "POST":
        if not request.form.get("symbol"):    # check for empty symbol
            return apology("You need to pick a symbol!")
        elif not request.form.get("shares"):
            return apology("You need to provide the number of shares to sell!")
        elif int(request.form.get("shares")) <= 0:  # technically useless because input form already specify must be integer
            return apology("Shares must be positive integers!")

        # extract no. of shares from portfolio
        owned_shares = db.execute("SELECT * FROM portfolio WHERE symbol = :symbol AND id = :userid", symbol = request.form.get("symbol"), userid = session["user_id"])
        # check if have enough shares
        if owned_shares[0]["shares"] < int(request.form.get("shares")):
            return apology("You do not have that many shares in that company!")

        # if have enough, UPDATE portfolio with new_owned_shares
        new_owned_shares = owned_shares[0]["shares"] - int(request.form.get("shares"))
        # find correct row in portfolio and update cash value
        db.execute("UPDATE portfolio SET shares = :new_owned_shares WHERE symbol = :symbol AND id = :userid",
            new_owned_shares = new_owned_shares, symbol = request.form.get("symbol"), userid = session["user_id"])

        # calculate new cash in hand value
        quote = lookup(request.form.get("symbol"))
        current_price = quote["price"]
        needed_shares = int(request.form.get("shares"))
        add_in_cash = current_price * needed_shares
        old_cash = db.execute("SELECT * FROM users WHERE id = :userid", userid = session["user_id"])
        new_cash = old_cash[0]["cash"] + add_in_cash

        # UPDATE users table
        db.execute("UPDATE users SET cash = :new_cash WHERE id = :userid",
            new_cash = new_cash, userid = session["user_id"])

        # insert sold transaction into history table
        time = str(datetime.datetime.now()).split('.')[0]
        db.execute("INSERT INTO history (soldbuy, symbol, price, shares, time, id) VALUES ('Sold', :symbol, :price, :shares, :time, :id)",
        symbol = quote["symbol"], price = current_price, shares = needed_shares, time = time, id = session["user_id"])
        return redirect("/")
    else:
        return render_template("sell.html", owned_stocks = owned_stocks)
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        # change password, update sql table
        hashed_pw = generate_password_hash(request.form.get("password"))
        db.execute("UPDATE users SET hash = :hashed_pw WHERE id = :id", hashed_pw = hashed_pw, id = session["user_id"])
        success = 1
        return render_template("change.html", success = success)
    else:
        return render_template("change.html")
