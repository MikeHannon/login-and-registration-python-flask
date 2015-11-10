from flask import Flask, flash, render_template, request, redirect, session
from mysqlconnection import MySQLConnector
import bcrypt
import re
app = Flask(__name__)

app.secret_key = 'MikesAmazingKeyThatNobodyWouldGuessTEST'
mysql = MySQLConnector('Login_Registration_Demo')


name = 'Mike'
# hashed = bcrypt.hashpw(name, bcrypt.gensalt())
# boolean_password = bcrypt.hashpw('Mike', hashed) == hashed
# boolean_password2 = bcrypt.hashpw('notMike', hashed) == hashed
# print hashed
# print boolean_password
# print boolean_password2


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
# MODEL FUNCTIONS
def show(param):
    if EMAIL_REGEX.match(param):
        query = "SELECT * FROM users where email = '{}'".format(param)
        print query
        user = mysql.fetch(query)
        return user
    return []

def create(param):
    # the param is the entire request object
    password_hash = bcrypt.hashpw(str(param['password']),bcrypt.gensalt());
    query = "INSERT into users (first_name, last_name, email, password_hash, created_at, updated_at) VALUES ('{}', '{}', '{}', '{}', NOW(), NOW())".format(param['first_name'], param['last_name'], param['email'], password_hash)
    mysql.run_mysql_query(query) #runs
    query_result = show(param['email']) #run
    if len(query_result) == 1:
        return query_result
    return []

#CONTROLLER FUNCTIONS
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods = ["POST"])
#1) Request form information.
#2) Use that information (the email field which should be unique / registrant) to get something from DB.
#3) using info DB - if present, compare hashed password with input password.
#4) if not present return to index with error flash message: 'user or password not correct'
#5) if both password and user found and match what's in the DB, set session to this user.
def login():
    current_user = show(request.form['email'])
    if len(current_user) == 1 and bcrypt.hashpw(str(request.form['password']), current_user[0]['password_hash']) == current_user[0]['password_hash']:
        session['user'] = current_user[0]
        return redirect("/success")
    return "failure so sad :("

@app.route('/register', methods = ["POST"])
#1) validations: present fields, other validations, email is potentially a real email.
#2) make sure that users email is not already in DB.
#3) if so: flash message that user is present.
#4)  (see 1) if not then check if passwords are the same (p1 and p2)
#5) if so then let's register our user: hash password, set password to that hash, and then save into DB.
#6) After successful registration: we could flash a mesasge that says: login!
#7) Set session user and go somewhere else.
def register():
    # if (request.form['register'] == 'login'):
    #     do something...
    # else:
    #     do this stuff below
    current_user = show(request.form['email'])#select one from db.
    if len(current_user) > 0:
        return redirect('/') #2) make sure that users email is not already in DB.
    user = create(request.form);
    if (len(user) > 0):
        session['user'] = user[0]
        print session['user']
        return render_template("success.html")

@app.route('/success', methods = ['GET'])
def success():
    return render_template("success.html")

if __name__ == '__main__':
    app.run(debug=True)
