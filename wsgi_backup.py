from flask import Flask, render_template, request, jsonify,redirect, url_for,flash, send_file, session
from werkzeug.wrappers.response import Response
import sqlite3
from functools import wraps
import json
import csv
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import uuid
import ssl
from datetime import datetime, timedelta, timezone
from datetime import time as dt_time
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import get_jwt
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import verify_jwt_in_request
from flask_jwt_extended import JWTManager
from jwt import encode, decode
from urllib.parse import unquote
# import pywhatkit
import pytz
import random
import requests
import os
from dotenv import load_dotenv, find_dotenv
dotenv_path = find_dotenv()
load_dotenv(dotenv_path, override=True)
import time
app = Flask(__name__)


# global variables
no_of_seats = 1
order_id = None
tx_id = None

app.secret_key = 'WoxsenUniversity'
app.config["JWT_SECRET_KEY"] = "super-secret" 
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
# client_id = 'bduatv2apt'
client_id = os.getenv('CLIENT_ID')
secret_key = os.getenv('SECRET_KEY')
mid = os.getenv('MERCHANT_ID')
CREATE_API_ENDPOINT = os.getenv('CREATE_API_ENDPOINT')
TXGET_API_ENDPOINT = os.getenv('TXGET_API_ENDPOINT')

from_ = "woxsenailab@gmail.com"
pwd = "ycoviljsqtfrtoul"

jwt = JWTManager(app)


bus_routes = {
    1:    {"name": "Corporate Office", "home": "5:15 PM", "campus": "7:00 AM", "fare": "450", "route_id": 1, "source": "campus", "destination": "Corporate Office", "locations": ["woxsen", "sangareddy", "Gachibowli", "Corporate Office"]},
    2:   {"name": "Ameerpet", "home": "5:15 PM", "campus": "7:00 AM", "fare": "450", "route_id": 2, "source": "campus", "destination": "Ameerpet", "locations": ["Woxsen", "Miyapur", "kukatpally", "ameerpet"]},
}

# handle page not found
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


def custom_unauthorized_response(*args):
    return redirect(url_for('login'))

jwt.unauthorized_loader(custom_unauthorized_response)

jwt.expired_token_loader(custom_unauthorized_response)


def connect_db():
    conn = sqlite3.connect("users.db")
    # what is cursor?
    # cursor is a pointer to the data
    c = conn.cursor() 
    # commit - save the changes   
    save = conn.commit
    close = conn.close
    return c, save, close


@app.after_request
def after_request(response: Response) -> Response:
    # response.headers.add('Access-Control-Allow-Origin', BASE_CORS_URL)
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

def jwt_or_redirect():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            if not get_jwt_identity():
                return redirect(url_for('login'))
            else:
                return fn(*args, **kwargs)
        return decorator
    return wrapper



@app.after_request
def refresh_expiring_jwts(response):
    try:
        verify_jwt_in_request()
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity()) 
            set_access_cookies(response, access_token)
        return response
    except Exception as e:
        return response

@app.route("/")
def redirect_app():
    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    # if jwt is present in cookies, redirect to dashboard
    if request.cookies.get("access_token_cookie"):
        # verify jwt and redirect to dashboard
        try:
            verify_jwt_in_request()
            return redirect(url_for('home'))
        except:
            pass
    
    if request.method == "GET":
        title = "WOXSEN Bus Login"
        return render_template("login.html", title=title)
    
    if request.method == "POST":
        form_data = request.form
        user_mail = form_data.get("email")
        pwd = form_data.get("password")
        
        if user_mail is None or pwd is None:
            error = "email or password is missing"
            return render_template("login.html", error=error)
        
        print(F"email : {user_mail} password : {pwd}")
        cursor, _, close = connect_db() # (cursor, save, close)
        # cursor = conn[0]
        # save = conn[1]
        # close = conn[2]
        
        query = "SELECT id,role FROM users WHERE email = ? AND password = ?"
        
        cursor.execute(query, (user_mail, pwd))
        
        result = cursor.fetchone() # None or (1, "admin")
        
        if result is None:
            print(result)
            error = "email or password is incorrect"
            return render_template("login.html", error=error)
        else:
            print(F"debug admin login : {result}")
    
        user_id = result[0]
        role = result[1]
        
        close()
        
        response = redirect(url_for('home'))
        
        expires = timedelta(days=1)
        access_token = create_access_token(identity={"email": user_mail,"id": user_id, "role": role}, expires_delta=expires)
        set_access_cookies(response, access_token)
        return response

def send_otp_mail(user_mail, gotp):
    
    msg = MIMEMultipart()
    
    msg["From"] = from_
    msg["To"] = user_mail
    msg["Subject"] = "Woxsen Bus Booking Confirmation"
    
    name = user_mail.split('@')[0]
    
    body = f"""
    <h1>Hi {name},</h1>
    <p>Thank you for signing up with Woxsen Bus Booking System.</p>
    <p><b>Your OTP for signing up</b>: {gotp}</p>    
    """
    
    msgHtml = MIMEText(body, "html")
    
    msg.attach(msgHtml)
    
    conn = smtplib.SMTP("smtp.gmail.com", 587)
    conn.starttls()
    
    conn.login(from_, pwd)

    conn.sendmail(from_, msg["To"], msg.as_string())
    print("Sent mail.")
    
    conn.close()

@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = ""
    # if jwt is present in cookies, redirect to dashboard
    if request.cookies.get("access_token_cookie"):
        # verify jwt and redirect to dashboard
        try:
            verify_jwt_in_request()
            return redirect(url_for('home'))
        except:
            pass
    
    if request.method == "GET":
        title = "WOXSEN Bus Signup"
        error = request.args.get('error')
        return render_template("signup.html", title=title, error=error)
    
    if request.method == "POST":
        form_data = request.form
        print(F"Form data : \n {form_data}")
        user_mail = form_data.get("email")
        pwd = form_data.get("password")
        mobile = form_data.get("mobile")
        school = form_data.get("school")
        name = form_data.get("name")
        stu_id = form_data.get("stu_id")
        # username = form_data.get("username")

        print(F"user_mail : {user_mail}\npwd : {pwd}\nmobile : {name}\nmobile : {mobile}\nschool : {school}\nstu_id : {stu_id}")
        
        if user_mail is None or pwd is None:
            error = "email or password is missing"
            return render_template("signup.html", error=error)

        # check if existing user
        cursor, _, close = connect_db() # (cursor, save, close)
        # cursor = conn[0]
        # save = conn[1]
        # close = conn[2]
        
        query = "SELECT id,role FROM users WHERE email = ? AND password = ?"
        
        cursor.execute(query, (user_mail, pwd))
        
        result = cursor.fetchone() # None or (1, "admin")
        
        if result is not None:
            error = "User already exists with this mail, please login instead"
            return redirect(url_for('login', error=error))
        
        close()
        
        # otp gen and mail
        gotp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        print(f"otp generated: {gotp}")

        send_otp_mail(user_mail, gotp)
        return redirect(url_for('otp', user_mail=user_mail, pwd=pwd, gotp=gotp, mobile=mobile, school=school, name=name, stu_id=stu_id))

@app.route("/otp", methods=["GET", "POST"])
def otp():
    error = ""
    if request.method == "GET":
        title = "WOXSEN Bus Signup"
        return render_template("otp.html")
    
    if request.method == "POST":
        form_data = request.form
        fotp = form_data.get("otp")
        gotp = request.args.get('gotp')
        print(F"fotp : {fotp}    gotp : {gotp}")
        if fotp == gotp:
            user_mail = request.args.get('user_mail')
            pwd = request.args.get('pwd')
            name = request.args.get('name')
            mobile = request.args.get('mobile')
            school = request.args.get('school')
            stu_id = request.args.get('stu_id')

            print("In OTP:")
            print()
            print(F"Usermail and pwd in otp route : {user_mail}  {pwd}")
            cursor, save, close = connect_db() # (cursor, save, close)
            # cursor = conn[0]
            # save = conn[1]
            # close = conn[2]
            
            # query = "SELECT id,role FROM users WHERE email = ? AND password = ?"

            query = "INSERT INTO users (stu_id, name, mobile, email, password, school, role) VALUES (?, ?, ?, ?, ?, ?, ?)"
            
            cursor.execute(query, (stu_id, name, mobile, user_mail, pwd, school, "student"))

            # query = "SELECT * FROM users"
            
            # cursor.execute(query)
            result = cursor.fetchall()
            print(result)
            
            save()
            close()
            print("user stored in db")
            return redirect(url_for('login'))
        else:
            error = "OTP Validation Failure"
            return redirect(url_for('signup', error = error))
        



@app.route("/logout")
def logout():
    response = redirect(url_for('login'))
    response.set_cookie("access_token_cookie", expires=0)
    return response

def create_csv(dict_data):
    with open("data.csv", "w") as f:
        writer = csv.DictWriter(f, fieldnames=dict_data[0].keys())
        writer.writeheader()
        writer.writerows(dict_data)


@app.route("/csv")
def download_csv():
    travel_date = request.args.get("date")
    bus_number = request.args.get("bus_number")
    print("Executing /csv route")
    print(F'bus_number : {bus_number}')
    
    # get id of bus
    query = "SELECT route_id FROM bus WHERE bus_number = ?"
    
    cursor, _, close = connect_db()
    
    cursor.execute(query, (bus_number,))
    bus_id = cursor.fetchone()[0]

    print(F"bus_id : {bus_id}")
    
    # get all reservations for bus_id on travel_date (email, username, seat, date, bus_number)
    query = """
    SELECT r.date, b.bus_number,r.p_name as passenger_name, r.p_email as passenger_email, r.p_phone as passenger_phone, r.p_school as passenger_school, r.transaction_id as transaction_id
    FROM reservation r
    INNER JOIN users u ON r.user_id = u.id
    INNER JOIN bus b ON r.bus_id = b.route_id
    WHERE r.date = ? AND r.bus_id = ?
    """
    
    cursor.execute(query, (travel_date, bus_id))
    
    result = cursor.fetchall()
    
    dict_result = [dict(zip([key[0] for key in cursor.description], row)) for row in result]
    print("Debugging CSV add transaction ID:")
    print(dict_result[:1])
    print("entering create_csv fun")
    create_csv(dict_result)
    
    # send file data.csv
    return send_file("./data.csv", as_attachment=True)


@app.route("/home")
@jwt_or_redirect()
def home():
    
    user = get_jwt_identity()

    # check if user is staff
    if user["role"] == "staff":
        title = "WOXSEN Bus Staff Home"

        # get all reservations made in the past 10 days AND bus_id, bus_number
        query = """
            SELECT r.id, r.bus_id, r.date, b.bus_number, b.fare FROM reservation r 
            INNER JOIN users u ON r.user_id = u.id  
            INNER JOIN bus b ON r.bus_id = b.route_id
            WHERE r.date >= date('now', '-10 days') ORDER BY r.date DESC LIMIT 10
        """

        cursor, save, close = connect_db()

        dict_result = {}

        cursor.execute(query)

        dict_result = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
        print(F"dict_result : {dict_result}")

        # filter in bus_number and date and total seats booked
        result = {}

        # {bus_number: {[date, total_seats_booked]}}
        for row in dict_result:
            bus_number = row["bus_number"]
            date = row["date"]
            bus_id = row["bus_id"]
            if bus_number not in result:
                result[bus_number] = {}
            if date not in result[bus_number]:
                result[bus_number][date] = [0, 30, bus_id, row['fare']]
            result[bus_number][date][0] += 1

        for row in dict_result:
            # check if bus_number and date exist in bus_seats
            # if exists, update available_seats = available_seats - total_seats_booked
            # if not exists, insert into bus_seats
            bus_seats_query = "SELECT total_seats FROM bus_seats WHERE bus_number = ? AND date = ?" 

            cursor.execute(bus_seats_query, (row["bus_number"], row["date"]))

            bus_seats_result = cursor.fetchone()
            if bus_seats_result is None:
                # insert into bus_seats
                insert_query = "INSERT INTO bus_seats (bus_number, total_seats, date, fare) VALUES (?, ?, ?, ?)"
                cursor.execute(insert_query, (row["bus_number"], result[row["bus_number"]][row["date"]][1], row["date"], result[row["bus_number"]][row["date"]][3]))
                bus_seats = 30
                fare = result[row["bus_number"]][row["date"]][3]
            else:
                # get available_seats and fare from bus_seats
                get_query = "SELECT total_seats, fare FROM bus_seats WHERE bus_number = ? AND date = ?"
                cursor.execute(get_query, (row["bus_number"], row["date"]))
                r = cursor.fetchone()
                bus_seats = r[0]
                fare = r[1]

            total_seats = bus_seats

            result[row["bus_number"]][row["date"]][1] = total_seats
            result[row["bus_number"]][row["date"]][3] = fare
            # print(total_seats)
        print(F"result : {result}")

        save()
        close()
        return render_template("staff_home.html", title=title, data=result)

        
        # add logic for only friday etc

    # Get the current time in the IST timezone
    ist_timezone = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(ist_timezone).time()
    
    # Create time objects for the desired time range 8:30 to 4 PM
    start_time = dt_time(8, 30)
    end_time = dt_time(23, 0) # change back time to 18
    
    # Check if it's Friday (weekday 4) or Saturday (weekday 5)
    if datetime.today().weekday() in [0, 1, 2, 3, 4, 5] and (start_time <= current_time <= end_time):
        print("DA")
        title = "WOXSEN Bus Student Home"
        return render_template("student_home.html", title=title, routes=bus_routes.values())
    else:
        print("NDA")
        return render_template("Not_Day.html")
   

# new routes
@app.route("/mail-details")
def mail_details():
    try:
        travel_date = request.args["date"]
        bus_number = request.args["bus_number"]
        additional_details = request.args["additional_details"]
        decoded_additional_details = unquote(additional_details)
        # print(F"decoded_details : {decoded_additional_details}")
        # print(f"Recieved data : {date}, {bus_number} and {additional_details}")
        query = "SELECT route_id FROM bus WHERE bus_number = ?"
    
        cursor, _, close = connect_db()
        
        cursor.execute(query, (bus_number,))
        bus_id = cursor.fetchone()[0]
        print(F"Fetched Bus_ID : {bus_id}")
        
        # get all reservations for bus_id on travel_date (email, username, seat, date, bus_number)
        query = """
        SELECT r.date, b.bus_number,r.p_name as passenger_name, r.p_email as passenger_email, r.p_phone as passenger_phone, r.p_school as passenger_school, r.transaction_id as transaction_id
        FROM reservation r
        INNER JOIN users u ON r.user_id = u.id
        INNER JOIN bus b ON r.bus_id = b.route_id
        WHERE r.date = ? AND r.bus_id = ?
        """
        
        cursor.execute(query, (travel_date, bus_id))
        
        result = cursor.fetchall()
        
        dict_result = [dict(zip([key[0] for key in cursor.description], row)) for row in result]
        print(F"dict result in mail debugging for tx_id: {dict_result}")
        print("sending extra mail to transportation@woxsen.edu.in")
        send_extra_mail_to_transport(dict_result[0], decoded_additional_details)
        print("Printing Bulk Mails")
        try:
            conn = smtplib.SMTP("smtp.gmail.com", 587)
            conn.starttls()
            conn.login(from_, pwd)
            for dct in dict_result:
                send_confirmation_mail(dct, decoded_additional_details, con=conn)
                # print(F"dict : {dct['passenger_email']}")
            conn.close()
        except Exception as e:
            print(F"Error Sending email : {str(e)}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(e)
        return jsonify({"status": "error", "msg": str(e)}), 400
    
@app.route("/whatsapp-details")
def whats_details():
    try:
        travel_date = request.args["date"]
        bus_number = request.args["bus_number"]
        additional_details = request.args["additional_details"]
        decoded_additional_details = unquote(additional_details)
        # print(F"decoded_details : {decoded_additional_details}")
        # print(f"Recieved data : {date}, {bus_number} and {additional_details}")
        query = "SELECT route_id FROM bus WHERE bus_number = ?"
    
        cursor, _, close = connect_db()
        
        cursor.execute(query, (bus_number,))
        bus_id = cursor.fetchone()[0]
        print(F"Fetched Bus_ID : {bus_id}")
        
        # get all reservations for bus_id on travel_date (email, username, seat, date, bus_number)
        query = """
        SELECT r.date, b.bus_number,r.p_name as passenger_name, r.p_email as passenger_email, r.p_phone as passenger_phone, r.p_school as passenger_school
        FROM reservation r
        INNER JOIN users u ON r.user_id = u.id
        INNER JOIN bus b ON r.bus_id = b.route_id
        WHERE r.date = ? AND r.bus_id = ?
        """
        
        cursor.execute(query, (travel_date, bus_id))
        
        result = cursor.fetchall()
        
        dict_result = [dict(zip([key[0] for key in cursor.description], row)) for row in result]
        for dct in dict_result:
            # send_confirmation_mail(dct, decoded_additional_details)
            # print(F"dict : {dct}")
            print(F"dict : {dct['passenger_phone']}")
            send_whatsapp_message(dct, decoded_additional_details)


        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(e)
        return jsonify({"status": "error", "msg": str(e)}), 400
    

# new routes end
@app.route("/update-bus-info")
def update_seats():
    try:
        date = request.args["date"]
        bus_number = request.args["bus_number"]
        seats = request.args["seats"]
        fare = request.args["fare"]
        updated_bus_number = request.args["updated_bus_number"]
        # print(F"updated seats : {seats}")
        print(F"Original bus number : {bus_number}")
        print(F"updated_bus_number : {updated_bus_number}")

        cursor, save, close = connect_db()
        
        # Update seats and fare in the bus table for bus_number and date
        update_query = "UPDATE bus_seats SET total_seats = ?, fare = ? WHERE bus_number = ? AND date = ?"
        cursor.execute(update_query, (seats, fare, bus_number, date))
        
        # Update the bus number in the same row
        update_bus_number_query = "UPDATE bus_seats SET bus_number = ? WHERE bus_number = ? AND date = ?"
        cursor.execute(update_bus_number_query, (updated_bus_number, bus_number, date))
        
        update_bus_number_query = "UPDATE bus SET bus_number = ? WHERE bus_number = ?"
        cursor.execute(update_bus_number_query, (updated_bus_number, bus_number))
        
        save()
        close()
        
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(e)
        return jsonify({"status": "error", "msg": str(e)}), 400



@app.route("/search-buses")
def search_bus():
    # get route and date from query params
    bus_route = request.args.get("route",0)
    bus_date = request.args.get("date")
    day_selector = request.args.get("day")
    
    # check if route is valid
    if bus_date is None:
        return jsonify({"msg": "Invalid route"}), 400
    

    route_id = int(bus_route)
    cursor, save, close = connect_db()
    
    # get bus details from db based on route id
    query = "SELECT bus_number,id FROM bus WHERE route_id = ?"
    
    
    cursor.execute(query, (route_id,))
    
    bus_result = cursor.fetchall()
    
    
    route_result = bus_routes[route_id]
    locations = route_result["locations"]
    

    source = route_result["source"]
    destination = route_result["destination"]
    if day_selector == "home":
        start_time = route_result["home"]
    else:
        start_time = route_result["campus"]
    fare = route_result["fare"]
    

    resp_dict = []
    
    for bus in bus_result:
        bus_number = bus[0]
        bus_id =    bus[1]
        # get all the reservations made on the given date from reservations table in db 
        # like date = 2021-03-13
        
        query = f"SELECT id FROM reservation WHERE date LIKE '%%{bus_date}%%' and bus_id = {bus_id} and day_type = '{day_selector}'"
        bus_seat_query = f"SELECT total_seats,fare FROM bus_seats WHERE bus_number = '{bus_number}' and date LIKE '%%{bus_date}%%'"
        
        cursor.execute(query)
        
        reservations = cursor.fetchall()
        count_reservations = len(reservations)
        
        cursor.execute(bus_seat_query)
        res = cursor.fetchone()
        if res is None:
            add_bus_seats_query = f"INSERT INTO bus_seats (bus_number, total_seats, date,fare) VALUES ('{bus_number}', 40, '{bus_date}',{fare})"
            update_bus_fare_query = f"UPDATE bus SET fare = {fare} WHERE bus_number = '{bus_number}'"
            cursor.execute(add_bus_seats_query)
            cursor.execute(update_bus_fare_query)
            total_seats = 40
        else:
            total_seats = res[0]
            fare = res[1]
        
        
        # available seats for each bus is 30 - count of reservations made on the given date
        available_seats = total_seats - count_reservations
        resp_dict.append({"bus_number": bus_number, "available_seats": available_seats, "source": source, "destination": destination, "start_time": start_time, "fare": fare, "bus_id": bus_id, "locations": locations })
    save()
    close()
    return jsonify({"data":resp_dict}), 200

@app.route("/book-seat")
@jwt_or_redirect()
def reserve_seat():
    user_mail = get_jwt_identity()['email']
    print(F"temp_debugging : {user_mail}")
    cursor, save, close = connect_db()
        
    # Update seats and fare in the bus table for bus_number and date
    user_query = F"SELECT * FROM users WHERE email='{user_mail}'"
    cursor.execute(user_query)
    user = cursor.fetchone()
    user_list = list(user)
    close()
    print(user_list)

    return render_template("seat_booking.html", user=user_list)

@app.route("/passenger-details")
@jwt_or_redirect()
def add_passenger():
    return render_template("add_passenger.html")


# Billdesk Logic
def jws_encode(headers, payload, secret_key, algorithm):
    return encode(payload, secret_key, algorithm=algorithm, headers=headers)

def decode_jwt_signature(token, secret_key, algorithm='HS256', headers=None):
    return decode(token, secret_key, algorithms=[algorithm], headers=headers)

@app.route('/thankyou', methods=['GET', 'POST'])
def thank_you():
    return render_template('thankyou.html')

@app.route('/close_popup', methods=['GET', 'POST'])
def close_popup():
    return render_template('close_popup.html')

@app.route("/payment", methods=["POST", "GET"])
@jwt_or_redirect()
def payment():
    # if request.method == 'POST':
    print("New_ Entered /payment")
    global order_id, no_of_seats
    order_id = 'WOX49fbe696e1' + str(random.randint(1000,9999))
    print(F"Checking order id right after setting it:\norder_id : {order_id}")
    amount = str(1.00 * no_of_seats)
    print(F"Amount : {amount}")
    # amount = str(1.00)
    # order_date = int(time.time())
    order_date = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")) + "+05:30"
    # print(order_date)
    currency = '356'
    ru = 'https://woubus.woxsen.edu.in/txn_response'
    additional_info = {
        "additional_info1": "B200910EC",
        "additional_info2": "Anand",
        "additional_info3": "abc@gmail.com",
        "additional_info4": "NA",
        "additional_info5": "NA",
        "additional_info6": "NA",
        "additional_info7": "NA"
    }
    item_code = 'DIRECT'
    device = {
        "init_channel": "internet",
        "ip": "10.108.4.249",
        "user_agent": "Mozilla/5.0",
        "accept_header": "text/html",
    }

    payload = {
        "mercid": mid,
        "orderid": order_id,
        "amount": amount,
        "order_date": order_date,
        "currency": currency,
        "ru": ru,
        "additional_info": additional_info,
        "itemcode": item_code,
        "device": device
    }

    headers = {
        "clientid": client_id,
        "alg": "HS256"
    }

    jws_request = jws_encode(headers, payload, secret_key, 'HS256')
    # print(F'JWT Encoded token : {jws_request}')
    bd_trace_id = str(int(time.time())) + 'ABCD12345'
    bd_timestamp = str(datetime.now().strftime("%Y%m%d%H%M%S"))
    response = requests.post(
        CREATE_API_ENDPOINT,
        headers={
            'Content-Type': 'application/jose',
            'Accept' : 'application/jose',
            'BD-Traceid': bd_trace_id,
            'BD-Timestamp': bd_timestamp 
            # 'Authorization': jws_encode(headers, payload, secret_key, 'HS256')
        },
        data=jws_request
    )
    print(F"Create Order API endpoint : {CREATE_API_ENDPOINT}")
    # print(F"Original encoded request string : {jws_request}")
    # print(F"Response.text : {response.text}")
    print(F"Trace ID : {bd_trace_id}")
    print(F"Timestamp : {bd_timestamp}")

    order_response = decode_jwt_signature(response.text, secret_key, 'HS256', headers)
    print(F"Order Response : {order_response}")
    flow_config = {
        "merchantId": mid,
        "bdOrderId": order_response["bdorderid"],
        "authToken": order_response["links"][1]["headers"]["authorization"],
        "childWindow": False,
        "returnUrl": "https://woubus.woxsen.edu.in/txn_response",
        "retryCount": 3,
        "prefs": {
        "payment_categories": ["card", "nb", "upi"],
        "allowed_bins": ["459150", "525211"]
        },
        "netBanking":{
        "showPopularBanks" : "Y",
        "popularBanks": ["Kotak Bank"," AXIS Bank [Retail]"] 
        }

    }

    if response.status_code == 200:
        print('Order created successfully')
        print(decode_jwt_signature(response.text, secret_key, 'HS256', headers))
        print(F"Before Modifying from response object, checking global order id\norder_id : {order_id}")
        session['order_id_new'] = order_id
        print(F"Checking if session varialble is set : {session.get('order_id_new')}")
        # modify order_id by parsing from response.text
        # return decode_jwt_signature(response.text, secret_key, 'HS256', headers)
        return render_template('payment_page.html', flow_config=flow_config, no_of_seats=no_of_seats)
    else:
        return decode_jwt_signature(response.text, secret_key, 'HS256', headers)


@app.route('/txn_response', methods=['GET', 'POST'])
@jwt_or_redirect()
def txn_response():
    global order_id
    print(F"Global Order Id : {order_id}")
    order_id_new = session.get('order_id_new')
    print(F"Purely printing order_id_new : {session.get('order_id_new')}")
    global client_id
    global mid
    global secret_key
    print("Hit txn Route")
    # print(F"Printing globals():\n{globals()}")
    print(F"Data from outside : \n order_id : {order_id_new}\nclient_id : {client_id}\nmid : {mid}\nsecret_key : {secret_key}")
    headers = {
            "clientid": client_id,
            "alg": "HS256"
        }
    payload = {
                "mercid": mid,
                "orderid": order_id_new,
                } 
    response = requests.post(
            TXGET_API_ENDPOINT,
            headers={
                'Content-Type': 'application/jose',
                'Accept' : 'application/jose',
                'BD-Traceid': str(int(time.time())) + 'ABCD12345',
                'BD-Timestamp': str(datetime.now().strftime("%Y%m%d%H%M%S")),
                # 'Authorization': jws_encode(headers, payload, secret_key, 'HS256')
            },
            data=jws_encode(headers=headers,payload=payload, secret_key=secret_key, algorithm='HS256')
        )
    print("Debugging new issue inside /txn response\nBelow is the response from txget api endpoint")
    # print(response.text)
    jwt_txn_response = decode_jwt_signature(response.text, secret_key, 'HS256', headers)
    print(jwt_txn_response)
    auth_status = str(jwt_txn_response["auth_status"] )
    transaction_status = jwt_txn_response["transaction_error_type"]
    global tx_id
    tx_id = jwt_txn_response["transactionid"]
    print(auth_status, transaction_status, tx_id)
    if auth_status == '0300' and transaction_status == 'success':
            print(F"Type of tx_id before conversion : {tx_id} : {type(tx_id)}")
            tx_id = str(tx_id)
            print(F'Transaction Success\nTransaction ID : {tx_id}')
            # return decode_jwt_signature(response.text, secret_key, 'HS256', headers)
            return render_template('savetodb.html', tx_id=tx_id)
    else:
        return render_template('Payment_Failed.html')

@app.route("/temp_pass_through")
@jwt_or_redirect()
def temp_pass_through():
    tx_id = "1234567890"
    print(F"Sending from temp_pass_through : type - {tx_id} - {type(tx_id)}")
    return render_template('savetodb.html', tx_id=tx_id)

@app.route("/thank_u", methods=["POST"])
@jwt_or_redirect()
def thank_u():
    user = get_jwt_identity()
    print("Last but latest route Debuggin tx_id in /thank_u")
    print(user)
    user_id = user["id"]
    form_data = request.form
    print(F"Form Data : {form_data}")
    
    booking = json.loads(form_data.get("booking"))

    tx_id_new = form_data.get("txidnew")

    print(F"Booking : {booking}")
    print("Up to date changed to .get from json.loads as it's a string and not a json object.")
    print(F"Latest tx id : {tx_id_new}")

    """
    {
        'bus_id': '2', 
        'seats': 1, 
        'date': '2023-10-05', 
        'passengers': [{'name': 'Tarun Kotagiri', 
        'email': 'tarun.kotagiri@woxsen.edu.in', 
        'school': 'School of Business', 
        'studentId': '12345678', 
        'phone': '7032611447'}], 
        'available_seats': '0', 
        'day_type': 'home', 
        'upi_id': 'test@ybl'
        
    }
    
    """
    print("Printing latest booking object from savetodb page")
    print(booking)
    booking_date= booking["date"]
    
    cursor, save, close = connect_db()
    
    # get the available seats for the given bus and date
    query  = f"SELECT id FROM reservation WHERE date LIKE '%%{booking_date}%%' and bus_id = {booking['bus_id']} and day_type = '{booking['day_type']}'"
    
    cursor.execute(query)
    
    print(F'first db call output: {cursor.fetchall()}')

    total_occuiped_seats = len(cursor.fetchall())
        
    # update reservation table with the new reservation
    update_query = "INSERT INTO reservation (bus_id, date, seat,user_id, p_name,p_email, p_school, p_id,p_phone, day_type,transaction_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
    
    seat_nos = []
    # tx_id = "2345678" # temp_pass_through
    # global tx_id
    print(F"appending tx id : {tx_id_new}")
    transaction_id = tx_id_new
    for index, passenger in enumerate(booking['passengers'],start=1):
        seat_no = f"L{total_occuiped_seats + index}"
        seat_nos.append(seat_no)
        available_seats = booking["available_seats"]
        print(F"available_seats : {available_seats}")
        if int(available_seats) <= 0: # mod_new_bus
            print('Making new bus with dummy bus number')
            if booking["bus_id"] == "1":
                booking["bus_id"] = "1.1"
            if booking["bus_id"] == "2":
                booking["bus_id"] = "2.1"
        cursor.execute(update_query, (booking["bus_id"], booking_date, seat_no, user_id, passenger['name'], passenger['email'], passenger['school'], passenger['studentId'],passenger["phone"],booking['day_type'], transaction_id))

    # get bus number from bus table
    query = "SELECT bus_number FROM bus WHERE route_id = ?"
    print(F"fetching busNumber with busID : {booking['bus_id']}")
    cursor.execute(query, (booking["bus_id"],))

    bus_number = cursor.fetchone()[0]
    print(F"Bus_Number : {bus_number}")
    

    save()
    close()
    print("Successfully completed the process, showing thankyou.html")
    return render_template('thankyou.html')
    # return redirect(url_for("logout"))

@app.route("/get_seat_no", methods=["POST", "GET"])
@jwt_or_redirect()
def get_seat_no():
    global no_of_seats
    no_of_seats = int(request.json.get('no_seats'))
    print(F"received no of seats : {no_of_seats}, format : {type(no_of_seats)}")
    return 'Successfully recieved by the python server', 200

def send_whatsapp_message(dct, decoded_additional_details):
    name = dct["passenger_name"]
    phoneNumber = f"+91{dct['passenger_phone']}"
    body = f"""Hi {name},
Thank you for booking with Woxsen Bus. 
Your booking details are as follows:
Booking Date: {dct['date']}
Bus Number: {dct['bus_number']}
Driver Details: {decoded_additional_details}
    """
    decoded = unquote(body)
    print(F"sending data : {decoded}")
    # pywhatkit.sendwhatmsg_instantly(phoneNumber, decoded, 10, tab_close=True)

def send_extra_mail_to_transport(dct, decoded_additional_details):
    print("def_send_extra_mail initiated")
    print(decoded_additional_details)
    decoded_additional_details_html = "<br>".join(decoded_additional_details.split("\n"))
    msg = MIMEMultipart()
    
    msg["From"] = from_
    msg["To"] = "transportation@woxsen.edu.in"
    #msg["To"] = "kotagiritarun@kgr.ac.in"
    msg["Subject"] = "Woxsen Bus Booking Confirmation"
    
    
    body = f"""
    <h1>Hi Srikanth, Below are the details shared to students</h1>
    <p>Thank you for booking with Woxsen Bus. Your booking details are as follows:</p>
    <p><b>Booking Date</b>: {dct['date']}</p>    
    <p><b>Bus Number</b>: {dct['bus_number']}</p>
    <p><b>Transaction ID</b>: transaction ID</p>
    <p><b>Driver Details</b>:<br> {decoded_additional_details_html}</p>
    """
    
    msgHtml = MIMEText(body, "html")
    
    msg.attach(msgHtml)
    
    conn = smtplib.SMTP("smtp.gmail.com", 587)
    conn.starttls()
    
    conn.login(from_, pwd)

    conn.sendmail(from_, msg["To"], msg.as_string())
    print(F"Sent mail to {msg['To']}.")
    
    conn.close()

def send_confirmation_mail(dct, decoded_additional_details, con):
    print(decoded_additional_details)
    decoded_additional_details_html = "<br>".join(decoded_additional_details.split("\n"))
    msg = MIMEMultipart()
    
    msg["From"] = from_
    msg["To"] = dct["passenger_email"]
    msg["Subject"] = "Woxsen Bus Booking Confirmation"
    
    name = dct["passenger_name"]
    transaction_id = dct["transaction_id"]
    print(F"send_mail_function tx id : {transaction_id}")
    
    body = f"""
    <h1>Hi {name},</h1>
    <p>Thank you for booking with Woxsen Bus. Your booking details are as follows:</p>
    <p><b>Booking Date</b>: {dct['date']}</p>    
    <p><b>Bus Number</b>: {dct['bus_number']}</p>
    <p><b>Transaction ID</b>: {transaction_id}</p>
    <p><b>Driver Details</b>:<br> {decoded_additional_details_html}</p>
    """
    
    msgHtml = MIMEText(body, "html")
    
    msg.attach(msgHtml)
    
    # conn = smtplib.SMTP("smtp.gmail.com", 587)
    # conn.starttls()
    
    # conn.login(from_, pwd)

    # conn.sendmail(from_, msg["To"], msg.as_string())
    try:
        con.sendmail(from_, msg["To"], msg.as_string())
    except Exception as e:
        print(F"Sending mail failed with exception : {str(e)}")
    print(F"Sent mail to {msg['To']}.")
    
    # conn.close()
    
    
    


if __name__ == "__main__":
    app.run(debug=True, port = 5123)
