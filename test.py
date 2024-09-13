import sqlite3


def connect_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    # create user table if not exists
    reservation_table_query = """
    CREATE TABLE IF NOT EXISTS reservation (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date varchar(255) NOT NULL,
        seat varchar(255) NOT NULL,
        p_name varchar(255) NOT NULL,
        bus_id INTEGER NOT NULL,
        p_email varchar(255) NOT NULL, 
        p_phone varchar(255) NOT NULL,
        p_school varchar(255) NOT NULL,
        p_id varchar(255) NOT NULL,
        day_type varchar(255) NOT NULL,
        transaction_id text NOT NULL
        );
    """
    
    payment_table_query = """
    CREATE TABLE IF NOT EXISTS payment (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        reservation_id INTEGER NOT NULL,
        date varchar(255) NOT NULL,
        amount integer NOT NULL
        );
    """
    
    
    bus_table_query = """
    CREATE TABLE IF NOT EXISTS bus (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bus_number varchar(255) NOT NULL,
        route_id varchar(255) NOT NULL,
        seats INTEGER NOT NULL DEFAULT 30,
        fare INTEGER NOT NULL
    );
    """

        
    c.execute("drop table reservation")
    # c.execute("drop table routes")
    c.execute("drop table bus")
    c.execute(reservation_table_query)
    c.execute(payment_table_query)
    c.execute(bus_table_query)
    # c.execute(routes_table_query)
    
    save = conn.commit
    close = conn.close
    return c, save, close



cursor, save, close = connect_db()


# create a new table called bus seats
# column bus_number, available_seats, date
query  = """
    CREATE TABLE IF NOT EXISTS bus_seats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bus_number varchar(255) NOT NULL,
        total_seats INTEGER default 30,
        date varchar(255) NOT NULL,
        fare INTEGER NOT NULL
        )
    """
    
cursor.execute("drop table bus_seats")
cursor.execute(query)

"""
bus_number varchar(255) NOT NULL,
        route_id varchar(255) NOT NULL,
        seats INTEGER NOT NULL DEFAULT 30,
        fare INTEGER NOT NULL
"""

# insert data into the table
buses= [
    ("TS 01 AB 1234", "1", 30, 1000),
    ("TS 01 AB 1235", "2", 30, 1100)
]

for bus in buses:
    cursor.execute("INSERT INTO bus (bus_number, route_id, seats, fare) VALUES (?, ?, ?, ?)", bus)

users = [
    ("Shobika", "shobika.gaddam_2023@woxsen.edu.in", "123456", "hyd",)
]

for user in users:
    cursor.execute("INSERT INTO users (username, email, password, address,role) VALUES (?, ?, ?, ?, 'student')", user)

save()
close()