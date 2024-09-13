PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE payment (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        reservation_id INTEGER NOT NULL,
        date varchar(255) NOT NULL,
        amount integer NOT NULL
        );
CREATE TABLE reservation (
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
CREATE TABLE bus (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bus_number varchar(255) NOT NULL,
        route_id varchar(255) NOT NULL,
        seats INTEGER NOT NULL DEFAULT 30,
        fare INTEGER NOT NULL
    );
INSERT INTO bus VALUES(1,'TS 09 FM 9876','1',30,450);
INSERT INTO bus VALUES(2,'TS 09 EM 9776','2',30,450);
INSERT INTO bus VALUES(3,'TS 09 FM 0000','1.1',30,450);
INSERT INTO bus VALUES(4,'TS 09 FM 1111','2.1',30,450);
CREATE TABLE bus_seats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bus_number varchar(255) NOT NULL,
        total_seats INTEGER default 30,
        date varchar(255) NOT NULL,
        fare INTEGER NOT NULL
        );
INSERT INTO bus_seats VALUES(1,'TS 01 AB 1234',30,'2023-04-05',1000);
INSERT INTO bus_seats VALUES(2,'TS 01 AB 1234',30,'2023-04-07',1000);
INSERT INTO bus_seats VALUES(3,'TS 01 AB 1235',30,'2023-04-05',1000);
INSERT INTO bus_seats VALUES(4,'TS 01 AB 1234',30,'2023-04-06',1000);
INSERT INTO bus_seats VALUES(5,'TS 09 FM 9876',40,'2023-09-26',450);
INSERT INTO bus_seats VALUES(6,'TS 09 EM 9776',40,'2023-09-26',450);
INSERT INTO bus_seats VALUES(7,'TS 09 FM 9876',30,'2023-09-27',450);
INSERT INTO bus_seats VALUES(8,'TS 09 EM 9776',30,'2023-09-27',450);
INSERT INTO bus_seats VALUES(9,'TS 09 FM 9876',30,'2023-09-28',450);
INSERT INTO bus_seats VALUES(10,'TS 09 FM 9876',30,'2023-10-05',450);
INSERT INTO bus_seats VALUES(11,'TS 09 EM 9776',30,'2023-10-05',450);
INSERT INTO bus_seats VALUES(12,'TS 09 FM 9876',30,'2023-10-07',450);
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stu_id VARCHAR(255),
    name VARCHAR(255),
    mobile VARCHAR(15),
    email VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    school VARCHAR(255),
    role VARCHAR(50)
);
INSERT INTO users VALUES(1,'170925','Tarun Kotagiri','7032611447','tarun.kotagiri@woxsen.edu.in','123456','School of Business','student');
INSERT INTO users VALUES(2,'123456','admin','8978290172','transport@woxsen.edu.in','$rikanth@123','woxsen','staff');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('bus',4);
INSERT INTO sqlite_sequence VALUES('bus_seats',12);
INSERT INTO sqlite_sequence VALUES('reservation',18);
INSERT INTO sqlite_sequence VALUES('users',2);
COMMIT;
