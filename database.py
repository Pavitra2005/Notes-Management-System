import mysql.connector

db=mysql.connector.connect(
    host='localhost',
    user='root',
    password='1234',
    database='personal_records'
)

cursor=db.cursor()
