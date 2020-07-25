from app import db, User

db.drop_all()
db.create_all()

admin_user = User(username="admin", password="$2b$12$fNx0I/0hDcuN3MS6HI1Ubu.KYW0aVoHdroNhziGXZsbCt8FBkINI.",
                  phone='12345678901', admin=True)
db.session.add(admin_user)
db.session.commit()

exit()
