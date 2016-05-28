from init import db,app


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    login = db.Column(db.String(20))
    pw_hash = db.Column(db.String(64))


class Animal(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50))
    location = db.Column(db.String(50))
    # creator_id holds the ID of a valid user
    # reference table names by lowercasing the class name
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # a *relationship* lets us resolve the creator id
    # this will also create an 'animals' on User to access their
    # animals.
    creator = db.relationship('User', backref='animals')

db.create_all(app=app)