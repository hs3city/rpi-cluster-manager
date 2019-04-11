import os
from datetime import datetime, timedelta

import peewee as pw
from werkzeug.security import check_password_hash, generate_password_hash

db = pw.SqliteDatabase(os.environ.get("DB_PATH", "whoisdevices.db"))

# TODO change
class User(pw.Model):
    id = pw.PrimaryKeyField()
    username = pw.CharField(unique=True)
    _password = pw.CharField(column_name="password")
    display_name = pw.CharField()
    flags = pw.BitField(null=True)

    is_hidden = flags.flag(1)
    is_name_anonymous = flags.flag(2)

    class Meta:
        database = db

    @classmethod
    def register(cls, username, password, display_name=None):
        """
        Creates user and hashes his password
        :param username: used in login
        :param password: plain text to be hashed
        :param display_name: displayed username
        :return: user instance
        """
        # TODO: ehh
        user = cls.create(
            username=username, _password="todo", display_name=display_name
        )
        user.password = password
        return user

    def __str__(self):
        if self.is_name_anonymous or self.is_hidden:
            return "anonymous"
        else:
            return self.display_name

    @property
    def is_active(self):
        return self.username is not None

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        """
        Needed by flask login
        :return:
        """
        return False

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, new_password):
        if len(new_password) < 3:
            raise Exception("too_short")
        else:
            self._password = generate_password_hash(new_password)

    def auth(self, password):
        return check_password_hash(self.password, password)

# TODO change
class Device(pw.Model):
    mac_address = pw.FixedCharField(primary_key=True, unique=True, max_length=17)
    owner = pw.ForeignKeyField(
        User, backref="devices", column_name="user_id", null=True
    )

    class Meta:
        database = db

    def __str__(self):
        return self.mac_address

    @classmethod
    def update_or_create(cls, mac_address):
        mac_address = mac_address.upper()
        try:
            res = cls.create(mac_address=mac_address)
            res.save()
        except pw.IntegrityError:
            res = cls.get(cls.mac_address == mac_address)


        return res
