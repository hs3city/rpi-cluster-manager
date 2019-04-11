import os
import logging
from whois.database import db, Device, User

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("db_create")

logger.info("connect to db at {}".format(os.environ.get("DB_PATH", "whoisdevices.db")))
db.connect()
logger.info("creating tables")
db.create_tables([Device, User])

u=User.register('test', 'test', 'test')
u.save()
Device(mac_address='FF:FF:FF:FF:FF:11', owner=u.get_id()).save()
# dm1 = Device.create(mac_address='00:00:00:00:00:00', last_seen=datetime.now())
# dm1.save()
