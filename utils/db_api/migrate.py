from utils.db_api.db import DB

db = DB("sqlite:///files/wallets.db")
db.add_column_to_table("wallets", "twitter_status", "VARCHAR", "OK")
