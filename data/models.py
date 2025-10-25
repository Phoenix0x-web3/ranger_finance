from dataclasses import dataclass

from data.settings import Settings
from libs.py_okx_async.models import OKXCredentials

settings = Settings()


@dataclass
class FromTo:
    from_: int | float
    to_: int | float


class OkxModel:
    required_minimum_balance: float
    withdraw_amount: FromTo
    delay_between_withdrawals: FromTo
    credentials: OKXCredentials


okx = OkxModel()
okx_credentials = OKXCredentials(api_key=settings.okx_api_key, secret_key=settings.okx_api_secret, passphrase=settings.okx_passphrase)
