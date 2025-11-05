import sys

import yaml
from loguru import logger

from data.config import LOG_FILE, SETTINGS_FILE
from libs.eth_async.classes import Singleton


class Settings(Singleton):
    def __init__(self):
        with open(SETTINGS_FILE, "r") as file:
            json_data = yaml.safe_load(file) or {}

        self.check_git_updates = json_data.get("check_git_updates", True)
        self.private_key_encryption = json_data.get("private_key_encryption", False)
        self.threads = json_data.get("threads", 4)
        self.range_wallets_to_run = json_data.get("range_wallets_to_run", [])
        self.exact_wallets_to_run = json_data.get("exact_wallets_to_run", [])
        self.shuffle_wallets = json_data.get("shuffle_wallets", True)
        self.show_wallet_address_logs = json_data.get("show_wallet_address_logs", True)
        self.log_level = json_data.get("log_level", "INFO")
        self.random_pause_start_wallet_min = json_data.get("random_pause_start_wallet", {}).get("min")
        self.random_pause_start_wallet_max = json_data.get("random_pause_start_wallet", {}).get("max")
        self.random_pause_between_actions_min = json_data.get("random_pause_between_actions", {}).get("min")
        self.random_pause_between_actions_max = json_data.get("random_pause_between_actions", {}).get("max")
        self.random_pause_wallet_after_completion_min = json_data.get("random_pause_wallet_after_completion", {}).get("min")
        self.random_pause_wallet_after_completion_max = json_data.get("random_pause_wallet_after_completion", {}).get("max")

        self.withdrawal_amount_min = json_data.get("withdrawal_amount", {}).get("min")
        self.withdrawal_amount_max = json_data.get("withdrawal_amount", {}).get("max")

        self.refill_usd_amount_min = json_data.get("refill_usd_amount", {}).get("min")
        self.refill_usd_amount_max = json_data.get("refill_usd_amount", {}).get("max")

        self.stablecoin_swap_percentage_min = json_data.get("stablecoin_swap_percentage", {}).get("min", 80)
        self.stablecoin_swap_percentage_max = json_data.get("stablecoin_swap_percentage", {}).get("max", 100)

        self.swaps_count_min = json_data.get("swaps_count", {}).get("min")
        self.swaps_count_max = json_data.get("swaps_count", {}).get("max")

        self.swap_tokens = json_data.get("swap_tokens", ["USDT", "USDC"])

        self.okx_api_key = json_data.get("okx_api_key", "")
        self.okx_api_secret = json_data.get("okx_api_secret", "")
        self.okx_passphrase = json_data.get("okx_passphrase", "")

        self.minimal_sol_balance = json_data.get("minimal_sol_balance", "")
        self.sol_balance_for_commissions_min = json_data.get("sol_balance_for_commissions", {}).get("min")
        self.sol_balance_for_commissions_max = json_data.get("sol_balance_for_commissions", {}).get("max")
        self.invite_codes = json_data.get("invite_codes", "")

        self.tg_bot_id = json_data.get("tg_bot_id", "")
        self.tg_user_id = json_data.get("tg_user_id", "")

        self.retry = json_data.get("retry", {})


# Configure the logger based on the settings
settings = Settings()

if settings.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR"]:
    raise ValueError(f"Invalid log level: {settings.log_level}. Must be one of: DEBUG, INFO, WARNING, ERROR")
logger.remove()  # Remove the default logger
logger.add(sys.stderr, level=settings.log_level)

logger.add(LOG_FILE, level="DEBUG")
