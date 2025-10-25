import os
import sys
from types import SimpleNamespace
from typing import Dict, List, Optional

from loguru import logger

from data.config import FILES_DIR
from data.settings import Settings
from libs.sol_async_py.client import Client
from libs.sol_async_py.data.models import Networks
from utils.db_api.models import Wallet
from utils.db_api.wallet_api import db, get_wallet_by_address
from utils.encryption import check_encrypt_param, get_private_key, prk_encrypt


def parse_proxy(proxy: str | None) -> Optional[str]:
    if not proxy:
        return None
    if proxy.startswith("http"):
        return proxy
    elif "@" in proxy and not proxy.startswith("http"):
        return "http://" + proxy
    else:
        value = proxy.split(":")
        if len(value) == 4:
            ip, port, login, password = value
            return f"http://{login}:{password}@{ip}:{port}"
        else:
            print(f"Invalid proxy format: {proxy}")
            return None


def pick_proxy(proxies: list, i: int) -> Optional[str]:
    if not proxies:
        return None
    return proxies[i % len(proxies)]


def remove_line_from_file(value: str, filename: str) -> bool:
    file_path = os.path.join(FILES_DIR, filename)

    if not os.path.isfile(file_path):
        return False

    with open(file_path, encoding="utf-8") as f:
        lines = [line.rstrip("\n") for line in f]

    original_len = len(lines)

    keep = [line for line in lines if line.strip() != value.strip()]

    if len(keep) == original_len:
        return False

    with open(file_path, "w", encoding="utf-8") as f:
        for line in keep:
            f.write(line + "\n")
    return True


def read_lines(path: str) -> List[str]:
    file_path = os.path.join(FILES_DIR, path)
    if not os.path.isfile(file_path):
        return []
    with open(file_path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


class Import:
    @staticmethod
    def parse_wallet_from_txt() -> List[Dict[str, Optional[str]]]:
        private_keys = read_lines("private_keys.txt")
        proxies = read_lines("proxy.txt")
        deposit_addresses = read_lines("deposit_addresses.txt")

        if not private_keys:
            raise ValueError("File private_keys.txt must not be empty")

        record_count = len(private_keys)

        wallets: List[Dict[str, Optional[str]]] = []
        for i in range(record_count):
            wallets.append(
                {
                    "private_key": private_keys[i],
                    "proxy": parse_proxy(pick_proxy(proxies, i)),
                    "deposit_address": deposit_addresses[i] if i < len(deposit_addresses) else None,
                }
            )

        return wallets

    @staticmethod
    async def wallets():
        check_encrypt_param(confirm=True)

        raw_wallets = Import.parse_wallet_from_txt()

        logger.success("Wallet import to the database is in progress…")

        wallets = [SimpleNamespace(**w) for w in raw_wallets]

        imported: list[Wallet] = []
        edited: list[Wallet] = []
        total = len(wallets)

        check_wallets = db.all(Wallet)

        if len(check_wallets) > 0:
            # Check pwd1
            try:
                check_wallet = check_wallets[0]
                get_private_key(check_wallet.private_key)

            except Exception as e:
                sys.exit(f"Database not empty | You must use same password for new wallets | {e}")

        for wl in wallets:
            decoded_private_key = get_private_key(wl.private_key)

            client = Client(private_key=decoded_private_key, network=Networks.Solana)

            wallet_instance = get_wallet_by_address(address=str(client.account.pubkey()))

            if wallet_instance:
                changed = False

                if wallet_instance.address == str(client.account.pubkey()):
                    wallet_instance.private_key = prk_encrypt(decoded_private_key) if not "gAAAA" in wl.private_key else wl.private_key
                    changed = True

                if wallet_instance.proxy != wl.proxy:
                    wallet_instance.proxy = wl.proxy
                    changed = True

                if hasattr(wallet_instance, "deposit_address") and wallet_instance.deposit_address != wl.deposit_address:
                    wallet_instance.deposit_address = wl.deposit_address
                    changed = True
                #
                # if hasattr(wallet_instance, "discord_token") and wallet_instance.discord_token != wl.discord_token:
                #     wallet_instance.discord_token = wl.discord_token
                #     changed = True

                if changed:
                    db.commit()
                    edited.append(wallet_instance)
                    remove_line_from_file(wl.private_key, "private_keys.txt")

                continue

            wallet_instance = Wallet(
                private_key=prk_encrypt(wl.private_key) if not "gAAAA" in wl.private_key else wl.private_key,
                address=str(client.account.pubkey()),
                proxy=wl.proxy,
                deposit_address=wl.deposit_address,
                # discord_token=wl.discord_token,
            )

            remove_line_from_file(wl.private_key, "private_keys.txt")

            # if not wallet_instance.twitter_token:
            #     logger.warning(
            #         f"{wallet_instance.id} | {wallet_instance.address} | Twitter Token not found, Twitter Action will be skipped"
            #     )
            #
            # if not wallet_instance.discord_token:
            #     logger.warning(
            #         f"{wallet_instance.id} | {wallet_instance.address} | Discord Token not found, Discord Action will be skipped"
            #     )

            db.insert(wallet_instance)
            imported.append(wallet_instance)

        logger.success(f"Done! imported wallets: {len(imported)}/{total}; edited wallets: {len(edited)}/{total}; total: {total}")


class Sync:
    @staticmethod
    def parse_tokens_and_proxies_from_txt(wallets: List) -> List[Dict[str, Optional[str]]]:
        proxies = read_lines("proxy.txt")
        deposit_address = read_lines("deposit_address.txt")
        # discord_tokens = read_lines("discord_tokens.txt")

        record_count = len(wallets)

        wallet_auxiliary: List[Dict[str, Optional[str]]] = []
        for i in range(record_count):
            wallet_auxiliary.append(
                {
                    "proxy": parse_proxy(pick_proxy(proxies, i)),
                    "deposit_address": deposit_address[i] if i < len(deposit_address) else None,
                    # "discord_token": discord_tokens[i] if i < len(discord_tokens) else None,
                }
            )

        return wallet_auxiliary

    @staticmethod
    async def sync_wallets_with_tokens_and_proxies():
        if not check_encrypt_param():
            logger.error(f"Decryption Failed | Wrong Password")
            return

        wallets = db.all(Wallet)

        if len(wallets) <= 0:
            logger.warning("No wallets in DB, nothing to update")
            return

        wallet_auxiliary_data_raw = Sync.parse_tokens_and_proxies_from_txt(wallets)

        wallet_auxiliary_data = [SimpleNamespace(**w) for w in wallet_auxiliary_data_raw]

        if len(wallet_auxiliary_data) != len(wallets):
            logger.warning("Mismatch between wallet data and tokens/proxies data. Exiting sync.")
            return

        total = len(wallets)

        logger.info(f"Start syncing wallets: {total}")

        edited: list[Wallet] = []
        for wl in wallets:
            decoded_private_key = get_private_key(wl.private_key)

            client = Client(private_key=decoded_private_key, network=Networks.Solana)

            wallet_instance = get_wallet_by_address(address=str(client.account.pubkey()))

            if wallet_instance:
                changed = False

                wallet_data = wallet_auxiliary_data[wallet_instance.id - 1]
                if wallet_instance.proxy != wallet_data.proxy:
                    wallet_instance.proxy = wallet_data.proxy
                    changed = True

                if hasattr(wallet_instance, "deposit_address") and wallet_instance.deposit_address != wallet_data.deposit_address:
                    wallet_instance.twitter_token = wallet_data.deposit_address
                    changed = True

                if changed:
                    db.commit()
                    edited.append(wallet_instance)

        logger.success(f"Done! edited wallets: {len(edited)}/{total}; total: {total}")


class Export:
    _FILES = {
        "private_key": "exported_private_keys.txt",
        "proxy": "exported_proxy.txt",
        "deposit_address": "exported_deposit_address.txt",
    }

    @staticmethod
    def _write_lines(filename: str, lines: List[Optional[str]]) -> None:
        path = os.path.join(FILES_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write((line or "") + "\n")

    @staticmethod
    async def wallets_to_txt() -> None:
        if not check_encrypt_param():
            logger.error(f"Decryption Failed | Wrong Password")
            return

        wallets: List[Wallet] = db.all(Wallet)

        if not wallets:
            logger.warning("Export: no wallets in db, skip....")
            return

        buf = {key: [] for key in Export._FILES.keys()}

        for w in wallets:
            prk = get_private_key(w.private_key) if Settings().private_key_encryption else w.private_key
            buf["private_key"].append(prk)

            buf["proxy"].append(w.proxy or "")
            buf["deposit_address"].append(w.deposit_address or "")

        for field, filename in Export._FILES.items():
            Export._write_lines(filename, buf[field])

        logger.success(f"Export: exported {len(wallets)} wallets in {FILES_DIR}")
