import asyncio
import base64
import hashlib
import random
import uuid
from time import time
from typing import Any, Dict, Optional, Tuple

from curl_cffi import Cookies
from loguru import logger
from solders.message import MessageV0
from solders.transaction import VersionedTransaction

from data.settings import Settings
from libs.base_sol import Base, TokenContracts
from libs.sol_async_py.client import Client
from libs.sol_async_py.data.models import TokenAmount
from libs.sol_async_py.instructions import COMPUTE_BUDGET
from utils.browser import Browser
from utils.db_api.models import Wallet
from utils.db_api.wallet_api import db
from utils.logs_decorator import controller_log
from utils.retry import async_retry


class RangerFinance(Base):
    __module_name__ = "Ranger Finance"

    RANGER_API = "https://prod-spot-api-437363704888.asia-northeast1.run.app/api/v1"

    def __init__(self, client: Client, wallet: Wallet):
        super().__init__(client=client, wallet=wallet)
        self.client = client
        self.wallet = wallet
        self.session = Browser(wallet=wallet)

        self.base_headers = {"referer": "https://www.app.ranger.finance/", "content-type": "application/json"}
        self.cookies = None
        self.privy_uuid = None
        self.privy_id = None

    @async_retry(retries=3, delay=2)
    async def get_quote(
        self,
        *,
        input_mint: str,
        output_mint: str,
        input_amount: int,
        slippage_bps: int = 100,
        user_wallet_address: Optional[str] = None,
        timeout: int = 20,
    ) -> dict:
        user_wallet_address = user_wallet_address or self.wallet.address

        url = (
            f"{self.RANGER_API}/orders/quote?"
            f"user_wallet_address={user_wallet_address}"
            f"&slippage_bps={slippage_bps}"
            f"&input_mint={input_mint}"
            f"&output_mint={output_mint}"
            f"&input_amount={input_amount}"
        )

        r = await self.session.get(url=url, headers=self.base_headers, timeout=timeout)
        # print(input_mint, output_mint, r.text)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def parse_quote_amounts(quote: Dict) -> Tuple[TokenAmount, TokenAmount]:
        def _decimals_for_mint(mint: str) -> int:
            if mint in (str(TokenContracts.USDC.mint), str(TokenContracts.USDT.mint)):
                return 6

            return 9

        out_info = quote.get("output_token_info", {})
        ranger_fee = quote.get("ranger_fee", {})

        out_amount = TokenAmount(amount=out_info.get("amount", 0), decimals=_decimals_for_mint(out_info.get("mint")), wei=True)
        fee_amount = TokenAmount(amount=ranger_fee.get("amount", 0), decimals=_decimals_for_mint(ranger_fee.get("mint")), wei=True)
        return out_amount, fee_amount

    async def best_quote(
        self,
        *,
        input_mint: str,
        output_mint: str,
        input_amount: int,
        slippage_bps: int = 100,
    ) -> Optional[Dict[str, Any]]:
        data = await self.get_quote(
            input_mint=input_mint,
            output_mint=output_mint,
            input_amount=input_amount,
            slippage_bps=slippage_bps,
        )
        quotes = data.get("quotes") or []

        if quotes:
            quotes = [quote for quote in quotes if "d_flow" not in quote["provider"]]

        if not quotes:
            return None

        best = max(quotes, key=lambda q: q["output_token_info"]["amount"])
        # logger.info(
        #     f"[RangerFinance] best quote provider={best['provider']} "
        #     f"amount={best['output_token_info']['amount']}"
        # )
        return best

    @async_retry(retries=3, delay=3)
    async def swap_from_quote(self, from_token, to_token, amount, retries=0) -> str:
        if retries > 3:
            return f"{self.__module__} | Failed after retries"

        quote = await self.best_quote(input_mint=from_token.mint, output_mint=to_token.mint, input_amount=amount.Wei)

        output, ranger_fee = self.parse_quote_amounts(quote)

        tx_b64 = quote.get("transaction")
        if not tx_b64:
            return f"{self.wallet} | {self.__module_name__} | No transaction in quote"

        tx_bytes = base64.b64decode(tx_b64)
        old_tx = VersionedTransaction.from_bytes(tx_bytes)

        onchain_fees = self.client.instruct.parse_from_instructions(old_tx.message)

        max_fee_sol = onchain_fees.max_fee_sol

        logger.debug(
            f"{self.wallet} | {self.__module_name__} | Trying to swap {amount} {from_token} to {output} {to_token} with {ranger_fee} usd ranger fee | onchain fee {max_fee_sol:.5f} sol | via {quote['provider']}"
        )
        from_token_ata = True
        to_token_ata = True

        if from_token != TokenContracts.SOL:
            from_token_ata = await self.client.tx.get_ata(from_token)

        if to_token != TokenContracts.SOL:
            to_token_ata = await self.client.tx.get_ata(to_token)

        if isinstance(old_tx.message, MessageV0):
            logger.debug(f"{self.wallet} | {self.__module_name__} | Message V0 | via {quote['provider']}")

            bh_resp = await self.client.rpc.get_latest_blockhash()
            recent_blockhash = bh_resp.value.blockhash
            account_keys = old_tx.message.account_keys

            try:
                prog_index = account_keys.index(COMPUTE_BUDGET)
            except ValueError:
                raise RuntimeError("ComputeBudget1111 not found in account_keys")

            # MAX_FEE_FROM_SETTINGS::::
            any_token_is_sol = from_token == TokenContracts.SOL or to_token == TokenContracts

            # logger.debug(f'Any token is SOL: {any_token_is_sol}')

            if max_fee_sol > 0.0005 and not any_token_is_sol and from_token_ata and to_token_ata:
                logger.warning(
                    f"{self.wallet} | {self.__module_name__} | Onchain fee too high ({max_fee_sol:.7f} SOL), replacing with custom budget"
                )

                instructions = [
                    self.client.instruct.compile_compute_unit_limit(random.randint(250_000, 290_000), prog_index),
                    self.client.instruct.compile_compute_unit_price(random.randint(450_000, 520_000), prog_index),
                ] + [ix for ix in old_tx.message.instructions if account_keys[ix.program_id_index] != COMPUTE_BUDGET]

            else:
                instructions = old_tx.message.instructions

            new_msg = MessageV0(
                header=old_tx.message.header,
                account_keys=old_tx.message.account_keys,
                recent_blockhash=recent_blockhash,
                instructions=instructions,
                address_table_lookups=old_tx.message.address_table_lookups,
            )

            new_tx = VersionedTransaction(new_msg, [self.client.account])

            sim = await self.client.rpc.simulate_transaction(txn=new_tx, sig_verify=True)

            if sim.value.err:
                if "6024" in str(sim.value.err):
                    logger.warning(f"{self.wallet} | {self.__module_name__} | retrying due to 6024 slippage/liquidity error")
                    await asyncio.sleep(random.randint(5, 7))

                    return await self.swap_from_quote(
                        from_token=from_token,
                        to_token=to_token,
                        amount=amount,
                        retries=retries + 1,
                    )

                if "(1)" in str(sim.value.err):
                    logger.warning(f"{self.wallet} | {self.__module_name__} | not enought balance to swap {amount} {from_token}")

                    raise Exception(
                        f"maybe not enought balance to swap {amount} {from_token} with fee {max_fee_sol} | {str(sim.value.err)}"
                    )

                raise Exception(f"TX Simulation failed: {sim.value.err}")

        else:
            logger.debug(f"{self.wallet} | {self.__module_name__} | LEGACY TX | via {quote['provider']}")
            new_tx = old_tx

            # new_tx = VersionedTransaction(new_tx.message, [self.client.account])

            # #print(old_tx.message)
            # print(recent_blockhash)
            # msg_bytes = bytes(old_tx.message)
            # new_msg_bytes = msg_bytes[:-32] + bytes(recent_blockhash)
            # new_msg = Message.from_bytes(new_msg_bytes)
            # new_tx = VersionedTransaction(new_msg, [self.client.account])

        resp = await self.client.tx.send_tx(message=new_tx.message, skip_simultaion=True)

        if resp:
            try:
                sol_price = await self.get_token_price(token_symbol="SOL")

                max_fee_usd = max_fee_sol * sol_price

                volume = float(output.Ether)
                float(amount.Ether) - volume

                if to_token == TokenContracts.SOL:
                    volume = float(output.Ether) * sol_price

                if from_token == TokenContracts.SOL:
                    volume = float(amount.Ether) * sol_price
                    float(amount.Ether) * sol_price - float(output.Ether)

                self.wallet.sol_fees_usd = round(self.wallet.sol_fees_usd + max_fee_usd, 3)
                self.wallet.ranger_fees = round(self.wallet.ranger_fees + float(ranger_fee.Ether), 3)
                self.wallet.summary_fees = self.wallet.sol_fees_usd + self.wallet.ranger_fees
                self.wallet.volume_onchain = self.wallet.volume_onchain + int(volume)

                db.commit()

            except Exception as e:
                logger.error(f"{self.wallet} | {self.__module_name__} | error in DB write {e}")
                pass

            finally:
                return f"Success | Swapped {amount} {from_token} to {output} {to_token} | Ranger fee {ranger_fee} USD | Onchain fee {max_fee_sol:.7f} sol | via {quote['provider']} |sent tx {resp}"

        raise Exception(f"Something Wrong in {resp}")

    @staticmethod
    def generate_serverless_token(host: str = "www.app.ranger.finance") -> str:
        ts_ms = int(time() * 1000)
        base = f"{host}-{ts_ms}"
        digest = hashlib.sha256(base.encode()).hexdigest()
        return f"{base}__{digest}"

    @staticmethod
    def generate_ga_jrn() -> str:
        now = int(time())
        session_start = now - random.randint(100, 500)
        ttl = 60

        return f"GS2.1.s{session_start}$o1$g1$t{now}$j{ttl}$l0$h0"

    async def old_login(self):
        url = f"https://www.app.ranger.finance/orders/providers"

        headers = {
            **self.base_headers,
            "accept": "*/*",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://www.app.ranger.finance",
        }

        r = await self.browser.get(url=url, headers=headers)

        # r.raise_for_status()
        self.cookies = r.cookies
        return await self.reg_token()

    async def reg_token(self):
        url = f"https://www.app.ranger.finance/api/auth/token"

        headers = {
            **self.base_headers,
            "accept": "*/*",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://www.app.ranger.finance",
        }

        payload = {"solanaAddress": None}

        r = await self.browser.post(
            url=url,
            headers=headers,
            cookies=self.cookies,
            json=payload,
        )
        r.raise_for_status()
        return True

    async def nonce(self):
        self.privy_uuid = str(uuid.uuid4())
        headers = {
            **self.base_headers,
            "accept": "application/json",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "content-type": "application/json",
            "origin": "https://www.app.ranger.finance",
            "priority": "u=1, i",
            "privy-app-id": "cmeiaw35f00dzjl0bztzhen22",
            "privy-ca-id": self.privy_uuid,
            "privy-client": "react-auth:2.21.1",
            "referer": "https://www.app.ranger.finance/",
        }

        payload = {"address": str(self.client.account.pubkey())}

        url = f"https://auth.privy.io/api/v1/siws/init"

        r = await self.browser.post(
            url=url,
            headers=headers,
            cookies=self.cookies,
            json=payload,
        )

        self.cookies = r.cookies
        r.raise_for_status()
        return r.json().get("nonce"), r.json().get("expires_at")

    async def create_privy_wallets(self, auth: str):
        url = "https://auth.privy.io/api/v1/wallets"

        # Shared headers
        base_headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://www.app.ranger.finance",
            "referer": "https://www.app.ranger.finance/",
            "privy-app-id": "cmeiaw35f00dzjl0bztzhen22",
            "privy-client": "react-auth:2.21.1",
            "privy-ca-id": self.privy_uuid,
            "authorization": f"Bearer {auth}",
        }

        payloads = [
            {"chain_type": "ethereum"},
            {"chain_type": "solana"},
        ]

        created = []
        for payload in payloads:
            try:
                resp = await self.browser.post(url=url, headers=base_headers, json=payload, cookies=self.cookies)
                resp.raise_for_status()
                created.append(resp.json())
                logger.success(f"Created privy {payload['chain_type']} wallet")
            except Exception as e:
                logger.error(f"Failed to create privy {payload['chain_type']} wallet: {e}")

        return created

    async def login(self):
        nonce, issued_at = await self.nonce()

        account_b58 = str(self.client.account.pubkey())

        message = (
            "www.app.ranger.finance wants you to sign in with your Solana account:\n"
            f"{account_b58}\n"
            "\n"
            f"You are proving you own {account_b58}.\n"
            "\n"
            "URI: https://www.app.ranger.finance\n"
            "Version: 1\n"
            "Chain ID: mainnet\n"
            f"Nonce: {nonce}\n"
            f"Issued At: {issued_at}\n"
            "Resources:\n"
            "- https://privy.io"
        )

        signature_b58 = self.client.account.sign_message(message=message.encode("utf-8"))
        signature_b64 = base64.b64encode(bytes(signature_b58)).decode()

        payload = {
            "message": message,
            "signature": str(signature_b64),
            "walletClientType": "phantom",
            "connectorType": "solana_adapter",
            "mode": "login-or-sign-up",
            "message_type": "plain",
        }

        headers = {
            **self.base_headers,
            "accept": "application/json",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "content-type": "application/json",
            "origin": "https://www.app.ranger.finance",
            "priority": "u=1, i",
            "privy-app-id": "cmeiaw35f00dzjl0bztzhen22",
            "privy-ca-id": self.privy_uuid,
            "privy-client": "react-auth:2.21.1",
            "referer": "https://www.app.ranger.finance/",
        }

        url = "https://auth.privy.io/api/v1/siws/authenticate"
        r = await self.browser.post(url=url, headers=headers, cookies=self.cookies, json=payload)

        r.raise_for_status()

        resp = r.json()
        self.privy_id = resp.get("user", {}).get("id")
        token = resp.get("privy_access_token")

        linked = resp.get("user", {}).get("linked_accounts", [])
        has_privy_wallet = any(acc.get("wallet_client_type") == "privy" for acc in linked)

        if len(linked) < 3 or not has_privy_wallet:
            logger.info(f"{self.wallet}: Missing linked wallets (found {len(linked)}). Creating via Privy API...")

            await self.create_privy_wallets(token)

        header_check_only = {
            **self.base_headers,
            "accept": "*/*",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://www.app.ranger.finance",
        }

        server_less_cookies = await self.browser.get(url="https://www.app.ranger.finance/leaderboard", headers=header_check_only)

        self.cookies.update(server_less_cookies.cookies)

        if isinstance(self.cookies, Cookies):
            if hasattr(self.cookies, "set"):
                self.cookies.set("privy-session", "t", domain=".privy.io", path="/")

                if token:
                    self.cookies.set("privy-token", token, domain=".privy.io", path="/")
            else:
                self.cookies["privy-session"] = "t"
                if token:
                    self.cookies["privy-token"] = token
        else:
            try:
                self.cookies["privy-session"] = "t"
                if token:
                    self.cookies["privy-token"] = token
            except Exception:
                pass

        data = {"privy_id": self.privy_id}

        # print(data)
        accept = await self.browser.post(
            url="https://www.app.ranger.finance/api/referral/v2/initialize-ranger-account",
            cookies=self.cookies,
            headers=header_check_only,
            json=data,
        )
        accept.raise_for_status()

        resp = accept.json()
        if not resp.get("is_success"):
            logger.error(f"{self.wallet} | {self.__module_name__} | Login failed on initialize-ranger-account")
        return r.json().get("user")

    @controller_log("Apply Refferal Link")
    async def apply_referral(self, invite_code=None):
        if not self.cookies:
            await self.login()

        message = "Sign this message to verify your ownership of this wallet and accept the referral."

        sig = self.client.account.sign_message(message=message.encode("utf-8"))

        # todo select - db or settings
        codes = Settings().invite_codes

        if codes:
            invite_code = random.choice(codes)

            headers = {
                **self.base_headers,
                "accept": "*/*",
                "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                "content-type": "text/plain;charset=UTF-8",
                "origin": "https://www.app.ranger.finance",
            }

            payload = {
                "publicKey": str(self.client.account.pubkey()),
                "privy_id": self.privy_id,
                "code": invite_code,
                "signature": str(sig),
            }

            r = await self.browser.post(
                url="https://www.app.ranger.finance/api/referral/post-referral", json=payload, headers=headers, cookies=self.cookies
            )

            return r.json().get("data").get("referred_status")
        else:
            return "No Refferal Code provided in settings"

    async def get_refferal_status(self):
        if not self.cookies:
            await self.login()

        url = f"https://www.app.ranger.finance/api/referral/get-referral-referrer"

        headers = {
            **self.base_headers,
            "accept": "*/*",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://www.app.ranger.finance",
        }

        payload = {
            "publicKey": str(self.client.account.pubkey()),
        }

        r = await self.browser.post(url=url, headers=headers, cookies=self.cookies, json=payload)

        if r.json().get("status") == 204:
            return False

        else:
            return r.json().get("referrer_wallet_address")

    async def get_leaderboard_rank(self):
        if not self.cookies:
            await self.login()

        url = f"https://www.app.ranger.finance/api/referral/get-leaderboard-rank"

        headers = {
            **self.base_headers,
            "accept": "*/*",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://www.app.ranger.finance",
        }

        payload = {"granularity": "all"}

        r = await self.browser.post(url=url, headers=headers, cookies=self.cookies, json=payload)

        data = r.json().get("data")

        user = [d for d in data if d.get("privy_id") == str(self.privy_id).split(":")[2]]

        if isinstance(user, list) and user:
            return user[0]

        else:
            return user

    async def get_points_information(self):
        # maybe this is old one
        if not self.cookies:
            await self.login()

        url = f"https://www.app.ranger.finance/api/points/information"

        headers = {
            **self.base_headers,
            "accept": "*/*",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://www.app.ranger.finance",
        }

        params = {"publicKey": str(self.client.account.pubkey())}

        r = await self.browser.get(url=url, headers=headers, cookies=self.cookies, params=params)

        return r.json()

    @controller_log("Swap Controller")
    async def swap_controller(self):
        tok = [
            TokenContracts.USDC,
            TokenContracts.USDT,
        ]

        balances = await self.balance_map(token_map=tok)

        from_token = random.choice(list(balances.keys()))

        tok.remove(from_token)

        to_token = random.choice(tok)

        swap = await self.swap_from_quote(from_token=from_token, to_token=to_token, amount=balances[from_token])

        if swap:
            return swap
            logger.success(swap)
