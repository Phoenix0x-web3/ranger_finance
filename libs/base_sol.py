import asyncio
import base64

from loguru import logger
from solders.transaction import VersionedTransaction

from libs.sol_async_py.client import Client
from libs.sol_async_py.data.models import RawContract, TokenAmount
from utils.browser import Browser
from utils.db_api.models import Wallet


class TokenContracts:
    SOL = RawContract(
        title="SOL", mint="So11111111111111111111111111111111111111112", program="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", decimals=9
    )

    USDC = RawContract(
        title="USDC", mint="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", program="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", decimals=6
    )

    USDT = RawContract(
        title="USDT", mint="Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", program="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", decimals=6
    )


class Base:
    def __init__(self, client: Client, wallet: Wallet):
        self.client: Client = client
        self.wallet: Wallet = wallet
        self.browser: Browser = Browser(wallet=self.wallet)

    async def get_token_price(self, token_symbol="ETH", second_token: str = "USDT") -> float | None:
        token_symbol, second_token = token_symbol.upper(), second_token.upper()

        if token_symbol.upper() in ("USDC", "USDC.E", "USDT", "DAI", "CEBUSD", "BUSD"):
            return 1
        if token_symbol == "WETH":
            token_symbol = "ETH"
        if token_symbol == "USDC.E":
            token_symbol = "USDC"

        if token_symbol in ["USDC", "USDT"]:
            return 1.0

        for _ in range(5):
            try:
                r = await self.browser.get(url=f"https://api.binance.com/api/v3/depth?limit=1&symbol={token_symbol}{second_token}")
                if r.status_code != 200:
                    return None
                result_dict = r.json()
                if "asks" not in result_dict:
                    return None
                return float(result_dict["asks"][0][0])
            except Exception as e:
                print(e)
                await asyncio.sleep(5)
        raise ValueError(f"Can not get {token_symbol + second_token} price from Binance")

    async def balance_map(self, token_map: list):
        tokens = {}

        for token in token_map:
            try:
                if token == TokenContracts.SOL:
                    balance: TokenAmount = await self.client.wallet.balance()

                else:
                    balance: TokenAmount = await self.client.wallet.balance(token=token)

                # if balance.Ether > 0.0001:
                #     tokens[token] = balance

                tokens[token] = balance

            except Exception as e:
                if "Invalid param: could not find account" in str(e):
                    tokens[token] = TokenAmount(amount=0, decimals=token.decimals)

                continue

        return tokens

    async def usd_balance_map(self, balances):
        sol_price = await self.get_token_price(token_symbol="SOL")

        usd_balanced = {}
        for token, balance in balances.items():
            if token == TokenContracts.SOL:
                usd_balanced[token] = float(balance.Ether) * sol_price
            else:
                usd_balanced[token] = float(balance.Ether)

        return usd_balanced

    async def debug_blockhashes(self, tx_b64: str) -> dict:
        tx = VersionedTransaction.from_bytes(base64.b64decode(tx_b64))

        api_bh = tx.message.recent_blockhash
        api_bh_str = str(api_bh)

        latest = await self.client.rpc.get_latest_blockhash()
        latest_bh = latest.value.blockhash
        last_valid_bh = latest.value.last_valid_block_height
        cur_height = (await self.client.rpc.get_block_height()).value

        is_valid = None

        try:
            resp = await self.client.rpc.is_blockhash_valid(api_bh)

            is_valid = getattr(resp, "value", None)
        except Exception:
            is_valid = None

        # ComputeBudget snapshot
        limit, micro = 200_000, 0

        for ix in tx.message.instructions:
            parsed = self.client.instruct.parse_compute_budget(ix, tx.message.account_keys)
            if not parsed:
                continue
            if parsed["type"] == "limit":
                limit = parsed["units"]
            elif parsed["type"] == "price":
                micro = parsed["micro_lamports"]

        if micro > 0:
            fee_lamports = (limit * micro) // 1_000_000
            fee_sol = fee_lamports / 1e9
            logger.info(f"[RangerFinance] ComputeBudget → limit={limit:,} CU | price={micro:,} µLamports | max_fee≈{fee_sol:.6f} SOL")
        else:
            logger.info(f"[RangerFinance] ComputeBudget → limit={limit:,} CU | price not set (default fee)")

        logger.info(
            f"[RangerFinance] Blockhashes → api={api_bh_str} | latest={latest_bh} | "
            f"cur_height={cur_height} | last_valid={last_valid_bh} | is_valid={is_valid}"
        )

        return {
            "api_blockhash": api_bh_str,
            "latest_blockhash": str(latest_bh),
            "current_block_height": cur_height,
            "last_valid_block_height": last_valid_bh,
            "is_valid": is_valid,
            "compute_limit": limit,
            "compute_price_micro": micro,
        }
