import asyncio
import random

from eth_account.messages import _hash_eip191_message, encode_defunct, encode_typed_data
from hexbytes import HexBytes
from loguru import logger
from web3.exceptions import TimeExhausted
from web3.types import TxParams

from libs.eth_async.client import Client
from libs.eth_async.data.models import TokenAmount
from utils.browser import Browser
from utils.db_api.models import Wallet


class Base:
    __module__ = "Web3 Base"

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

        for _ in range(5):
            try:
                async with self.browser:
                    r = await self.browser.get(url=f"https://api.binance.com/api/v3/depth?limit=1&symbol={token_symbol}{second_token}")
                    if r.status_code != 200:
                        return None
                    result_dict = r.json()
                    if "asks" not in result_dict:
                        return None
                    return float(result_dict["asks"][0][0])
            except Exception:
                await asyncio.sleep(5)
        raise ValueError(f"Can not get {token_symbol + second_token} price from Binance")

    async def approve_interface(self, token_address, spender, amount: TokenAmount | None = None) -> bool:
        balance = await self.client.wallet.balance(token=token_address)
        if balance.Wei <= 0:
            return False

        if not amount or amount.Wei > balance.Wei:
            amount = balance

        approved = await self.client.transactions.approved_amount(token=token_address, spender=spender, owner=self.client.account.address)

        if amount.Wei <= approved.Wei:
            return True

        # print(f'Trying to approve: {token_address} {amount.Ether} - {amount.Wei}')

        tx = await self.client.transactions.approve(token=token_address, spender=spender, amount=amount)

        receipt = await tx.wait_for_receipt(client=self.client, timeout=300)
        if receipt:
            return True

        return False

    async def get_token_info(self, contract_address):
        contract = await self.client.contracts.default_token(contract_address=contract_address)
        print("name:", await contract.functions.name().call())
        print("symbol:", await contract.functions.symbol().call())
        print("decimals:", await contract.functions.decimals().call())

    @staticmethod
    def parse_params(params: str, has_function: bool = True):
        if has_function:
            function_signature = params[:10]
            print("function_signature", function_signature)
            params = params[10:]
        while params:
            print(params[:64])
            params = params[64:]

    async def sign_message(self, text: str = None, typed_data: dict = None, hash: bool = False):
        if text:
            message = encode_defunct(text=text)
        elif typed_data:
            message = encode_typed_data(full_message=typed_data)
            if hash:
                message = encode_defunct(hexstr=_hash_eip191_message(message).hex())

        signed_message = self.client.account.sign_message(message)

        signature = signed_message.signature.hex()

        if not signature.startswith("0x"):
            signature = "0x" + signature
        return signature

    async def send_eth(self, to_address, amount: TokenAmount):
        tx_params = TxParams(to=to_address, data="0x", value=amount.Wei)

        tx = await self.client.transactions.sign_and_send(tx_params=tx_params)
        await asyncio.sleep(random.randint(2, 4))
        receipt = await tx.wait_for_receipt(client=self.client, timeout=300)
        if receipt:
            return f"Balance Sender | Success send {amount.Ether:.5f} ETH to {to_address}"

        else:
            return f"Balance Sender | Failed"

    async def wait_tx_status(
        self,
        tx_hash: HexBytes,
        max_wait_time: int = 100,
    ) -> bool:
        try:
            receipt = await self.client.w3.eth.wait_for_transaction_receipt(
                transaction_hash=tx_hash,
                timeout=max_wait_time,
            )
        except TimeExhausted:
            logger.error("{0} получил неудачную транзакцию", self.client.account.address)
            return False
        status = receipt.get("status")
        if status == 1:
            return True
        return False
