from __future__ import annotations

import json
import random
from typing import TYPE_CHECKING

from solders.instruction import Instruction
from solders.pubkey import Pubkey
from solders.rpc.errors import InvalidParamsMessage
from solders.system_program import TransferParams, transfer
from solders.token.associated import get_associated_token_address
from solders.transaction import VersionedTransaction
from spl.token.instructions import TransferCheckedParams, transfer_checked

from .data.models import RawContract, TokenAmount

if TYPE_CHECKING:
    from .client import Client


class Wallet:
    def __init__(self, client: Client):
        self.client = client

    async def get_transactions(self, address: str | Pubkey = None):
        if isinstance(address, str):
            address = Pubkey.from_string(address)

        if address is None:
            address = self.client.account.pubkey()

        data = await self.client.rpc.get_signatures_for_address(account=address, commitment="finalized")

        form = json.loads(data.to_json())
        data = form.get("result")

        return data

    async def get_token_decimals(self, token):
        if token == str(self.client.account.pubkey()):
            return 9

        token = Pubkey.from_string(token)
        info = await self.client.rpc.get_token_supply(token)

        if info.value.decimals:
            print(info.value.decimals)
            return info.value.decimals

        return None

    async def balance(
        self,
        token=None,
    ):
        if not token:
            balance = await self.client.rpc.get_balance(pubkey=self.client.account.pubkey())

            return TokenAmount(amount=balance.value, decimals=9, wei=True)

        associated_token = get_associated_token_address(
            wallet_address=self.client.account.pubkey(), token_mint_address=token.mint, token_program_id=token.program
        )

        balance = await self.client.rpc.get_token_account_balance(associated_token)

        if isinstance(balance, InvalidParamsMessage):
            return TokenAmount(amount=0)

        return TokenAmount(amount=int(balance.value.amount), decimals=balance.value.decimals, wei=True)

    async def transfer_native(self, to_address: str | Pubkey, amount: int | TokenAmount, return_ix: bool = False):
        if isinstance(to_address, str):
            to_address = Pubkey.from_string(to_address)

        if isinstance(to_address, int):
            amount = TokenAmount(amount=amount)

        if not amount:
            return "No amount provided"

        transfer_tx = transfer(TransferParams(from_pubkey=self.client.account.pubkey(), to_pubkey=to_address, lamports=amount.Wei))

        if return_ix:
            return transfer_tx

        tx = await self.client.tx.prepare_tx(instructions=transfer_tx)

        return await self.send_tx(message=tx)

    async def transfer_token2022(
        self,
        to_address: str | Pubkey,
        amount: int | TokenAmount,
        token: RawContract,
        return_ix: bool = False,
    ):
        if isinstance(to_address, str):
            to_address = Pubkey.from_string(to_address)

        if isinstance(to_address, int):
            amount = TokenAmount(amount=amount)

        if not amount:
            return "No amount provided"

            # --- деривация ATA ---

        sender_ata = get_associated_token_address(
            wallet_address=self.client.account.pubkey(),
            token_mint_address=token.mint,
            token_program_id=token.program,
        )

        recipient_ata = get_associated_token_address(
            wallet_address=to_address,
            token_mint_address=token.mint,
            token_program_id=token.program,
        )
        # print(sender_ata, recipient_ata)

        data = random.randint(190000, 200000)
        Instruction(
            program_id=Pubkey.from_string("ComputeBudget111111111111111111111111111111"),
            accounts=[],
            data=bytes([2]) + (data).to_bytes(4, "little"),
        )

        # 2. Установка цены за вычислительную единицу
        # data = random.randint(4900, 5100)
        data = random.randint(3700, 10000)
        Instruction(
            program_id=Pubkey.from_string("ComputeBudget111111111111111111111111111111"),
            accounts=[],
            data=bytes([3]) + (data).to_bytes(8, "little"),
        )

        ixs = []

        # --- инструкция перевода ---
        ixs.append(
            transfer_checked(
                TransferCheckedParams(
                    program_id=token.program,
                    source=sender_ata,
                    mint=token.mint,
                    dest=recipient_ata,
                    owner=self.client.account.pubkey(),
                    amount=amount.Wei,
                    decimals=amount.decimals,
                    signers=[],
                )
            )
        )

        if return_ix:
            return ixs

        tx = await self.client.tx.prepare_tx(instructions=ixs)

        return await self.send_tx(message=tx)

        transfer_tx = transfer(TransferParams(from_pubkey=self.client.account.pubkey(), to_pubkey=to_address, lamports=amount.Wei))

        if return_ix:
            return transfer_tx

        tx = await self.client.tx.prepare_tx(instructions=transfer_tx)

        return await self.send_tx(message=tx)

    async def send_tx(self, message, signers=None):
        if not signers:
            signers = self.client.account

        tx = VersionedTransaction(message=message, keypairs=[signers])
        tx_sig = await self.client.rpc.send_transaction(txn=tx)
        if tx_sig:
            return tx_sig.value
