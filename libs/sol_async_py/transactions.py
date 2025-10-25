from __future__ import annotations

import asyncio
from time import time
from typing import TYPE_CHECKING

from solana.rpc.types import TxOpts
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction
from solders.transaction_status import TransactionConfirmationStatus
from spl.token.instructions import get_associated_token_address

from .data.models import RawContract

if TYPE_CHECKING:
    from .client import Client


class Transactions:
    def __init__(self, client: Client):
        self.client = client

    async def get_ata(self, token: RawContract) -> Pubkey | None:
        if token.title == "SOL":
            ata = get_associated_token_address(self.client.account.pubkey(), token.mint, token.program)
        else:
            ata = get_associated_token_address(self.client.account.pubkey(), token.mint, token.program)

        resp = await self.client.rpc.get_account_info(ata)

        if resp.value is None:
            return None
        if resp.value.lamports == 0:
            return None
        return ata

    async def prepare_tx(self, instructions: list | None, units: int = None, return_ix=False, signers: list = None):
        if instructions is None:
            instructions = []

        elif not isinstance(instructions, list):
            instructions = [instructions]

        # if units is not None:
        #     instructions = [set_compute_unit_limit(units)] + instructions
        #     print('units', units)

        if isinstance(instructions, list):
            if units is not None:
                instructions = [units, instructions]
        else:
            instructions = [units, instructions]

        instructions = [i for i in instructions if i is not None]
        # print(instructions)
        if return_ix:
            return instructions

        block = await self.client.rpc.get_latest_blockhash()
        block = block.value.blockhash

        message = MessageV0.try_compile(
            instructions=instructions, payer=self.client.account.pubkey(), address_lookup_table_accounts=[], recent_blockhash=block
        )
        # if units is None:
        #     if not signers:
        #             signers = [self.client.account]
        #     tx = VersionedTransaction(message=message, keypairs=signers)
        #
        #     sim = await self.client.rpc.simulate_transaction(txn=tx)
        #     units = getattr(sim.value, "units_consumed", None)
        #
        #     print(sim)
        #     print(units)
        #     return await self.prepare_tx(instructions=instructions, units=int(units))

        return message

    async def wait_tx_confirmation_lite(self, sig: str, timeout: int = 60):
        started = time()

        while True:
            resp = await self.client.rpc.get_signature_statuses([sig], search_transaction_history=True)
            status = resp.value[0]

            if status is not None:
                if status.err is None:
                    if status.confirmation_status == TransactionConfirmationStatus.Confirmed:
                        return status.confirmation_status

                else:
                    raise Exception(status.err)

            if time() - started > timeout:
                raise Exception(f"[TX {sig}] timeout after {timeout} sec")

            await asyncio.sleep(1)

    async def send_tx(self, message, signers=None, skip_simultaion=False):
        if not signers:
            signers = [self.client.account]

        tx = VersionedTransaction(message=message, keypairs=signers)

        if isinstance(message, MessageV0):
            if not skip_simultaion:
                await self.client.rpc.simulate_transaction(
                    txn=tx,
                    sig_verify=True,
                )

            sig = await self.client.rpc.send_transaction(txn=tx)

        else:
            sig = await self.client.rpc.send_transaction(txn=tx, opts=TxOpts(skip_preflight=True))

        wait_for_send = await self.wait_tx_confirmation_lite(sig=sig.value)

        if wait_for_send == TransactionConfirmationStatus.Confirmed:
            return sig.value

        raise Exception(f"TX Status: {wait_for_send}")
