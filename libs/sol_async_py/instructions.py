from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional

from solders.instruction import AccountMeta, CompiledInstruction, Instruction
from solders.message import Message, MessageV0
from solders.pubkey import Pubkey

if TYPE_CHECKING:
    from .client import Client

COMPUTE_BUDGET = Pubkey.from_string("ComputeBudget111111111111111111111111111111")

@dataclass
class ComputeBudgetInfo:
    limit: int = 0
    price: int = 0
    max_fee_sol: float = 0.0


class Instructions:
    def __init__(self, client: Client):
        self.client = client

    @staticmethod
    def set_compute_unit_limit(units: int) -> Instruction:
        data = bytes([2]) + units.to_bytes(4, "little")
        return Instruction(program_id=COMPUTE_BUDGET, accounts=[], data=data)

    @staticmethod
    def set_compute_unit_price( micro_lamports: int) -> Instruction:
        data = bytes([3]) + micro_lamports.to_bytes(8, "little")
        return Instruction(program_id=COMPUTE_BUDGET, accounts=[], data=data)

    @staticmethod
    def compile_compute_unit_limit(units: int = 209_646, prog_index: int = 1) -> CompiledInstruction:
        data = bytes([2]) + units.to_bytes(4, "little")  # tag=2, u32 units
        return CompiledInstruction(
            program_id_index=prog_index,
            accounts=b"",
            data=data,
        )

    @staticmethod
    def compile_compute_unit_price(micro_lamports: int = 476_994, prog_index: int = 1) -> CompiledInstruction:
        data = bytes([3]) + micro_lamports.to_bytes(8, "little")  # tag=3, u64 price

        return CompiledInstruction(
            program_id_index=prog_index,
            accounts=b"",
            data=data,
        )

    def parse_from_instructions(self, message: Message | MessageV0) -> ComputeBudgetInfo:
        """Разобрать инструкции ComputeBudget и вернуть информацию о лимите, цене и комиссии."""
        limit, price = 0, 0

        for ix in message.instructions:
            parsed = self._parse_compute_budget(ix, message.account_keys)

            if not parsed:
                continue
            if parsed["type"] == "limit":
                limit = parsed["units"]
            elif parsed["type"] == "price":
                price = parsed["micro_lamports"]

        return self.calc_max_fee(limit, price)


    def calc_max_fee(self, limit: int, price: int) -> ComputeBudgetInfo:

        max_fee_sol = 0.0
        if price > 0 and limit > 0:
            fee_lamports = limit * price // 1_000_000
            max_fee_sol = fee_lamports / 1e9

        return ComputeBudgetInfo(limit=limit, price=price, max_fee_sol=max_fee_sol)


    def _parse_compute_budget(self, ix: CompiledInstruction, account_keys: list[Pubkey]) -> Optional[dict]:
        program_id = account_keys[ix.program_id_index]

        if program_id != COMPUTE_BUDGET:
            return None

        data = bytes(ix.data)
        if not data:
            return None

        tag = data[0]
        if tag == 2 and len(data) >= 5:
            units = int.from_bytes(data[1:5], "little")
            return {"type": "limit", "units": units}

        elif tag == 3 and len(data) >= 9:
            micro_lamports = int.from_bytes(data[1:9], "little")
            return {"type": "price", "micro_lamports": micro_lamports}

        return None

    def __parse_compute_budget(self, ix, account_keys):

        prog_id = account_keys[ix.program_id_index]
        if str(prog_id) != "ComputeBudget111111111111111111111111111111":
            return None

        tag = ix.data[0]

        if tag == 2:
            units = int.from_bytes(ix.data[1:5], "little")
            return {"type": "limit", "units": units}

        elif tag == 3:
            micro_lamports = int.from_bytes(ix.data[1:9], "little")
            return {"type": "price", "micro_lamports": micro_lamports}

        return None

    @staticmethod
    async def acount_meta(pubkey, is_signer: bool = False, is_writable: bool = False):

        return AccountMeta(
            pubkey=pubkey, is_signer=is_signer, is_writable=is_writable
        )

    async def prepare_instruction(self,
                                  program_id: str ,
                                  accounts: List[Pubkey, bool, bool],
                                  data: bytes) -> Instruction:

        #accounts = [self.acount_meta(account) for account in accounts]

        instruction = Instruction(
            program_id=Pubkey.from_string(program_id),
            accounts=accounts,
            data=data
        )

        return instruction

    async def make_instruction_data(self, *discriminators: int) -> bytes:
        """
        Аналог Go-функции makeInstructionData(discriminator ...int) []byte.
        Для каждого целого discriminator < 256 записывает его как uint8 (little-endian).
        Возвращает итоговый набор байт.
        """
        buf = bytearray()
        for val in discriminators:
            # Убедимся, что значение укладывается в байт
            if not (0 <= val < 256):
                raise ValueError(f"Значение {val} выходит за границы uint8")
            buf.extend(struct.pack('<B', val))
        return bytes(buf)