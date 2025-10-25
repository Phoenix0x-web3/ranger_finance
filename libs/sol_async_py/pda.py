from __future__ import annotations

from typing import TYPE_CHECKING, List, Tuple

from solders.pubkey import Pubkey

if TYPE_CHECKING:
    from .client import Client


class PDA:
    def __init__(self, client: Client):
        self.client = client

    async def find_program_address(self, seeds: List[bytes], program_id: str) -> Tuple[Pubkey, int]:
        """
        Аналог Go-функции FindProgramAddress, перебирающей nonce от 255 до 0,
        пока не удастся создать программно-производный адрес (PDA).
        Возвращает (pda, nonce), либо бросает ValueError, если PDA найти не удалось.
        """
        nonce = 0xFF  # начинаем с 255
        bytes_seeds = []
        for seed in seeds:
            if isinstance(seed, str):
                s = seed.encode()
            else:
                s = bytes(seed)
            bytes_seeds.append(s)

        program_id = Pubkey.from_string(program_id)

        while True:
            # Формируем полный список сидов: исходные + байт с nonce
            all_seeds = bytes_seeds + [bytes([nonce])]
            try:
                # Пытаемся создать PDA
                pda = Pubkey.create_program_address(all_seeds, program_id)
                return pda

            except Exception:
                # create_program_address бросит ошибку, если nonce не подходит
                pass

            if nonce == 0:
                break
            nonce -= 1

        raise ValueError("unable to find a viable program address")
