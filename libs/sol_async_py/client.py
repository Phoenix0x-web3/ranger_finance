import re

import solana
import solders
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ed25519
from solana.rpc import async_api
from solders.keypair import Keypair

from libs.sol_async_py.data.models import Network
from libs.sol_async_py.instructions import Instructions
from libs.sol_async_py.pda import PDA
from libs.sol_async_py.transactions import Transactions
from libs.sol_async_py.wallet import Wallet
from utils.encryption import get_private_key


class Client:
    def __init__(self, private_key, network, proxy=None) -> None:
        self.private_key = private_key
        self.proxy = proxy
        self.network: Network = network
        self.rpc = async_api.AsyncClient(endpoint=self.network.endpoint, proxy=self.proxy)

        self.solders = solders
        self.solana_py = solana
        self.account = None
        self.pda = PDA(self)
        self.tx = Transactions(self)
        self.instruct = Instructions(self)
        self.wallet = Wallet(self)

        if isinstance(private_key, str) and re.match("\\[.+]", private_key):
            self.account = self.parse_private_key_bytes(private_key)

        elif isinstance(private_key, str):
            if "gAAA" in private_key:
                private_key = get_private_key(private_key)
            self.account = Keypair.from_base58_string(private_key)

        elif isinstance(private_key, bytes):
            self.account = Keypair.from_bytes(private_key)

        else:
            self.account = Keypair()

    def parse_private_key_bytes(self, key_str: str) -> Keypair:
        raw_string = key_str.strip("[] \t\n")
        number_strings = raw_string.split(",")
        byte_array = []
        for num_str in number_strings:
            num = int(num_str.strip())
            byte_array.append(num)
        seed = bytes(byte_array)

        return self.keypair_from_bytes(seed)

    def keypair_from_bytes(self, key_64: bytes) -> Keypair:
        """
        Аналог Go-функции:

        func AccountFromBytes(key []byte) (Account, error) {
            if len(key) != ed25519.PrivateKeySize {
                ... ошибка ...
            }
            priKey := ed25519.PrivateKey(key)
            return Account{
                PublicKey:  common.PublicKeyFromBytes(priKey.Public().(ed25519.PublicKey)),
                PrivateKey: priKey,
            }, nil
        }

        В Go `ed25519.PrivateKeySize` = 64 (32 байта приватного + 32 байта публичного),
        хотя возможен вариант, когда приватный ключ = 64 байта, а публичный формируется.
        """

        # Проверяем длину: ожидается 64 байта (Ed25519 private key в "expanded" виде)
        if len(key_64) != 64:
            raise ValueError(f"Ожидается 64 байта (Solana expanded key), а получили {len(key_64)}.")

        # 1) Считаем, что первые 32 - приватное "seed"
        seed_32 = key_64[:32]
        # (Оставшиеся 32 — публичный ключ, вычисленный в Go заранее)
        embedded_pubkey = key_64[32:]  # на всякий случай можем проверить совпадение

        # 2) Создаём Ed25519PrivateKey
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(seed_32)

        # 3) Вычисляем публичный ключ из этой либы
        public_key_obj = private_key_obj.public_key()
        public_key_bytes = public_key_obj.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

        # 4) (Необязательно) Проверяем, совпадает ли вычисленный public_key с зашитым
        #    во второй половине 64-байтового массива:
        if public_key_bytes != embedded_pubkey:
            # Если хочется строго, можно кидать исключение или просто предупредить
            print("Warning: публичный ключ из seed не совпадает с key[32:].")

        # 5) Возвращаем Account, где в `private_key` храним все 64 байта (Solana-формат).
        return Keypair.from_bytes(key_64)
