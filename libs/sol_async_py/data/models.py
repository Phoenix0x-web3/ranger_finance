from decimal import Decimal

from solders.pubkey import Pubkey

from data.rpc import RPC_MAP


class Programs:
    SYS_PROGRAM = Pubkey.from_string("11111111111111111111111111111111")
    SYS_VAR_INSTRUCTIONS = Pubkey.from_string("Sysvar1nstructions1111111111111111111111111")


class RawContract:
    def __init__(self, title, mint, program):
        self.title = title
        self.mint = Pubkey.from_string(mint)
        self.program = Pubkey.from_string(program)

    def __repr__(self):
        return f"{self.title}"


class TokenAmount:
    Wei: int
    Ether: Decimal
    decimals: int

    def __init__(self, amount: int | float | str | Decimal, decimals: int = 9, wei: bool = False, gwei: bool = False) -> None:
        if wei:
            self.Wei: int = int(amount)
            self.Ether: Decimal = Decimal(str(amount)) / 10**decimals
        else:
            self.Ether: Decimal = Decimal(str(amount))
            self.Wei: int = int(self.Ether * 10**decimals)

        self.decimals = decimals

    def __str__(self):
        return f"{float(self.Ether):.5f}"

    def __repr__(self):
        return str(self)


class Network:
    def __init__(
        self,
        name: str,
        endpoint: str,
        decimals: int,
        explorer: str | None = None,
    ) -> None:
        self.name: str = name.lower()
        self.endpoint: str = endpoint
        self.explorer: str | None = explorer
        self.decimals: int = decimals


class Networks:
    # Mainnets

    Solana = Network(name="solana", endpoint=RPC_MAP["solana"], explorer="https://solscan.io/", decimals=9)

    Eclipse = Network(name="eclipse", endpoint="https://eclipse.helius-rpc.com/", explorer="https://eclipsescan.xyz/", decimals=9)
    # endpoint='https://eclipse.helius-rpc.com/ ',
    # endpoint='https://eclipse.lgns.net/'
    # endpoint='https://mainnetbeta-rpc.eclipse.xyz/'
    # endpoint='https://solarst-eclipse-870b.mainnet.eclipse.rpcpool.com/'
