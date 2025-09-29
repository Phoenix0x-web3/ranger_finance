from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from data.constants import PROJECT_SHORT_NAME
from data.settings import Settings


class Base(DeclarativeBase):
    pass


class Wallet(Base):
    __tablename__ = "wallets"

    id: Mapped[int] = mapped_column(primary_key=True)
    private_key: Mapped[str] = mapped_column(unique=True, index=True)
    address: Mapped[str] = mapped_column(unique=True)
    proxy: Mapped[str] = mapped_column(default=None, nullable=True)
    deposit_address: Mapped[str] = mapped_column(default=None, nullable=True)
    sol_fees_usd: Mapped[float] = mapped_column(default=0.0)
    ranger_fees: Mapped[float] = mapped_column(default=0.0)
    slippage_lost_usd: Mapped[float] = mapped_column(default=0.0)
    summary_fees: Mapped[float] = mapped_column(default=0.0)
    volume_onchain: Mapped[int] = mapped_column(default=0)
    points: Mapped[int] = mapped_column(default=0)
    rank: Mapped[str] = mapped_column(default="")
    volume_portal: Mapped[int] = mapped_column(default=0)
    invite_code: Mapped[str] = mapped_column(default="")
    completed: Mapped[bool] = mapped_column(default=False)

    def __repr__(self):
        if Settings().show_wallet_address_logs:
            return f"[{PROJECT_SHORT_NAME} | {self.id} | {self.address}]"
        return f"[{PROJECT_SHORT_NAME} | {self.id}]"
