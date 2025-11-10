import asyncio
import random
from decimal import Decimal
from time import time

from loguru import logger

from data.models import okx_credentials
from data.settings import Settings
from functions.cex_withdrawal import okx_withdraw, OKXActions
from libs.base_sol import TokenContracts
from libs.sol_async_py.client import Client
from libs.sol_async_py.data.models import TokenAmount
from libs.sol_async_py.utils.utils import randfloat
from modules.ranger import RangerFinance, TOKENS_MAP
from utils.db_api.models import Wallet
from utils.db_api.wallet_api import db
from utils.logs_decorator import controller_log


class Controller:
    def __init__(self, client: Client, wallet: Wallet):
        self.client = client
        self.wallet = wallet
        self.ranger = RangerFinance(client=client, wallet=wallet)

    async def update_db_by_user_info(self):
        rank = await self.ranger.get_leaderboard_rank()

        if rank:
            self.wallet.rank = rank.get('position')
            self.wallet.volume_portal = int(rank.get('total_volume'))
            self.wallet.points = int(rank.get('total_points'))

            self.wallet.point_cost = round(self.wallet.summary_fees / self.wallet.points, 3) if self.wallet.points else 0
            db.commit()

        logger.info(f"{self.wallet} -> "
                    f"Rank: [{self.wallet.rank}] | "
                    f"Volume: [{self.wallet.volume_portal:.2f}] | "
                    f"Points: [{self.wallet.points:.2f}] ")
        return

    @controller_log('OKX Withdrawal')
    async def withdrawal_from_okx(self):
        settings = Settings()

        amount = randfloat(from_=settings.withdrawal_amount_min,
                           to_=settings.withdrawal_amount_max,
                           step=0.001)

        okx = OKXActions(credentials=okx_credentials)

        chain = 'Solana'
        token_symbol = 'SOL'

        res = await okx.withdraw(
            to_address=str(self.wallet.address),
            amount=amount,
            token_symbol=token_symbol,
            chain=chain
        )

        if 'Failed' not in res:
            logger.success(f'{self.wallet} | OKX Withdrawal | {res} successfully')

            await asyncio.sleep(10)

            timeout = 360

            started = time()

            balance = await self.client.wallet.balance()

            while float(balance.Ether) < (amount - 0.003):

                sleep = random.randint(35, 60)
                logger.warning(f"{self.wallet} | OKX | awaiting balance, retry in {sleep} sec..")
                await asyncio.sleep(sleep)
                balance = await self.client.wallet.balance()

            if time() - started > timeout:
                raise Exception(f"Something went wrong in Withdrawal, no sol balance received")

            return f"Success withdraw {amount:.3f} {token_symbol} | balance {balance}"

        raise Exception(f"Error | {res}")

    @controller_log('Refill Solana from Tokens')
    async def refill_sol_balance(self):
        settings = Settings()
        tokens = [TokenContracts.USDC, TokenContracts.USDT]

        token_balances = await self.ranger.balance_map(token_map=tokens)

        refill_amount = random.randint(settings.refill_usd_amount_min, settings.refill_usd_amount_max)

        candidates = {}

        for token, balance in token_balances.items():
            if float(balance.Ether) >= refill_amount:
                candidates[token] = balance

        if candidates:
            from_token = random.choice(list(candidates.keys()))

            return await self.ranger.swap_from_quote(
                from_token=from_token,
                to_token=TokenContracts.SOL,
                amount=TokenAmount(amount=refill_amount, decimals=6)
            )

        raise Exception(f"Cannot refill SOL, balances in tokens lower that {refill_amount} -- {token_balances}")

    @controller_log(f'Initial Swap')
    async def make_first_swap(self, for_comissions):

        balance = await self.client.wallet.balance()

        if float(balance.Ether) <= for_comissions:
            raise Exception(f"Low balance for init: {balance} sol < {for_comissions} sol")

        amount = TokenAmount(
            amount=float(balance.Ether) - for_comissions
        )

        logger.debug(f'{self.wallet} | Ranger Finance | trying to make first swap from {amount} of SOL')

        return await self.ranger.swap_from_quote(
            from_token=TokenContracts.SOL,
            to_token=random.choice([TokenContracts.USDC, TokenContracts.USDT]),
            amount=amount
        )

    async def perform_withdraw_and_swap_to_stables(self):
        settings = Settings()

        withdraw = await self.withdrawal_from_okx()
        logger.success(withdraw)

        min_sol_for_comission = randfloat(
            from_=settings.sol_balance_for_commissions_min,
            to_=settings.sol_balance_for_commissions_max,
            step=0.001
        )

        initial_swap = await self.make_first_swap(for_comissions=min_sol_for_comission)

        return initial_swap

    async def swap_to_stables(self):
        settings = Settings()
        min_sol_for_comission = randfloat(
            from_=settings.sol_balance_for_commissions_min,
            to_=settings.sol_balance_for_commissions_max,
            step=0.001
        )
        return await self.make_first_swap(for_comissions=min_sol_for_comission)

    async def deposit_controller(self):
        if not self.wallet.deposit_address:
            raise Exception(f"No deposit address provided, skipping deposit")

        balances = await self.ranger.balance_map(token_map=TOKENS_MAP)

        for tok, balance in balances.items():
            if tok != TokenContracts.SOL:
                if float(balance.Ether) > 0:
                    swap_back = await self.ranger.swap_from_quote(
                        from_token=tok, to_token=TokenContracts.SOL, amount=balances[tok]
                    )
                    sleep = random.randint(10, 15)
                    logger.success(f"{swap_back} | sleeping {sleep} seconds for next tx")
                    await asyncio.sleep(sleep)

        sol_balance = await self.client.wallet.balance()

        amount = TokenAmount(
            amount=sol_balance.Ether - Decimal(randfloat(from_=0.001, to_=0.002, step=0.0001)), decimals=sol_balance.decimals)
        try:
            deposit = await self.client.wallet.transfer_native(
                to_address=self.wallet.deposit_address,
                amount=amount
            )

            logger.success(f"{self.wallet} | Deposit Controller | Sol Transfered | https://solscan.io/tx/{deposit}")
            await asyncio.sleep(random.randint(10, 15))

            balances = await self.ranger.balance_map(token_map=TOKENS_MAP)
            usd_balances = await self.ranger.usd_balance_map(balances=balances)

            return f"Deposit to {self.wallet.deposit_address} finished | Current USD Balances: {usd_balances}"

        except Exception as e:
            raise Exception(f"Deposit Controller | Error: {e}")


        #todo transfer to deposit address

    async def build_actions(self):
        settings = Settings()

        swaps_count = random.randint(settings.swaps_count_min, settings.swaps_count_max)

        balance = await self.client.wallet.balance()

        initial = False
        if float(balance.Ether) == 0.0:

            withdraw = await self.withdrawal_from_okx()
            initial = True
            logger.success(withdraw)

        final_actions = []

        tokens = [TokenContracts.USDC, TokenContracts.USDT]
        balance_map = await self.ranger.balance_map(token_map=tokens)

        any_token_balances = [t for t in list(balance_map.values()) if float(t.Ether) > 10]

        if not any_token_balances:
            min_sol_for_comission = randfloat(
                from_=settings.sol_balance_for_commissions_min,
                to_=settings.sol_balance_for_commissions_max,
                step=0.001
            )

            initial_swap = await self.make_first_swap(for_comissions=min_sol_for_comission)
            logger.success(initial_swap)

        ref_status = await self.ranger.get_refferal_status()

        if not ref_status:
            final_actions.append(lambda: self.ranger.apply_referral())

        if float(balance.Ether) <= settings.sol_balance_for_commissions_min and not initial:

            refill_sol_balance = await self.refill_sol_balance()
            logger.success(refill_sol_balance)

        if float(balance.Ether) >= 0:
            final_actions += [lambda: self.ranger.swap_controller() for _ in range(swaps_count)]

        return final_actions