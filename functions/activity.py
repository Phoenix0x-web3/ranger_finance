import asyncio
import random
from datetime import datetime, timedelta
from typing import List

from loguru import logger

from data.settings import Settings
from functions.controller import Controller
from libs.sol_async_py.client import Client
from libs.sol_async_py.data.models import Networks
from utils.db_api.models import Wallet
from utils.db_api.wallet_api import db
from utils.encryption import check_encrypt_param


async def random_sleep_before_start(wallet):
    random_sleep = random.randint(Settings().random_pause_start_wallet_min, Settings().random_pause_start_wallet_max)
    now = datetime.now()

    logger.info(f"{wallet} Start at {now + timedelta(seconds=random_sleep)} sleep {random_sleep} seconds before start actions")
    await asyncio.sleep(random_sleep)


async def swap_sol_to_stable(wallet):
    try:
        await random_sleep_before_start(wallet=wallet)

        client = Client(private_key=wallet.private_key, network=Networks.Solana, proxy=wallet.proxy)
        controller = Controller(client=client, wallet=wallet)

        stats = await controller.swap_to_stables()
        logger.success(stats)

    except Exception as e:
        logger.error(f"Core | Activity | {wallet} | {e}")
        raise e


async def withdraw_and_swap(wallet):
    try:
        await random_sleep_before_start(wallet=wallet)

        client = Client(private_key=wallet.private_key, network=Networks.Solana, proxy=wallet.proxy)
        controller = Controller(client=client, wallet=wallet)

        stats = await controller.perform_withdraw_and_swap_to_stables()
        logger.success(stats)

    except Exception as e:
        logger.error(f"Core | Withdraw and Swap | {wallet} | {e}")
        raise e


async def update_statistics(wallet):
    try:
        await random_sleep_before_start(wallet=wallet)

        client = Client(private_key=wallet.private_key, network=Networks.Solana, proxy=wallet.proxy)
        controller = Controller(client=client, wallet=wallet)

        await controller.update_db_by_user_info()

    except Exception as e:
        logger.error(f"Core | Activity | {wallet} | {e}")
        raise e


async def swaps_activity_task(wallet):
    try:
        await random_sleep_before_start(wallet=wallet)

        client = Client(private_key=wallet.private_key, network=Networks.Solana, proxy=wallet.proxy)
        controller = Controller(client=client, wallet=wallet)

        actions = await controller.build_actions()

        if isinstance(actions, str):
            logger.warning(actions)

        else:
            logger.info(f"{wallet} | Started Activity Tasks | Wallet will do {len(actions)} actions")

            for action in actions:
                sleep = random.randint(Settings().random_pause_between_actions_min, Settings().random_pause_between_actions_max)
                try:
                    status = await action()

                    if "Failed" not in status:
                        logger.success(status)
                    else:
                        logger.error(status)

                except Exception as e:
                    logger.error(e)
                    continue

                finally:
                    logger.info(f"{wallet} | Started sleep {sleep} sec for next action....")
                    await asyncio.sleep(sleep)

        await controller.update_db_by_user_info()

    except asyncio.CancelledError:
        raise

    except Exception as e:
        logger.exception(f"Core | Activity | {wallet} | {e}")
        raise e


async def execute(wallets: List[Wallet], task_func, random_pause_wallet_after_completion: int = 0):
    while True:
        semaphore = asyncio.Semaphore(min(len(wallets), Settings().threads))

        if Settings().shuffle_wallets:
            random.shuffle(wallets)

        async def sem_task(wallet: Wallet):
            async with semaphore:
                try:
                    await task_func(wallet)
                except Exception as e:
                    logger.error(f"[{wallet.id}] failed: {e}")

        tasks = [asyncio.create_task(sem_task(wallet)) for wallet in wallets]
        await asyncio.gather(*tasks, return_exceptions=True)

        if random_pause_wallet_after_completion == 0:
            break

        # update dynamically the pause time
        random_pause_wallet_after_completion = random.randint(
            Settings().random_pause_wallet_after_completion_min, Settings().random_pause_wallet_after_completion_max
        )

        next_run = datetime.now() + timedelta(seconds=random_pause_wallet_after_completion)
        logger.info(f"Sleeping {random_pause_wallet_after_completion} seconds. Next run at: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
        await asyncio.sleep(random_pause_wallet_after_completion)


async def activity(action: int):
    if not check_encrypt_param():
        logger.error(f"Decryption Failed | Wrong Password")
        return

    wallets = db.all(Wallet)

    range_wallets = Settings().range_wallets_to_run
    if range_wallets != [0, 0]:
        start, end = range_wallets
        wallets = [wallet for i, wallet in enumerate(wallets, start=1) if start <= i <= end]
    else:
        if Settings().exact_wallets_to_run:
            wallets = [wallet for i, wallet in enumerate(wallets, start=1) if i in Settings().exact_wallets_to_run]

    if action == 1:
        await execute(
            wallets,
            swaps_activity_task,
            random.randint(Settings().random_pause_wallet_after_completion_min, Settings().random_pause_wallet_after_completion_max),
        )

    if action == 2:
        await execute(
            wallets,
            withdraw_and_swap,
        )
    if action == 3:
        await execute(
            wallets,
            swap_sol_to_stable,
        )
    if action == 4:
        await execute(
            wallets,
            update_statistics,
        )


async def parse_stats():
    sum_volume = 0
    sum_points = 0
    sum_fee = 0

    wallets: List[Wallet] = db.all(Wallet)
    for w in wallets:
        sum_volume = +w.volume_portal
        sum_points = +w.points
        sum_fee = +w.summary_fees

        point_cost = w.summary_fees / w.points if w.points else 0
        logger.info(f"{w} | [Point Cost: {point_cost:.4f} $] | [Burned: {w.summary_fees:.2f} $, Points: {w.points:.2f}]")

    point_cost = sum_fee / sum_points
    logger.success(
        f"Summary on Farm | [Point Cost: {point_cost:.4f} $  | [Burned: {sum_fee:.2f} $, Points: {sum_points:.2f}] | Total Volume {sum_volume:.2f}"
    )
