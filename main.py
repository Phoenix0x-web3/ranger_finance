import asyncio
import platform

import inquirer
from colorama import Fore
from inquirer import themes
from rich.console import Console

from data.constants import PROJECT_NAME
from functions.activity import activity
from utils.create_files import create_files, reset_folder
from utils.db_import_export_sync import Export, Import, Sync
from utils.git_version import check_for_updates
from utils.output import show_channel_info

console = Console()


PROJECT_ACTIONS = [
    "Start Testing Project",
    "Start Testing Requests",
    "Start Testing Web3",
    "Start Testing Twitter",
    "Back",
]

UTILS_ACTIONS = ["1. Reset files Folder", "Back"]


async def choose_action():
    cat_question = [
        inquirer.List(
            "category",
            message=Fore.LIGHTBLACK_EX + "Choose action",
            choices=["DB Actions", PROJECT_NAME, "Utils", "Exit"],
        )
    ]

    answers = inquirer.prompt(cat_question, theme=themes.Default())
    category = answers.get("category")

    if category == "Exit":
        console.print(f"[bold red]Exiting {PROJECT_NAME}...[/bold red]")
        raise SystemExit(0)

    if category == "DB Actions":
        actions = [
            "Import wallets to Database",
            "Sync wallets with tokens and proxies",
            "Export wallets to TXT",
            "Back",
        ]

    if category == PROJECT_NAME:
        actions = PROJECT_ACTIONS

    if category == "Utils":
        actions = UTILS_ACTIONS

    act_question = [
        inquirer.List(
            "action",
            message=Fore.LIGHTBLACK_EX + f"Choose action in '{category}'",
            choices=actions,
        )
    ]

    act_answer = inquirer.prompt(act_question, theme=themes.Default())
    action = act_answer["action"]

    if action == "Import wallets to Database":
        console.print(f"[bold blue]Starting Import Wallets to DB[/bold blue]")
        await Import.wallets()
    elif action == "Sync wallets with tokens and proxies":
        console.print(f"[bold blue]Starting sync data in DB[/bold blue]")
        await Sync.sync_wallets_with_tokens_and_proxies()
    elif action == "Export wallets to TXT":
        console.print(f"[bold blue]Starting Import Wallets to DB[/bold blue]")
        await Export.wallets_to_txt()

    elif action == "Start Testing Project":
        await activity(action=1)

    elif action == "Start Testing Requests":
        await activity(action=2)

    elif action == "Start Testing Web3":
        await activity(action=3)

    elif action == "Start Testing Twitter":
        await activity(action=4)

    elif action == "1. Reset files Folder":
        console.print("This action will delete the files folder and reset it.")
        answer = input("Are you sure you want to perform this action? y/N ")
        if answer.lower() == "y":
            reset_folder()
            console.print("Files folder success reset")

    elif action == "Exit":
        console.print(f"[bold red]Exiting {PROJECT_NAME}...[/bold red]")
        raise SystemExit(0)

    await choose_action()


async def main():
    create_files()

    await check_for_updates(repo_name=PROJECT_NAME)
    await choose_action()


if __name__ == "__main__":
    show_channel_info(PROJECT_NAME)

    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())
