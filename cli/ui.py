import os
import sys


class Colors:
    RED = "\033[1;31m"
    DARK_RED = "\033[0;31m"
    MUTED = "\033[0;37m"
    CYAN = "\033[1;36m"
    YELLOW = "\033[1;33m"
    GREEN = "\033[1;32m"
    WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    HLINE = "─"
    VLINE = "│"
    TOPL = "┌"
    TOPR = "┐"
    BOTL = "└"
    BOTR = "┘"


if not sys.stdout.isatty():
    for attribute in dir(Colors):
        value = getattr(Colors, attribute)
        if not attribute.startswith("_") and isinstance(value, str):
            setattr(Colors, attribute, "")
    Colors.HLINE = "-"
    Colors.VLINE = "|"
    Colors.TOPL = "+"
    Colors.TOPR = "+"
    Colors.BOTL = "+"
    Colors.BOTR = "+"


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def banner(title: str):
    width = max(60, len(title) + 8)
    inner_width = width - 2
    padding = max(0, inner_width - len(title))
    left_padding = padding // 2
    right_padding = padding - left_padding
    print(f"{Colors.RED}{Colors.TOPL}{Colors.HLINE * inner_width}{Colors.TOPR}")
    print(
        f"{Colors.VLINE}{' ' * left_padding}{Colors.BOLD}{title}{Colors.RESET}"
        f"{Colors.RED}{' ' * right_padding}{Colors.VLINE}"
    )
    print(f"{Colors.BOTL}{Colors.HLINE * inner_width}{Colors.BOTR}{Colors.RESET}")


def render_logo(version: str = ""):
    print(f"""{Colors.RED}
███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║╚════██║
██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████║
██║╚██╗██║██╔══╝  ██║╚██╔╝██║╚════██║██╔══╝  ██║╚════██║
██║ ╚████║███████╗██║ ╚═╝ ██║███████║███████║██║███████║
╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝
{Colors.RESET}""")


def render_menu(
    title: str,
    options,
    hint: str = "",
    clear: bool = True,
    brand: str = "",
):
    if clear:
        clear_screen()
    render_logo()
    if brand:
        print(f"{Colors.RED}{Colors.BOLD}{brand}{Colors.RESET} {Colors.MUTED}│{Colors.RESET}")
    banner(title)
    for key, label, description in options:
        if str(key) == "0":
            key_color = Colors.RED
        else:
            key_color = Colors.CYAN
        print(
            f"  {key_color}{Colors.BOLD}[{key}]{Colors.RESET} "
            f"{Colors.YELLOW}{label}{Colors.RESET}"
            f"{Colors.MUTED} - {description}{Colors.RESET}"
        )
    if hint:
        print(f"{Colors.MUTED}{hint}{Colors.RESET}")


def choose_option(prompt: str, valid_options, default=None):
    valid = {str(option) for option in valid_options}
    choice = input(f"{Colors.CYAN}{prompt}{Colors.RESET}").strip()
    if not choice and default is not None:
        return str(default)
    if choice not in valid:
        print(f"{Colors.RED}Choose one of: {', '.join(sorted(valid))}.{Colors.RESET}")
        return None
    return choice


def confirm(prompt: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{Colors.CYAN}{prompt} {suffix}: {Colors.RESET}").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def pause(message: str = "Press Enter to continue"):
    input(f"\n{Colors.MUTED}{message}...{Colors.RESET}")


def print_error(message: str):
    print(f"{Colors.RED}{message}{Colors.RESET}")


def print_success(message: str):
    print(f"{Colors.GREEN}{message}{Colors.RESET}")
