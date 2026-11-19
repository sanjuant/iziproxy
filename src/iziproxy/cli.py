"""
Commande ``iziproxy`` : remplaçant de cntlm sans réglage à la main.

- ``iziproxy serve`` démarre le proxy local sur 127.0.0.1:3128 avec un jeton
  fixe, gardé dans le répertoire de configuration de l'utilisateur ;
- ``iziproxy setup`` configure une fois pour toutes git, curl et pip pour
  qu'ils passent par ce proxy local (``--undo`` pour revenir en arrière).
"""

import argparse
import sys

from . import __version__
from .local_proxy import DEFAULT_PORT
from .tool_setup import TOOLS, SetupError, apply, has_backup, load_token, plan, token_path, undo


def _port(value):
    port = int(value)
    if not 0 < port < 65536:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _tools(value):
    tools = [t.strip().lower() for t in value.split(",") if t.strip()]
    unknown = sorted(set(tools) - set(TOOLS))
    if not tools or unknown:
        raise argparse.ArgumentTypeError(f"choose among {','.join(TOOLS)}")
    return tuple(dict.fromkeys(tools))


def build_parser():
    """Analyseur des arguments de la commande ``iziproxy``."""
    parser = argparse.ArgumentParser(
        prog="iziproxy",
        description="Local proxy for corporate networks (cntlm replacement).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    serve = commands.add_parser("serve", help="run the local proxy (Ctrl+C to stop)",
                                description="Run the local proxy on 127.0.0.1 with a fixed token.")
    serve.add_argument("--port", type=_port, default=DEFAULT_PORT, help=f"listening port (default: {DEFAULT_PORT})")
    serve.add_argument("--config", help="IziProxy YAML configuration file")
    serve.add_argument("--debug", action="store_true", help="verbose logs")

    setup = commands.add_parser("setup", help="configure git, curl and pip to use the local proxy",
                                description="Write the local proxy address (with its token, never a password) "
                                            "into the user configuration of git, curl and pip.")
    setup.add_argument("--port", type=_port, default=DEFAULT_PORT,
                       help=f"port of 'iziproxy serve' (default: {DEFAULT_PORT})")
    setup.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    setup.add_argument("--only", type=_tools, default=TOOLS, metavar="TOOLS",
                       help=f"comma-separated tools to configure (default: {','.join(TOOLS)})")
    setup.add_argument("--undo", action="store_true", help="restore the settings saved by a previous setup")
    return parser


def _confirm(question):
    """Demande une confirmation ; non par défaut et sans terminal."""
    try:
        answer = input(f"{question} [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes", "o", "oui")


def _serve(args):
    from .proxy_manager import IziProxy

    token = load_token()
    izi = IziProxy(config_path=args.config, debug=args.debug)
    try:
        local = izi.start_local_proxy(port=args.port, token=token)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Local proxy listening on {local.address} (token stored in {token_path()})")
    print("Configure git, curl and pip once with: iziproxy setup" +
          (f" --port {local.port}" if local.port != DEFAULT_PORT else ""))
    print("Press Ctrl+C to stop.", flush=True)
    local.serve_forever()
    return 0


def _setup(args):
    if args.undo:
        if not has_backup():
            print("Nothing to undo: no setup backup found.")
            return 0
        for line in undo(tools=args.only):
            print(line)
        return 0

    changes, skipped = plan(port=args.port, tools=args.only)
    for reason in skipped:
        print(f"Skipped {reason}")
    if not changes:
        print("Nothing to configure.")
        return 1
    print("The following settings will be written (*** = local proxy token):")
    current = None
    for change in changes:
        header = f"{change.tool} ({'global git config' if change.kind == 'git' else change.target})"
        if header != current:
            print(f"\n  {header}")
            current = header
        for line in change.summary:
            print(f"    {line}")
    print("\nPrevious values are saved: 'iziproxy setup --undo' restores them.")
    if not args.yes and not _confirm("Apply?"):
        print("Aborted, nothing written.")
        return 1
    apply(changes)
    print("Done. Start the local proxy with: iziproxy serve"
          + (f" --port {args.port}" if args.port != DEFAULT_PORT else ""))
    return 0


def main(argv=None):
    """Point d'entrée de la commande ``iziproxy``."""
    args = build_parser().parse_args(argv)
    try:
        if args.command == "serve":
            return _serve(args)
        return _setup(args)
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
