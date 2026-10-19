#!/usr/bin/env python3
"""
Unified entry point
Run API server: python run.py server
Run CLI analysis: python run.py cli --pcap data/test.pcap
"""
import sys
import argparse
import uvicorn


def run_server():
    uvicorn.run(
        "src.api.app:app",
        host="0.0.0.0",
        port=8001,
        reload=False,
        log_level="info",
    )


def run_cli(args):
    from src.cli import main
    sys.argv = ["tad"] + args
    sys.exit(main())


def main():
    parser = argparse.ArgumentParser(description="Traffic Anomaly Detector")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Server subcommand
    subparsers.add_parser("server", help="Start web API server")

    # CLI subcommand
    cli_parser = subparsers.add_parser("cli", help="Run CLI analysis")
    cli_parser.add_argument("--pcap", required=True)
    cli_parser.add_argument("--contamination", type=float, default=0.05)
    cli_parser.add_argument("--top", type=int, default=10)

    args, remaining = parser.parse_known_args()

    if args.command == "server":
        run_server()
    elif args.command == "cli":
        run_cli(remaining)


if __name__ == "__main__":
    main()

