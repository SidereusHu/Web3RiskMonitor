# Web3 Risk Monitor

A blockchain risk monitoring and analysis system focused on Ethereum on-chain data.

## Features

- **Block & Transaction Fetching**: Real-time and batch data collection from Ethereum
- **Transaction Parsing**: Method ID decoding, ABI parameter parsing, event log analysis
- **Risk Assessment**: Automated risk scoring based on signatures and address databases
- **Storage**: SQLite-based storage with extensible architecture

## Project Structure

```
Web3RiskMonitor/
├── src/
│   ├── models/          # Data models (Block, Transaction, etc.)
│   ├── parser/          # Transaction parser & signature database
│   ├── fetcher/         # Block fetcher (single/batch/realtime)
│   ├── storage/         # SQLite storage module
│   └── *.py             # Exploration & demo scripts
├── config/              # Configuration management
├── data/                # Local database (gitignored)
└── requirements.txt
```

## Quick Start

```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure RPC (get free key from https://www.alchemy.com/)
cp .env.example .env
# Edit .env with your ETH_RPC_URL

# Run
python src/explore_ethereum_basics.py      # Explore Ethereum basics
python src/explore_transaction_parsing.py  # Transaction parsing demo
python src/run_collector.py --blocks 5     # Collect recent blocks
python src/verify_system.py                # Verify all modules
```

## Risk Detection Capabilities

- **Sanctioned Address Detection**: OFAC sanctioned addresses (Tornado Cash, etc.)
- **High-Risk Method Identification**: Mixer deposits, unlimited approvals
- **Large Transfer Monitoring**: Configurable threshold alerts
- **New Account Activity**: First transaction risk signals

## Tech Stack

- Python 3.9+
- Web3.py for Ethereum interaction
- Pydantic for data modeling
- SQLite for storage (PostgreSQL ready)
- Rich for CLI visualization

## Roadmap

- [x] Phase 1: On-chain data collection & parsing
- [ ] Phase 2: Address profiling & behavior analysis
- [ ] Phase 3: Risk rule engine
- [ ] Phase 4: Smart contract risk identification
- [ ] Phase 5: Dashboard & visualization

## License

MIT
