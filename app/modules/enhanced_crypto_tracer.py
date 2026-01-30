"""
Enhanced Crypto Tracer Module
CyberTrace - Zambia Police Service

Cryptocurrency wallet investigation with auto-detection of chain type,
transaction graph building, exchange detection, and risk scoring.
"""

import re
import os
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime

import requests

logger = logging.getLogger('osint')


class CryptoTracer:
    """Cryptocurrency Wallet Investigation Tool"""

    def __init__(self):
        self.results = {
            'address': None,
            'chain': None,
            'chain_detected': False,
            'balance': None,
            'transaction_count': 0,
            'transactions': [],
            'exchange_info': {},
            'transaction_graph': {'nodes': [], 'edges': []},
            'risk_score': 0,
            'risk_factors': [],
            'metadata': {
                'investigated_at': None,
                'investigation_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

        # Known exchange address prefixes (simplified)
        self.known_exchanges = {
            'btc': {
                '1A1zP1': 'Satoshi (Genesis)',
                '3Kzh9q': 'Binance',
                'bc1qm3': 'Coinbase',
                '1NDyJt': 'Binance',
                '3M219K': 'Bitfinex',
                '1Kr6QS': 'Bittrex',
            },
            'eth': {
                '0xBE0eB5': 'Binance',
                '0x3f5CE5': 'Binance',
                '0xD551234': 'Coinbase',
                '0xdAC17F': 'Tether Treasury',
                '0x28C6c0': 'FTX',
                '0x2FAF48': 'Kraken',
            }
        }

    def investigate_wallet(self, address: str, chain: str = 'auto', case_id: str = None) -> Dict:
        """
        Main orchestrator for cryptocurrency wallet investigation.

        Args:
            address: Wallet address to investigate
            chain: Blockchain type ('auto', 'btc', 'eth', 'trx', 'bsc')
            case_id: Optional case ID to link investigation

        Returns:
            Dict with comprehensive wallet investigation results
        """
        self.start_time = time.time()
        address = address.strip()
        self.results['address'] = address
        self.results['metadata']['investigated_at'] = datetime.utcnow().isoformat()

        # Step 1: Auto-detect chain if needed
        if chain == 'auto':
            chain = self._detect_chain(address)
            self.results['chain_detected'] = True

        self.results['chain'] = chain

        # Step 2: Chain-specific investigation
        try:
            if chain == 'btc':
                chain_results = self._investigate_bitcoin(address)
            elif chain == 'eth':
                chain_results = self._investigate_ethereum(address)
            elif chain == 'trx':
                chain_results = self._investigate_tron(address)
            elif chain == 'bsc':
                chain_results = self._investigate_bsc(address)
            else:
                chain_results = {'error': f'Unsupported chain: {chain}'}

            # Merge chain results
            if 'error' not in chain_results:
                self.results['balance'] = chain_results.get('balance')
                self.results['transaction_count'] = chain_results.get('transaction_count', 0)
                self.results['transactions'] = chain_results.get('transactions', [])
        except Exception as e:
            logger.error(f"Chain investigation failed for {address} on {chain}: {e}")
            self.results['transactions'] = []

        # Step 3: Exchange Detection
        try:
            self.results['exchange_info'] = self._detect_exchange(address)
        except Exception as e:
            logger.error(f"Exchange detection failed for {address}: {e}")
            self.results['exchange_info'] = {'error': str(e)}

        # Step 4: Build Transaction Graph
        try:
            self.results['transaction_graph'] = self._build_transaction_graph(
                self.results['transactions']
            )
        except Exception as e:
            logger.error(f"Transaction graph build failed for {address}: {e}")
            self.results['transaction_graph'] = {'nodes': [], 'edges': []}

        # Step 5: Risk Score Calculation
        try:
            risk_data = self._calculate_risk_score(self.results)
            self.results['risk_score'] = risk_data['score']
            self.results['risk_factors'] = risk_data['factors']
        except Exception as e:
            logger.error(f"Risk score calculation failed for {address}: {e}")

        # Finalize metadata
        self.results['metadata']['investigation_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return self.results

    def _detect_chain(self, address: str) -> str:
        """
        Auto-detect blockchain from address format.

        Args:
            address: Wallet address

        Returns:
            Chain identifier string
        """
        # Bitcoin: starts with 1, 3, or bc1
        if re.match(r'^(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
            return 'btc'
        if re.match(r'^bc1[a-zA-HJ-NP-Z0-9]{25,62}$', address):
            return 'btc'

        # Ethereum: starts with 0x, 42 characters total
        if re.match(r'^0x[0-9a-fA-F]{40}$', address):
            return 'eth'

        # Tron: starts with T
        if re.match(r'^T[a-zA-Z0-9]{33}$', address):
            return 'trx'

        # Default to BTC if unknown
        logger.warning(f"Could not auto-detect chain for address: {address}")
        return 'btc'

    def _investigate_bitcoin(self, address: str) -> Dict:
        """
        Investigate a Bitcoin address using blockchain.info API.

        Args:
            address: Bitcoin address

        Returns:
            Dict with balance, transaction count, and transactions
        """
        result = {
            'balance': 0,
            'transaction_count': 0,
            'transactions': [],
            'total_received': 0,
            'total_sent': 0,
            'error': None
        }

        try:
            url = f"https://blockchain.info/rawaddr/{address}?limit=50"
            headers = {'User-Agent': 'CyberTrace-ZambiaPolice'}
            response = requests.get(url, headers=headers, timeout=15)
            self.api_calls += 1

            if response.status_code == 200:
                data = response.json()

                # Balance is in satoshis, convert to BTC
                result['balance'] = data.get('final_balance', 0) / 1e8
                result['transaction_count'] = data.get('n_tx', 0)
                result['total_received'] = data.get('total_received', 0) / 1e8
                result['total_sent'] = data.get('total_sent', 0) / 1e8

                for tx in data.get('txs', []):
                    tx_entry = {
                        'hash': tx.get('hash', ''),
                        'time': datetime.fromtimestamp(tx.get('time', 0)).isoformat() if tx.get('time') else None,
                        'block_height': tx.get('block_height'),
                        'inputs': [],
                        'outputs': [],
                        'fee': tx.get('fee', 0) / 1e8 if tx.get('fee') else 0,
                        'size': tx.get('size', 0)
                    }

                    for inp in tx.get('inputs', []):
                        prev_out = inp.get('prev_out', {})
                        tx_entry['inputs'].append({
                            'address': prev_out.get('addr', 'Unknown'),
                            'value': prev_out.get('value', 0) / 1e8
                        })

                    for out in tx.get('out', []):
                        tx_entry['outputs'].append({
                            'address': out.get('addr', 'Unknown'),
                            'value': out.get('value', 0) / 1e8
                        })

                    result['transactions'].append(tx_entry)

            elif response.status_code == 429:
                result['error'] = 'Rate limit exceeded'
            else:
                result['error'] = f'API returned status {response.status_code}'

        except requests.exceptions.RequestException as e:
            result['error'] = f'Request failed: {str(e)}'
            logger.warning(f"Bitcoin API request failed for {address}: {e}")
        except Exception as e:
            result['error'] = f'Investigation failed: {str(e)}'
            logger.error(f"Bitcoin investigation error for {address}: {e}")

        return result

    def _investigate_ethereum(self, address: str) -> Dict:
        """
        Investigate an Ethereum address using Etherscan API.

        Args:
            address: Ethereum address

        Returns:
            Dict with balance, transaction count, and transactions
        """
        result = {
            'balance': 0,
            'transaction_count': 0,
            'transactions': [],
            'error': None
        }

        api_key = os.environ.get('ETHERSCAN_API_KEY', '')

        try:
            # Get balance
            balance_url = (
                f"https://api.etherscan.io/api?module=account&action=balance"
                f"&address={address}&tag=latest&apikey={api_key}"
            )
            response = requests.get(balance_url, timeout=15)
            self.api_calls += 1

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '1':
                    # Balance in Wei, convert to ETH
                    result['balance'] = int(data.get('result', 0)) / 1e18

            # Get transactions
            tx_url = (
                f"https://api.etherscan.io/api?module=account&action=txlist"
                f"&address={address}&startblock=0&endblock=99999999"
                f"&page=1&offset=50&sort=desc&apikey={api_key}"
            )
            response = requests.get(tx_url, timeout=15)
            self.api_calls += 1

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '1' and data.get('result'):
                    txs = data['result']
                    result['transaction_count'] = len(txs)

                    for tx in txs:
                        result['transactions'].append({
                            'hash': tx.get('hash', ''),
                            'time': datetime.fromtimestamp(
                                int(tx.get('timeStamp', 0))
                            ).isoformat() if tx.get('timeStamp') else None,
                            'block_number': tx.get('blockNumber'),
                            'from': tx.get('from', ''),
                            'to': tx.get('to', ''),
                            'value': int(tx.get('value', 0)) / 1e18,
                            'gas': tx.get('gas', ''),
                            'gas_price': tx.get('gasPrice', ''),
                            'is_error': tx.get('isError', '0') == '1',
                            'function_name': tx.get('functionName', '')
                        })
                elif data.get('message') == 'No transactions found':
                    pass  # No transactions, not an error
                else:
                    result['error'] = data.get('message', 'Unknown API error')

        except requests.exceptions.RequestException as e:
            result['error'] = f'Request failed: {str(e)}'
            logger.warning(f"Etherscan API request failed for {address}: {e}")
        except Exception as e:
            result['error'] = f'Investigation failed: {str(e)}'
            logger.error(f"Ethereum investigation error for {address}: {e}")

        return result

    def _investigate_tron(self, address: str) -> Dict:
        """
        Investigate a Tron address (placeholder).

        Args:
            address: Tron address

        Returns:
            Dict with placeholder results
        """
        return {
            'balance': None,
            'transaction_count': 0,
            'transactions': [],
            'error': 'Tron investigation not yet implemented - placeholder'
        }

    def _investigate_bsc(self, address: str) -> Dict:
        """
        Investigate a Binance Smart Chain address (placeholder).

        Args:
            address: BSC address

        Returns:
            Dict with placeholder results
        """
        return {
            'balance': None,
            'transaction_count': 0,
            'transactions': [],
            'error': 'BSC investigation not yet implemented - placeholder'
        }

    def _detect_exchange(self, address: str) -> Dict:
        """
        Check if an address belongs to a known exchange.

        Args:
            address: Wallet address

        Returns:
            Dict with exchange detection results
        """
        exchange_info = {
            'is_exchange': False,
            'exchange_name': None,
            'confidence': 'none'
        }

        chain = self.results.get('chain', 'btc')
        chain_exchanges = self.known_exchanges.get(chain, {})

        for prefix, name in chain_exchanges.items():
            if address.startswith(prefix):
                exchange_info['is_exchange'] = True
                exchange_info['exchange_name'] = name
                exchange_info['confidence'] = 'medium'
                break

        # Also check transaction counterparties
        if not exchange_info['is_exchange']:
            for tx in self.results.get('transactions', []):
                # Check inputs/outputs for BTC
                for inp in tx.get('inputs', []):
                    addr = inp.get('address', '')
                    for prefix, name in chain_exchanges.items():
                        if addr.startswith(prefix):
                            exchange_info['interacted_with_exchange'] = True
                            exchange_info['exchange_interactions'] = exchange_info.get(
                                'exchange_interactions', []
                            )
                            exchange_info['exchange_interactions'].append({
                                'exchange': name,
                                'address': addr,
                                'direction': 'input'
                            })

                # Check from/to for ETH
                for field in ['from', 'to']:
                    addr = tx.get(field, '')
                    for prefix, name in chain_exchanges.items():
                        if addr.startswith(prefix):
                            exchange_info['interacted_with_exchange'] = True
                            exchange_info['exchange_interactions'] = exchange_info.get(
                                'exchange_interactions', []
                            )
                            exchange_info['exchange_interactions'].append({
                                'exchange': name,
                                'address': addr,
                                'direction': field
                            })

        return exchange_info

    def _build_transaction_graph(self, transactions: List[Dict]) -> Dict:
        """
        Build a D3.js-compatible transaction graph from transactions.

        Args:
            transactions: List of transaction dicts

        Returns:
            Dict with nodes and edges for D3.js visualization
        """
        nodes = {}
        edges = []
        target_address = self.results.get('address', '')

        # Ensure target address is a node
        nodes[target_address] = {
            'id': target_address,
            'label': target_address[:12] + '...',
            'type': 'target',
            'group': 0
        }

        for tx in transactions:
            tx_hash = tx.get('hash', '')

            # Handle BTC-style transactions
            if 'inputs' in tx:
                for inp in tx.get('inputs', []):
                    addr = inp.get('address', 'Unknown')
                    if addr not in nodes:
                        nodes[addr] = {
                            'id': addr,
                            'label': addr[:12] + '...',
                            'type': 'address',
                            'group': 1
                        }

                for out in tx.get('outputs', []):
                    addr = out.get('address', 'Unknown')
                    if addr not in nodes:
                        nodes[addr] = {
                            'id': addr,
                            'label': addr[:12] + '...',
                            'type': 'address',
                            'group': 2
                        }

                # Create edges from inputs to outputs
                for inp in tx.get('inputs', []):
                    for out in tx.get('outputs', []):
                        edges.append({
                            'source': inp.get('address', 'Unknown'),
                            'target': out.get('address', 'Unknown'),
                            'value': out.get('value', 0),
                            'tx_hash': tx_hash
                        })

            # Handle ETH-style transactions
            elif 'from' in tx and 'to' in tx:
                from_addr = tx.get('from', 'Unknown')
                to_addr = tx.get('to', 'Unknown')

                if from_addr not in nodes:
                    nodes[from_addr] = {
                        'id': from_addr,
                        'label': from_addr[:12] + '...',
                        'type': 'address',
                        'group': 1
                    }
                if to_addr not in nodes:
                    nodes[to_addr] = {
                        'id': to_addr,
                        'label': to_addr[:12] + '...',
                        'type': 'address',
                        'group': 2
                    }

                edges.append({
                    'source': from_addr,
                    'target': to_addr,
                    'value': tx.get('value', 0),
                    'tx_hash': tx_hash
                })

        return {
            'nodes': list(nodes.values()),
            'edges': edges
        }

    def _calculate_risk_score(self, results: Dict) -> Dict:
        """
        Calculate risk score based on wallet activity patterns.

        Args:
            results: Current investigation results

        Returns:
            Dict with score (0-100) and risk factors
        """
        score = 0
        factors = []

        transactions = results.get('transactions', [])
        balance = results.get('balance', 0)

        # High transaction count with low balance (pass-through)
        if len(transactions) > 20 and (balance or 0) < 0.01:
            score += 25
            factors.append('High transaction count with near-zero balance (pass-through pattern)')

        # Rapid transactions (multiple in short timeframes)
        if len(transactions) >= 2:
            try:
                times = []
                for tx in transactions:
                    t = tx.get('time')
                    if t:
                        times.append(datetime.fromisoformat(t))

                if len(times) >= 2:
                    times.sort()
                    for i in range(1, len(times)):
                        diff = (times[i] - times[i - 1]).total_seconds()
                        if diff < 300:  # Less than 5 minutes apart
                            score += 10
                            factors.append('Rapid successive transactions detected')
                            break
            except (ValueError, TypeError):
                pass

        # Exchange interaction (could indicate cashing out)
        exchange_info = results.get('exchange_info', {})
        if exchange_info.get('interacted_with_exchange'):
            score += 10
            factors.append('Interacted with known exchange addresses')

        # Many unique counterparties (distribution pattern)
        unique_addrs = set()
        for tx in transactions:
            for inp in tx.get('inputs', []):
                unique_addrs.add(inp.get('address', ''))
            for out in tx.get('outputs', []):
                unique_addrs.add(out.get('address', ''))
            if tx.get('from'):
                unique_addrs.add(tx['from'])
            if tx.get('to'):
                unique_addrs.add(tx['to'])

        unique_addrs.discard('')
        unique_addrs.discard('Unknown')

        if len(unique_addrs) > 15:
            score += 15
            factors.append(f'High number of unique counterparties ({len(unique_addrs)})')

        # No transaction history (freshly created for single use)
        if results.get('transaction_count', 0) <= 1 and (balance or 0) > 0:
            score += 15
            factors.append('Single-use wallet pattern (few transactions with balance)')

        # Cap score at 100
        score = min(score, 100)

        return {'score': score, 'factors': factors}


def investigate_wallet(address: str, chain: str = 'auto', case_id: str = None) -> Dict:
    """
    Convenience function to investigate a cryptocurrency wallet.

    Args:
        address: Wallet address to investigate
        chain: Blockchain type ('auto', 'btc', 'eth', 'trx', 'bsc')
        case_id: Optional case ID

    Returns:
        Dict with investigation results
    """
    tracer = CryptoTracer()
    return tracer.investigate_wallet(address, chain, case_id)
