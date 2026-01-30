"""
Financial Tracer Module
CyberTrace - Zambia Police Service

Financial transaction analysis for fraud investigation including
transaction import, flow analysis, mule account detection, and
graph-based visualization.
"""

import os
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger('osint')


class FinancialTracer:
    """Financial Transaction Analysis Tool"""

    def __init__(self):
        self.results = {
            'transactions': [],
            'accounts': {},
            'flow_analysis': {},
            'mule_accounts': [],
            'graph_data': {'nodes': [], 'edges': []},
            'statistics': {},
            'metadata': {
                'analyzed_at': None,
                'analysis_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def import_transactions(self, file_path: str, file_type: str = 'csv',
                            case_id: str = None) -> List[Dict]:
        """
        Import and normalize financial transactions from CSV or Excel.

        Args:
            file_path: Path to the transaction file
            file_type: File type ('csv' or 'excel')
            case_id: Optional case ID

        Returns:
            List of normalized transaction dicts
        """
        transactions = []

        try:
            import pandas as pd

            if file_type == 'csv':
                df = pd.read_csv(file_path)
            elif file_type in ('excel', 'xlsx', 'xls'):
                df = pd.read_excel(file_path)
            else:
                logger.error(f"Unsupported file type: {file_type}")
                return []

            # Normalize column names to lowercase
            df.columns = [col.strip().lower().replace(' ', '_') for col in df.columns]

            # Map common column name variations
            column_map = {
                'date': ['date', 'transaction_date', 'txn_date', 'trans_date', 'timestamp'],
                'amount': ['amount', 'value', 'sum', 'total', 'transaction_amount'],
                'sender': ['sender', 'from', 'from_account', 'source', 'sender_account',
                           'originator', 'debit_account'],
                'receiver': ['receiver', 'to', 'to_account', 'destination', 'receiver_account',
                             'beneficiary', 'credit_account'],
                'description': ['description', 'memo', 'reference', 'narration', 'details',
                                'remarks'],
                'type': ['type', 'transaction_type', 'txn_type', 'category'],
                'currency': ['currency', 'ccy'],
                'status': ['status', 'state']
            }

            def find_column(target_names):
                for name in target_names:
                    if name in df.columns:
                        return name
                return None

            mapped = {}
            for standard, variants in column_map.items():
                col = find_column(variants)
                if col:
                    mapped[standard] = col

            for _, row in df.iterrows():
                tx = {
                    'date': str(row.get(mapped.get('date', ''), '')) if mapped.get('date') else None,
                    'amount': float(row.get(mapped.get('amount', ''), 0)) if mapped.get('amount') else 0,
                    'sender': str(row.get(mapped.get('sender', ''), '')) if mapped.get('sender') else None,
                    'receiver': str(row.get(mapped.get('receiver', ''), '')) if mapped.get('receiver') else None,
                    'description': str(row.get(mapped.get('description', ''), '')) if mapped.get('description') else None,
                    'type': str(row.get(mapped.get('type', ''), '')) if mapped.get('type') else None,
                    'currency': str(row.get(mapped.get('currency', ''), 'ZMW')) if mapped.get('currency') else 'ZMW',
                    'status': str(row.get(mapped.get('status', ''), '')) if mapped.get('status') else None,
                    'case_id': case_id
                }
                transactions.append(tx)

            self.results['transactions'] = transactions
            logger.info(f"Imported {len(transactions)} transactions from {file_path}")

        except ImportError:
            logger.error("pandas is required for transaction import")
        except FileNotFoundError:
            logger.error(f"Transaction file not found: {file_path}")
        except Exception as e:
            logger.error(f"Transaction import failed: {e}")

        return transactions

    def analyze_flow(self, transactions: List[Dict], case_id: str = None) -> Dict:
        """
        Analyze financial flow patterns across transactions.

        Args:
            transactions: List of transaction dicts
            case_id: Optional case ID

        Returns:
            Dict with flow analysis results
        """
        self.start_time = time.time()
        self.results['metadata']['analyzed_at'] = datetime.utcnow().isoformat()

        flow = {
            'total_volume': 0,
            'transaction_count': len(transactions),
            'accounts': {},
            'patterns': [],
            'date_range': {'start': None, 'end': None},
            'currency_breakdown': defaultdict(float)
        }

        accounts = defaultdict(lambda: {
            'total_inflow': 0,
            'total_outflow': 0,
            'inflow_count': 0,
            'outflow_count': 0,
            'counterparties_in': set(),
            'counterparties_out': set(),
            'first_seen': None,
            'last_seen': None,
            'transactions': []
        })

        dates = []

        for tx in transactions:
            amount = tx.get('amount', 0)
            sender = tx.get('sender')
            receiver = tx.get('receiver')
            tx_date = tx.get('date')
            currency = tx.get('currency', 'ZMW')

            flow['total_volume'] += abs(amount)
            flow['currency_breakdown'][currency] += abs(amount)

            if tx_date:
                dates.append(tx_date)

            # Update sender account
            if sender:
                accounts[sender]['total_outflow'] += abs(amount)
                accounts[sender]['outflow_count'] += 1
                if receiver:
                    accounts[sender]['counterparties_out'].add(receiver)
                accounts[sender]['transactions'].append(tx)
                if tx_date:
                    if not accounts[sender]['first_seen'] or tx_date < accounts[sender]['first_seen']:
                        accounts[sender]['first_seen'] = tx_date
                    if not accounts[sender]['last_seen'] or tx_date > accounts[sender]['last_seen']:
                        accounts[sender]['last_seen'] = tx_date

            # Update receiver account
            if receiver:
                accounts[receiver]['total_inflow'] += abs(amount)
                accounts[receiver]['inflow_count'] += 1
                if sender:
                    accounts[receiver]['counterparties_in'].add(sender)
                accounts[receiver]['transactions'].append(tx)
                if tx_date:
                    if not accounts[receiver]['first_seen'] or tx_date < accounts[receiver]['first_seen']:
                        accounts[receiver]['first_seen'] = tx_date
                    if not accounts[receiver]['last_seen'] or tx_date > accounts[receiver]['last_seen']:
                        accounts[receiver]['last_seen'] = tx_date

        # Convert sets to lists for JSON serialization
        serializable_accounts = {}
        for acct_id, acct_data in accounts.items():
            serializable_accounts[acct_id] = {
                'total_inflow': acct_data['total_inflow'],
                'total_outflow': acct_data['total_outflow'],
                'net_flow': acct_data['total_inflow'] - acct_data['total_outflow'],
                'inflow_count': acct_data['inflow_count'],
                'outflow_count': acct_data['outflow_count'],
                'counterparties_in': list(acct_data['counterparties_in']),
                'counterparties_out': list(acct_data['counterparties_out']),
                'first_seen': acct_data['first_seen'],
                'last_seen': acct_data['last_seen'],
                'transaction_count': len(acct_data['transactions'])
            }

        flow['accounts'] = serializable_accounts

        if dates:
            dates.sort()
            flow['date_range'] = {'start': dates[0], 'end': dates[-1]}

        flow['currency_breakdown'] = dict(flow['currency_breakdown'])

        # Detect patterns
        try:
            flow['patterns'] = self._detect_flow_patterns(serializable_accounts, transactions)
        except Exception as e:
            logger.error(f"Flow pattern detection failed: {e}")
            flow['patterns'] = []

        self.results['flow_analysis'] = flow
        self.results['accounts'] = serializable_accounts

        # Build graph
        try:
            self.results['graph_data'] = self.build_graph_data(transactions)
        except Exception as e:
            logger.error(f"Graph data build failed: {e}")

        # Detect mules
        try:
            self.results['mule_accounts'] = self.detect_mules(serializable_accounts)
        except Exception as e:
            logger.error(f"Mule detection failed: {e}")

        self.results['metadata']['analysis_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return flow

    def _detect_flow_patterns(self, accounts: Dict, transactions: List[Dict]) -> List[Dict]:
        """Detect suspicious flow patterns in the data."""
        patterns = []

        for acct_id, data in accounts.items():
            # Layering: funds rapidly passed through
            if data['inflow_count'] > 0 and data['outflow_count'] > 0:
                ratio = data['total_outflow'] / max(data['total_inflow'], 0.01)
                if 0.85 <= ratio <= 1.0:
                    patterns.append({
                        'type': 'layering',
                        'account': acct_id,
                        'description': f'Account passes through ~{ratio:.0%} of incoming funds',
                        'severity': 'high'
                    })

            # Structuring: many small transactions just below threshold
            acct_txs = [
                tx for tx in transactions
                if tx.get('sender') == acct_id or tx.get('receiver') == acct_id
            ]
            # Check for amounts clustering near common reporting thresholds
            threshold_amounts = [amt for tx in acct_txs
                                 for amt in [tx.get('amount', 0)]
                                 if 9000 <= amt <= 9999]
            if len(threshold_amounts) >= 3:
                patterns.append({
                    'type': 'structuring',
                    'account': acct_id,
                    'description': f'{len(threshold_amounts)} transactions near reporting threshold',
                    'severity': 'high'
                })

            # Fan-out: one source, many destinations
            if data['outflow_count'] >= 5 and len(data['counterparties_out']) >= 5:
                patterns.append({
                    'type': 'fan_out',
                    'account': acct_id,
                    'description': f'Funds distributed to {len(data["counterparties_out"])} accounts',
                    'severity': 'medium'
                })

            # Fan-in: many sources, one destination
            if data['inflow_count'] >= 5 and len(data['counterparties_in']) >= 5:
                patterns.append({
                    'type': 'fan_in',
                    'account': acct_id,
                    'description': f'Funds collected from {len(data["counterparties_in"])} accounts',
                    'severity': 'medium'
                })

        return patterns

    def detect_mules(self, accounts: Dict) -> List[Dict]:
        """
        Detect potential money mule accounts.

        Flags accounts with:
        - High in/out ratio within short timeframes
        - Rapid pass-through behavior
        - Many sources, few destinations

        Args:
            accounts: Dict of account data from analyze_flow

        Returns:
            List of suspected mule account dicts
        """
        mules = []

        for acct_id, data in accounts.items():
            risk_indicators = []
            risk_score = 0

            # High pass-through ratio
            if data['total_inflow'] > 0 and data['total_outflow'] > 0:
                pass_through_ratio = data['total_outflow'] / data['total_inflow']
                if 0.80 <= pass_through_ratio <= 1.0:
                    risk_indicators.append(
                        f'Pass-through ratio: {pass_through_ratio:.1%}'
                    )
                    risk_score += 30

            # Many sources, few destinations
            sources = len(data.get('counterparties_in', []))
            destinations = len(data.get('counterparties_out', []))
            if sources >= 3 and destinations <= 2:
                risk_indicators.append(
                    f'Many sources ({sources}), few destinations ({destinations})'
                )
                risk_score += 25

            # High transaction velocity
            if data.get('first_seen') and data.get('last_seen'):
                try:
                    first = datetime.fromisoformat(str(data['first_seen']))
                    last = datetime.fromisoformat(str(data['last_seen']))
                    duration_hours = max((last - first).total_seconds() / 3600, 1)
                    tx_count = data.get('transaction_count', 0)
                    velocity = tx_count / duration_hours

                    if velocity > 2:  # More than 2 tx per hour
                        risk_indicators.append(
                            f'High velocity: {velocity:.1f} tx/hour'
                        )
                        risk_score += 20

                    # Active window within 24-48 hours
                    if 0 < duration_hours <= 48 and tx_count >= 5:
                        risk_indicators.append(
                            f'Short activity window: {duration_hours:.0f} hours, {tx_count} transactions'
                        )
                        risk_score += 25
                except (ValueError, TypeError):
                    pass

            if risk_score >= 40:
                mules.append({
                    'account': acct_id,
                    'risk_score': min(risk_score, 100),
                    'indicators': risk_indicators,
                    'total_inflow': data['total_inflow'],
                    'total_outflow': data['total_outflow'],
                    'classification': 'HIGH RISK' if risk_score >= 70 else 'MEDIUM RISK'
                })

        # Sort by risk score descending
        mules.sort(key=lambda x: x['risk_score'], reverse=True)
        return mules

    def build_graph_data(self, transactions: List[Dict]) -> Dict:
        """
        Generate D3.js-compatible graph data from transactions.

        Args:
            transactions: List of transaction dicts

        Returns:
            Dict with nodes and edges for visualization
        """
        nodes = {}
        edges = []
        edge_map = defaultdict(float)

        for tx in transactions:
            sender = tx.get('sender')
            receiver = tx.get('receiver')
            amount = tx.get('amount', 0)

            if sender and sender not in nodes:
                nodes[sender] = {
                    'id': sender,
                    'label': sender,
                    'type': 'account',
                    'group': 0
                }

            if receiver and receiver not in nodes:
                nodes[receiver] = {
                    'id': receiver,
                    'label': receiver,
                    'type': 'account',
                    'group': 1
                }

            if sender and receiver:
                key = f"{sender}|{receiver}"
                edge_map[key] += abs(amount)

        for key, total_amount in edge_map.items():
            source, target = key.split('|')
            edges.append({
                'source': source,
                'target': target,
                'value': total_amount,
                'label': f'{total_amount:,.2f}'
            })

        return {
            'nodes': list(nodes.values()),
            'edges': edges
        }

    def calculate_account_risk(self, account: Dict) -> int:
        """
        Calculate risk score (0-100) for a specific account.

        Args:
            account: Account data dict

        Returns:
            Integer risk score 0-100
        """
        score = 0

        # Pass-through behavior
        inflow = account.get('total_inflow', 0)
        outflow = account.get('total_outflow', 0)
        if inflow > 0 and outflow > 0:
            ratio = outflow / inflow
            if ratio >= 0.9:
                score += 30
            elif ratio >= 0.7:
                score += 15

        # Transaction volume
        tx_count = account.get('transaction_count', 0)
        if tx_count > 20:
            score += 20
        elif tx_count > 10:
            score += 10

        # Counterparty asymmetry
        sources = len(account.get('counterparties_in', []))
        dests = len(account.get('counterparties_out', []))
        if sources >= 5 and dests <= 2:
            score += 25
        elif dests >= 5 and sources <= 2:
            score += 20

        # Net flow near zero
        net = account.get('net_flow', 0)
        if inflow > 0 and abs(net) / inflow < 0.1:
            score += 15

        return min(score, 100)


def analyze_transactions(file_path: str, file_type: str = 'csv',
                         case_id: str = None) -> Dict:
    """
    Convenience function to import and analyze financial transactions.

    Args:
        file_path: Path to the transaction file
        file_type: File type ('csv' or 'excel')
        case_id: Optional case ID

    Returns:
        Dict with complete analysis results
    """
    tracer = FinancialTracer()
    transactions = tracer.import_transactions(file_path, file_type, case_id)
    if transactions:
        tracer.analyze_flow(transactions, case_id)
    return tracer.results
