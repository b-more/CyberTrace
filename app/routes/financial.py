"""
Financial Investigation Routes
Zambia Police Service CyberTrace OSINT Platform

Financial transaction tracking, import, and analysis operations
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify, current_app
from flask_login import current_user
from app import db
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.audit_log import AuditLog
from app.models.financial_transaction import FinancialTransaction
from app.utils.decorators import login_required, permission_required
from datetime import datetime
import os, tempfile, time

financial_bp = Blueprint('financial', __name__)


def _get_user_cases():
    """Get cases accessible by the current user"""
    if current_user.role in ['admin', 'senior_investigator']:
        cases = Case.query.filter(Case.status.in_(['open', 'investigating'])).order_by(Case.created_at.desc()).all()
    else:
        cases = Case.query.filter(
            ((Case.lead_investigator_id == current_user.id) |
             (Case.assigned_officers.contains([current_user.id]))) &
            (Case.status.in_(['open', 'investigating']))
        ).order_by(Case.created_at.desc()).all()
    return cases


@financial_bp.route('/')
@login_required
def index():
    """Financial investigation dashboard"""
    cases = _get_user_cases()
    return render_template('financial/search.html', cases=cases)


@financial_bp.route('/import', methods=['POST'])
@login_required
def import_transactions():
    """Import financial transactions from CSV/Excel file"""
    case_id = request.form.get('case_id')

    if not case_id:
        flash('Please select a case to link the transactions.', 'danger')
        return redirect(url_for('financial.index'))

    case = Case.query.get(case_id)
    if not case:
        flash('Invalid case selected.', 'danger')
        return redirect(url_for('financial.index'))

    if not current_user.can_access_case(case):
        flash('You do not have permission to access this case.', 'danger')
        return redirect(url_for('financial.index'))

    file = request.files.get('file')
    if not file or not file.filename:
        flash('Please upload a CSV or Excel file.', 'danger')
        return redirect(url_for('financial.index'))

    try:
        from werkzeug.utils import secure_filename

        filename = secure_filename(file.filename)
        upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], str(case_id))
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)

        from app.modules.financial_tracer import FinancialTracer

        start_time = time.time()
        tracer = FinancialTracer()
        results = tracer.import_transactions(file_path)
        execution_time = time.time() - start_time

        # Save individual transaction records
        imported_count = 0
        for tx_data in results.get('transactions', []):
            transaction = FinancialTransaction(
                case_id=case_id,
                transaction_type=tx_data.get('transaction_type', 'other'),
                amount=tx_data.get('amount', 0),
                currency=tx_data.get('currency', 'ZMW'),
                sender_account=tx_data.get('sender_account', ''),
                sender_name=tx_data.get('sender_name'),
                receiver_account=tx_data.get('receiver_account', ''),
                receiver_name=tx_data.get('receiver_name'),
                provider=tx_data.get('provider', 'Unknown'),
                reference_number=tx_data.get('reference_number', f'IMP-{imported_count}'),
                transaction_date=datetime.fromisoformat(tx_data['transaction_date']) if tx_data.get('transaction_date') else datetime.utcnow(),
                is_suspicious=tx_data.get('is_suspicious', False),
                mule_score=tx_data.get('mule_score'),
                notes=tx_data.get('notes'),
                raw_data=tx_data
            )
            db.session.add(transaction)
            imported_count += 1

        db.session.commit()

        # Log the import
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='import_financial_transactions',
            action_category='investigation',
            resource_type='financial_transaction',
            resource_id=str(case_id),
            resource_identifier=case.case_number,
            details={
                'filename': filename,
                'imported_count': imported_count,
                'execution_time': execution_time
            },
            ip_address=request.remote_addr
        )

        flash(f'Successfully imported {imported_count} transactions for case {case.case_number}.', 'success')
        return redirect(url_for('financial.view_result', case_id=case_id))

    except Exception as e:
        db.session.rollback()
        flash(f'Import failed: {str(e)}', 'danger')

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='import_financial_failed',
            action_category='investigation',
            resource_type='financial_transaction',
            details={'error': str(e)},
            status='failure',
            error_message=str(e),
            ip_address=request.remote_addr
        )

        return redirect(url_for('financial.index'))


@financial_bp.route('/result/<case_id>')
@login_required
def view_result(case_id):
    """View financial analysis results for a case"""
    case = Case.query.get_or_404(case_id)

    if not current_user.can_access_case(case):
        flash('You do not have permission to access this case.', 'danger')
        return redirect(url_for('financial.index'))

    transactions = FinancialTransaction.query.filter_by(
        case_id=case_id
    ).order_by(FinancialTransaction.transaction_date.desc()).all()

    # Run analysis on the transactions
    analysis = {}
    try:
        from app.modules.financial_tracer import FinancialTracer
        tracer = FinancialTracer()
        analysis = tracer.analyze_flow([tx.to_dict() for tx in transactions])
    except Exception as e:
        flash(f'Analysis encountered an error: {str(e)}', 'warning')

    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_financial_analysis',
        ip_address=request.remote_addr
    )

    return render_template('financial/result.html',
                         case=case,
                         transactions=transactions,
                         analysis=analysis)


@financial_bp.route('/graph/<case_id>')
@login_required
def view_graph(case_id):
    """View financial transaction flow graph with D3.js"""
    case = Case.query.get_or_404(case_id)

    if not current_user.can_access_case(case):
        flash('You do not have permission to access this case.', 'danger')
        return redirect(url_for('financial.index'))

    transactions = FinancialTransaction.query.filter_by(
        case_id=case_id
    ).order_by(FinancialTransaction.transaction_date.asc()).all()

    # Build D3.js-compatible graph data
    nodes = {}
    links = []

    for tx in transactions:
        if tx.sender_account not in nodes:
            nodes[tx.sender_account] = {
                'id': tx.sender_account,
                'name': tx.sender_name or tx.sender_account,
                'type': 'sender'
            }
        if tx.receiver_account not in nodes:
            nodes[tx.receiver_account] = {
                'id': tx.receiver_account,
                'name': tx.receiver_name or tx.receiver_account,
                'type': 'receiver'
            }
        links.append({
            'source': tx.sender_account,
            'target': tx.receiver_account,
            'amount': tx.amount,
            'currency': tx.currency,
            'date': tx.transaction_date.isoformat() if tx.transaction_date else None,
            'suspicious': tx.is_suspicious
        })

    graph_data = {
        'nodes': list(nodes.values()),
        'links': links
    }

    return render_template('financial/graph.html',
                         case=case,
                         graph_data=graph_data)


@financial_bp.route('/<case_id>/pdf')
@login_required
def pdf_report(case_id):
    """Download PDF report for financial investigation"""
    case = Case.query.get_or_404(case_id)

    if not current_user.can_access_case(case):
        flash('You do not have permission to access this case.', 'danger')
        return redirect(url_for('financial.index'))

    flash('PDF generation coming soon.', 'info')
    return redirect(url_for('financial.view_result', case_id=case_id))
