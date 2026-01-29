"""
CyberTrace OSINT Platform
Zambia Police Service

Application entry point for development server
"""

import os
import click
from app import create_app, db
from app.models.user import User
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.evidence import Evidence
from app.models.audit_log import AuditLog

# Create application instance
app = create_app(os.getenv('FLASK_ENV', 'development'))


@app.shell_context_processor
def make_shell_context():
    """
    Make database models available in Flask shell
    Usage: flask shell
    """
    return {
        'db': db,
        'User': User,
        'Case': Case,
        'Investigation': Investigation,
        'Evidence': Evidence,
        'AuditLog': AuditLog
    }


@app.cli.command()
def init_db():
    """Initialize the database"""
    click.echo('Initializing database...')
    db.create_all()
    click.echo('Database tables created successfully!')


@app.cli.command()
def create_admin():
    """Create admin user"""
    from app import create_admin_user

    with app.app_context():
        try:
            create_admin_user()
            click.echo('Admin user created successfully!')
        except Exception as e:
            click.echo(f'Error creating admin user: {str(e)}')


@app.cli.command()
def seed_data():
    """Seed database with test data"""
    click.echo('Seeding database with test data...')

    # Create test users
    users_data = [
        {
            'badge_number': 'ZPS0001',
            'username': 'admin',
            'email': 'admin@zambiapolice.gov.zm',
            'full_name': 'System Administrator',
            'rank': 'Superintendent',
            'department': 'Cybercrime Unit',
            'role': 'admin',
            'password': 'Admin@123'
        },
        {
            'badge_number': 'ZPS0010',
            'username': 'investigator1',
            'email': 'investigator1@zambiapolice.gov.zm',
            'full_name': 'John Mwale',
            'rank': 'Inspector',
            'department': 'Fraud Investigation',
            'role': 'senior_investigator',
            'password': 'Invest@123'
        },
        {
            'badge_number': 'ZPS0020',
            'username': 'investigator2',
            'email': 'investigator2@zambiapolice.gov.zm',
            'full_name': 'Mary Banda',
            'rank': 'Sergeant',
            'department': 'Cybercrime Unit',
            'role': 'investigator',
            'password': 'Invest@123'
        },
        {
            'badge_number': 'ZPS0030',
            'username': 'analyst1',
            'email': 'analyst1@zambiapolice.gov.zm',
            'full_name': 'Peter Phiri',
            'rank': 'Constable',
            'department': 'Intelligence',
            'role': 'analyst',
            'password': 'Analyst@123'
        }
    ]

    for user_data in users_data:
        # Check if user exists
        existing_user = User.query.filter_by(badge_number=user_data['badge_number']).first()
        if not existing_user:
            password = user_data.pop('password')
            user = User(**user_data)
            user.set_password(password)
            db.session.add(user)
            click.echo(f"Created user: {user_data['username']}")

    db.session.commit()
    click.echo('Database seeded successfully!')
    click.echo('\nTest Credentials:')
    click.echo('Admin: ZPS0001 / Admin@123')
    click.echo('Senior Investigator: ZPS0010 / Invest@123')
    click.echo('Investigator: ZPS0020 / Invest@123')
    click.echo('Analyst: ZPS0030 / Analyst@123')


@app.cli.command()
def routes():
    """Display all registered routes"""
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(sorted(rule.methods))
        line = urllib.parse.unquote(f"{rule.endpoint:50s} {methods:20s} {rule}")
        output.append(line)

    for line in sorted(output):
        click.echo(line)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000, debug=True)
