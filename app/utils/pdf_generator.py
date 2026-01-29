"""
PDF Report Generator
CyberTrace - Zambia Police Service

Generate professional court-ready investigation reports
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from datetime import datetime
import os


class InvestigationPDFReport:
    """Generate PDF reports for investigations"""

    def __init__(self, investigation, case, investigator, logo_path=None):
        """
        Initialize PDF report generator

        Args:
            investigation: Investigation model instance
            case: Case model instance
            investigator: User model instance (investigator)
            logo_path: Path to police logo image
        """
        self.investigation = investigation
        self.case = case
        self.investigator = investigator
        self.logo_path = logo_path or 'app/static/img/zp_logo.jpg'
        self.styles = getSampleStyleSheet()
        self.zps_blue = colors.HexColor('#000663')
        self.zps_green = colors.HexColor('#008000')
        
        # Create custom styles
        self._create_custom_styles()

    def _create_custom_styles(self):
        """Create custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=self.zps_blue,
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Heading style
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.zps_blue,
            spaceAfter=10,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        # Confidential style
        self.styles.add(ParagraphStyle(
            name='Confidential',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.red,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Body style
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=6
        ))

    def _add_header(self, elements):
        """Add report header with logo and confidential marking"""
        # Logo and title table
        if os.path.exists(self.logo_path):
            logo = Image(self.logo_path, width=1*inch, height=1*inch)
            
            header_data = [
                [logo, Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>CYBERCRIME INVESTIGATION UNIT', 
                                self.styles['CustomTitle'])]
            ]
            
            header_table = Table(header_data, colWidths=[1.2*inch, 5*inch])
            header_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (0, 0), 'LEFT'),
                ('ALIGN', (1, 0), (1, 0), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(header_table)
        else:
            title = Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>CYBERCRIME INVESTIGATION UNIT', 
                            self.styles['CustomTitle'])
            elements.append(title)

        elements.append(Spacer(1, 0.2*inch))

        # Confidential marking
        confidential = Paragraph('** CONFIDENTIAL - LAW ENFORCEMENT ONLY **', 
                               self.styles['Confidential'])
        elements.append(confidential)
        elements.append(Spacer(1, 0.3*inch))

    def _add_investigation_header(self, elements):
        """Add investigation metadata"""
        results = self.investigation.raw_results

        # Investigation title
        inv_type = self.investigation.investigation_type.replace('_', ' ').title()
        title = Paragraph(f'<b>{inv_type} Investigation Report</b>',
                         self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))

        # Investigation metadata table
        metadata = [
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Investigation Date:', self.investigation.created_at.strftime('%Y-%m-%d %H:%M:%S')],
            ['Investigation ID:', str(self.investigation.id)],
            ['Case Number:', self.case.case_number],
            ['Case Title:', self.case.title],
            ['Investigator:', f'{self.investigator.full_name} ({self.investigator.badge_number})'],
            ['Rank:', self.investigator.rank],
            ['Department:', self.investigator.department],
            ['Target:', self.investigation.target_identifier],
            ['Execution Time:', f'{self.investigation.execution_time:.2f} seconds'],
            ['Status:', self.investigation.status.upper()],
        ]

        meta_table = Table(metadata, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        elements.append(meta_table)
        elements.append(Spacer(1, 0.2*inch))

        # Add summary statistics
        self._add_summary_statistics(elements)
        elements.append(Spacer(1, 0.2*inch))

    def _add_summary_statistics(self, elements):
        """Add quick summary statistics"""
        results = self.investigation.raw_results

        # Calculate statistics
        is_valid = results.get('is_valid', False)
        breaches = results.get('breaches', [])
        valid_breaches = [b for b in breaches if 'error' not in b and b.get('name')]
        social_media = results.get('social_media', [])
        found_social = [s for s in social_media if s.get('found')]
        reputation = results.get('reputation', {})
        risk_score = reputation.get('risk_score', 0)

        elements.append(Paragraph('<b>INVESTIGATION SUMMARY</b>', self.styles['CustomHeading']))

        summary_data = [
            ['Email Valid:', 'YES' if is_valid else 'NO'],
            ['Data Breaches Found:', str(len(valid_breaches))],
            ['Social Media Accounts:', f'{len(found_social)} found / {len(social_media)} checked'],
            ['Risk Score:', f'{risk_score}/100 - {reputation.get("assessment", "UNKNOWN")}'],
            ['Confidence Score:', f'{self.investigation.confidence_score}%'],
        ]

        summary_table = Table(summary_data, colWidths=[2.5*inch, 3.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.zps_blue),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ]))

        elements.append(summary_table)

    def _add_risk_assessment(self, elements):
        """Add risk assessment section"""
        results = self.investigation.raw_results
        reputation = results.get('reputation', {})
        
        if not reputation:
            return

        elements.append(Paragraph('<b>RISK ASSESSMENT</b>', self.styles['CustomHeading']))
        
        risk_score = reputation.get('risk_score', 0)
        assessment = reputation.get('assessment', 'UNKNOWN')
        
        # Determine color based on risk
        if risk_score >= 70:
            risk_color = colors.red
        elif risk_score >= 40:
            risk_color = colors.orange
        else:
            risk_color = colors.green

        risk_data = [
            ['Risk Score:', f'{risk_score}/100'],
            ['Assessment:', assessment],
        ]

        risk_table = Table(risk_data, colWidths=[2*inch, 4*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (1, 1), (1, 1), risk_color),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        elements.append(risk_table)
        elements.append(Spacer(1, 0.1*inch))

        # Risk flags
        flags = reputation.get('flags', [])
        if flags:
            elements.append(Paragraph('Risk Flags:', self.styles['CustomHeading']))
            for flag in flags:
                elements.append(Paragraph(f'  • {flag}', self.styles['CustomBody']))

        # Recommendations
        recommendations = reputation.get('recommendations', [])
        if recommendations:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph('Recommendations:', self.styles['CustomHeading']))
            for rec in recommendations:
                elements.append(Paragraph(f'  • {rec}', self.styles['CustomBody']))

        elements.append(Spacer(1, 0.2*inch))

    def _add_email_validation(self, elements):
        """Add email validation details"""
        results = self.investigation.raw_results
        validation = results.get('validation', {})
        
        if not validation:
            return

        elements.append(Paragraph('<b>EMAIL VALIDATION</b>', self.styles['CustomHeading']))
        
        validation_data = [
            ['Syntax Valid', 'YES' if validation.get('syntax_valid') else 'NO'],
            ['Domain Exists', 'YES' if validation.get('domain_exists') else 'NO'],
            ['MX Records', 'FOUND' if validation.get('mx_records_exist') else 'NOT FOUND'],
            ['Disposable Email', 'YES' if validation.get('disposable') else 'NO'],
            ['Free Provider', 'YES' if validation.get('free_provider') else 'NO'],
        ]

        val_table = Table(validation_data, colWidths=[2.5*inch, 3.5*inch])
        val_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        elements.append(val_table)
        elements.append(Spacer(1, 0.2*inch))

    def _add_data_breaches(self, elements):
        """Add data breach information"""
        results = self.investigation.raw_results
        breaches = results.get('breaches', [])

        # Filter out errors
        valid_breaches = [b for b in breaches if 'error' not in b and b.get('name')]

        elements.append(Paragraph(f'<b>DATA BREACHES ({len(valid_breaches)} FOUND)</b>',
                                self.styles['CustomHeading']))

        if valid_breaches:
            elements.append(Paragraph(
                '<font color="red"><b>WARNING:</b> This email address has been compromised in '
                f'{len(valid_breaches)} data breach(es). '
                'Associated credentials may be available to threat actors.</font>',
                self.styles['CustomBody']
            ))
            elements.append(Spacer(1, 0.1*inch))

            for idx, breach in enumerate(valid_breaches, 1):
                # Breach header with number
                breach_name = breach.get('name', 'Unknown')
                breach_title = breach.get('title', breach_name)
                elements.append(Paragraph(
                    f'<b>Breach #{idx}: {breach_title}</b>',
                    self.styles['CustomHeading']
                ))

                # Breach details table
                breach_info = [
                    ['Breach Name:', breach.get('name', 'N/A')],
                    ['Domain:', breach.get('domain', 'N/A')],
                    ['Breach Date:', breach.get('breach_date', 'N/A')],
                    ['Added to HIBP:', breach.get('added_date', 'N/A')],
                    ['Accounts Affected:', f"{breach.get('pwn_count', 0):,}"],
                    ['Verified:', 'YES' if breach.get('is_verified') else 'NO'],
                    ['Sensitive:', 'YES' if breach.get('is_sensitive') else 'NO'],
                    ['Retired:', 'YES' if breach.get('is_retired') else 'NO'],
                ]

                breach_table = Table(breach_info, colWidths=[1.8*inch, 4.2*inch])
                breach_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))

                elements.append(breach_table)
                elements.append(Spacer(1, 0.1*inch))

                # Compromised data classes
                data_classes = breach.get('data_classes', [])
                if data_classes:
                    elements.append(Paragraph('Compromised Data:', self.styles['CustomHeading']))
                    data_list = ', '.join(data_classes)
                    elements.append(Paragraph(data_list, self.styles['CustomBody']))
                    elements.append(Spacer(1, 0.1*inch))

                # Breach description
                description = breach.get('description', '')
                if description:
                    elements.append(Paragraph('Description:', self.styles['CustomHeading']))
                    # Remove HTML tags from description for PDF
                    import re
                    clean_description = re.sub('<[^<]+?>', '', description)
                    elements.append(Paragraph(clean_description, self.styles['CustomBody']))

                elements.append(Spacer(1, 0.2*inch))
        else:
            elements.append(Paragraph(
                '<font color="green"><b>Good News:</b> No data breaches found for this email address.</font>',
                self.styles['CustomBody']
            ))
            elements.append(Spacer(1, 0.2*inch))

    def _add_domain_info(self, elements):
        """Add domain information"""
        results = self.investigation.raw_results
        domain_info = results.get('domain_info', {})
        
        if not domain_info or domain_info.get('error'):
            return

        elements.append(Paragraph('<b>DOMAIN INFORMATION</b>', self.styles['CustomHeading']))
        
        domain_data = []
        if domain_info.get('domain'):
            domain_data.append(['Domain:', domain_info['domain']])
        if domain_info.get('registrar'):
            domain_data.append(['Registrar:', domain_info['registrar']])
        if domain_info.get('creation_date'):
            domain_data.append(['Created:', domain_info['creation_date'][:10]])
        if domain_info.get('expiration_date'):
            domain_data.append(['Expires:', domain_info['expiration_date'][:10]])
        if domain_info.get('country'):
            domain_data.append(['Country:', domain_info['country']])
        if domain_info.get('name_servers'):
            ns_list = ', '.join(domain_info['name_servers'][:3])  # First 3 nameservers
            domain_data.append(['Name Servers:', ns_list])

        if domain_data:
            domain_table = Table(domain_data, colWidths=[2*inch, 4*inch])
            domain_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            
            elements.append(domain_table)
            elements.append(Spacer(1, 0.2*inch))

    def _add_dns_records(self, elements):
        """Add DNS records"""
        results = self.investigation.raw_results
        dns_records = results.get('dns_records', {})
        
        if not dns_records:
            return

        elements.append(Paragraph('<b>DNS RECORDS</b>', self.styles['CustomHeading']))
        
        # MX Records
        mx_records = dns_records.get('mx', [])
        if mx_records:
            elements.append(Paragraph('MX Records (Mail Servers):', self.styles['CustomHeading']))
            mx_data = [['Priority', 'Mail Server']]
            for mx in mx_records:
                mx_data.append([str(mx.get('priority', '')), mx.get('server', '')])
            
            mx_table = Table(mx_data, colWidths=[1*inch, 5*inch])
            mx_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.zps_blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(mx_table)
            elements.append(Spacer(1, 0.1*inch))

        # SPF Record
        spf = dns_records.get('spf')
        elements.append(Paragraph('SPF Record:', self.styles['CustomHeading']))
        if spf:
            elements.append(Paragraph(f'{spf}', self.styles['CustomBody']))
        else:
            elements.append(Paragraph('<font color="orange">NOT CONFIGURED</font>',
                                    self.styles['CustomBody']))

        # DMARC Record
        dmarc = dns_records.get('dmarc')
        elements.append(Paragraph('DMARC Record:', self.styles['CustomHeading']))
        if dmarc:
            elements.append(Paragraph(f'{dmarc}', self.styles['CustomBody']))
        else:
            elements.append(Paragraph('<font color="orange">NOT CONFIGURED</font>',
                                    self.styles['CustomBody']))

        elements.append(Spacer(1, 0.2*inch))

    def _add_social_media(self, elements):
        """Add social media accounts found"""
        results = self.investigation.raw_results
        social_media = results.get('social_media', [])

        # Count found accounts
        found_accounts = [acc for acc in social_media if acc.get('found')]
        total_checked = len(social_media)

        elements.append(Paragraph(
            f'<b>SOCIAL MEDIA ACCOUNTS ({len(found_accounts)} FOUND / {total_checked} CHECKED)</b>',
            self.styles['CustomHeading']
        ))

        if not social_media:
            elements.append(Paragraph(
                'No social media platforms were checked.',
                self.styles['CustomBody']
            ))
            elements.append(Spacer(1, 0.2*inch))
            return

        # Separate found and not found accounts
        found = [acc for acc in social_media if acc.get('found')]
        not_found = [acc for acc in social_media if not acc.get('found')]

        # Show found accounts first
        if found:
            elements.append(Paragraph('Accounts Found:', self.styles['CustomHeading']))
            found_data = [['Platform', 'Status', 'Confidence', 'URL']]
            for account in found:
                platform = account.get('platform', 'Unknown')
                confidence = account.get('confidence', 'N/A').upper()
                url = account.get('url', 'N/A')
                # Truncate URL if too long
                if len(url) > 50:
                    url = url[:47] + '...'
                found_data.append([platform, 'FOUND', confidence, url])

            found_table = Table(found_data, colWidths=[1.5*inch, 1*inch, 1*inch, 2.5*inch])
            found_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.zps_green),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))

            elements.append(found_table)
            elements.append(Spacer(1, 0.15*inch))

        # Show not found accounts (summary only)
        if not_found:
            not_found_platforms = [acc.get('platform', 'Unknown') for acc in not_found]
            elements.append(Paragraph('Not Found On:', self.styles['CustomHeading']))
            elements.append(Paragraph(
                ', '.join(not_found_platforms),
                self.styles['CustomBody']
            ))

        elements.append(Spacer(1, 0.2*inch))

    def _add_evidence_hash(self, elements):
        """Add evidence integrity hash"""
        elements.append(Paragraph('<b>EVIDENCE INTEGRITY</b>', self.styles['CustomHeading']))
        
        elements.append(Paragraph(
            'Evidence Hash (SHA-256):',
            self.styles['CustomHeading']
        ))
        
        elements.append(Paragraph(
            f'<font name="Courier" size="8">{self.investigation.evidence_hash}</font>',
            self.styles['CustomBody']
        ))
        
        elements.append(Spacer(1, 0.1*inch))
        
        elements.append(Paragraph(
            '<i>This cryptographic hash ensures the integrity of the investigation results. '
            'Any modification to the data will result in a different hash value, '
            'making tampering detectable. This evidence is admissible in legal proceedings.</i>',
            self.styles['CustomBody']
        ))
        
        elements.append(Spacer(1, 0.2*inch))

    def _add_footer(self, elements):
        """Add report footer"""
        elements.append(PageBreak())
        
        footer_text = f'''
        <para align=center>
        <b>ZAMBIA POLICE SERVICE - CYBERCRIME INVESTIGATION UNIT</b><br/>
        <font color="red"><b>CONFIDENTIAL - LAW ENFORCEMENT USE ONLY</b></font><br/>
        <br/>
        This report contains sensitive law enforcement information. Unauthorized disclosure, distribution, 
        or copying of this document is strictly prohibited and may result in criminal prosecution.<br/>
        <br/>
        <b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>
        <b>Generated By:</b> {self.investigator.full_name} ({self.investigator.badge_number})<br/>
        <b>Investigation ID:</b> {self.investigation.id}<br/>
        <b>Case Number:</b> {self.case.case_number}<br/>
        <br/>
        <i>This is an electronically generated report from the CyberTrace OSINT Platform</i>
        </para>
        '''
        
        elements.append(Paragraph(footer_text, self.styles['CustomBody']))

    def generate(self, output_path):
        """
        Generate the PDF report

        Args:
            output_path (str): Path to save the PDF file

        Returns:
            str: Path to generated PDF file
        """
        # Create PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )

        # Build document elements
        elements = []
        
        self._add_header(elements)
        self._add_investigation_header(elements)
        self._add_risk_assessment(elements)
        self._add_email_validation(elements)
        self._add_data_breaches(elements)
        self._add_domain_info(elements)
        self._add_dns_records(elements)
        self._add_social_media(elements)
        self._add_evidence_hash(elements)
        self._add_footer(elements)

        # Build PDF
        doc.build(elements)
        
        return output_path
