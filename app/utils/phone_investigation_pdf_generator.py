"""
Phone Investigation PDF Report Generator
CyberTrace - Zambia Police Service

Generate professional court-ready phone investigation reports
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from datetime import datetime
import os


class PhoneInvestigationPDFReport:
    """Generate PDF reports for phone investigations"""

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

        # Subheading style
        self.styles.add(ParagraphStyle(
            name='CustomSubheading',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=self.zps_blue,
            spaceAfter=8,
            spaceBefore=10,
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

        # Small text style
        self.styles.add(ParagraphStyle(
            name='SmallText',
            parent=self.styles['Normal'],
            fontSize=8,
            alignment=TA_LEFT,
            spaceAfter=4
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
        title = Paragraph('<b>Phone Number OSINT Investigation Report</b>',
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
            ['Phone Number:', self.investigation.target_identifier],
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

        # Extract data
        validation = results.get('validation', {})
        is_valid = validation.get('is_valid', False)
        number_type = validation.get('number_type', 'Unknown')
        location = results.get('location', {})
        carrier_info = results.get('carrier', {})
        risk = results.get('risk_assessment', {})
        risk_score = risk.get('risk_score', 0)
        social_media = results.get('social_media', [])
        online_mentions = results.get('online_mentions', {})

        elements.append(Paragraph('<b>INVESTIGATION SUMMARY</b>', self.styles['CustomHeading']))

        summary_data = [
            ['Phone Number Valid:', 'YES' if is_valid else 'NO'],
            ['Number Type:', number_type],
            ['Country:', location.get('country', 'Unknown')],
            ['Carrier:', carrier_info.get('carrier', 'Unknown')],
            ['Social Media Platforms:', f'{len(social_media)} potential account(s)'],
            ['Online Mentions:', f'{online_mentions.get("total_found", 0)} source(s)'],
            ['Risk Score:', f'{risk_score}/100 - {risk.get("assessment", "UNKNOWN")}'],
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

    def _add_phone_validation(self, elements):
        """Add phone validation details"""
        results = self.investigation.raw_results
        validation = results.get('validation', {})

        if not validation:
            return

        elements.append(Paragraph('<b>PHONE NUMBER VALIDATION</b>', self.styles['CustomHeading']))

        validation_data = [
            ['Valid Number', 'YES' if validation.get('is_valid') else 'NO'],
            ['Possible Number', 'YES' if validation.get('is_possible') else 'NO'],
            ['Number Type', validation.get('number_type', 'Unknown')],
            ['Country Code', f'+{validation.get("country_code", "N/A")}'],
            ['National Number', str(validation.get('national_number', 'N/A'))],
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
        elements.append(Spacer(1, 0.1*inch))

        # Number formats
        elements.append(Paragraph('<b>Number Formats</b>', self.styles['CustomSubheading']))
        format_data = [
            ['International Format', validation.get('international_format', 'N/A')],
            ['National Format', validation.get('national_format', 'N/A')],
            ['E.164 Format', validation.get('e164_format', 'N/A')],
        ]

        format_table = Table(format_data, colWidths=[2.5*inch, 3.5*inch])
        format_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(format_table)
        elements.append(Spacer(1, 0.2*inch))

    def _add_carrier_location_info(self, elements):
        """Add carrier and location information"""
        results = self.investigation.raw_results
        carrier_info = results.get('carrier', {})
        location_info = results.get('location', {})

        # Carrier Information
        elements.append(Paragraph('<b>CARRIER INFORMATION</b>', self.styles['CustomHeading']))

        carrier_data = [
            ['Carrier/Provider', carrier_info.get('carrier', 'Unknown')],
            ['Network Type', carrier_info.get('network_type', 'Unknown')],
        ]

        carrier_table = Table(carrier_data, colWidths=[2.5*inch, 3.5*inch])
        carrier_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(carrier_table)
        elements.append(Spacer(1, 0.2*inch))

        # Location Information
        elements.append(Paragraph('<b>LOCATION INFORMATION</b>', self.styles['CustomHeading']))

        timezones = location_info.get('timezones', [])
        tz_str = ', '.join(timezones) if timezones else 'Not available'

        location_data = [
            ['Country', location_info.get('country', 'Unknown')],
            ['Region/Location', location_info.get('location', 'Not available')],
            ['Timezones', tz_str],
        ]

        location_table = Table(location_data, colWidths=[2.5*inch, 3.5*inch])
        location_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(location_table)

        # Important note
        note = Paragraph(
            '<i>Note: Location is based on number registration, not current device location.</i>',
            self.styles['SmallText']
        )
        elements.append(Spacer(1, 0.05*inch))
        elements.append(note)
        elements.append(Spacer(1, 0.2*inch))

    def _add_risk_assessment(self, elements):
        """Add risk assessment section"""
        results = self.investigation.raw_results
        risk = results.get('risk_assessment', {})

        if not risk:
            return

        elements.append(Paragraph('<b>FRAUD RISK ASSESSMENT</b>', self.styles['CustomHeading']))

        risk_score = risk.get('risk_score', 0)
        assessment = risk.get('assessment', 'UNKNOWN')

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
        flags = risk.get('flags', [])
        if flags:
            elements.append(Paragraph('<b>Risk Indicators:</b>', self.styles['CustomSubheading']))
            for flag in flags:
                elements.append(Paragraph(f'  • {flag}', self.styles['CustomBody']))

        # Recommendations
        recommendations = risk.get('recommendations', [])
        if recommendations:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph('<b>Recommendations:</b>', self.styles['CustomSubheading']))
            for rec in recommendations:
                elements.append(Paragraph(f'  • {rec}', self.styles['CustomBody']))

        elements.append(Spacer(1, 0.2*inch))

    def _add_social_media_findings(self, elements):
        """Add social media accounts found"""
        results = self.investigation.raw_results
        social_media = results.get('social_media', [])

        elements.append(Paragraph(f'<b>SOCIAL MEDIA & MESSAGING PLATFORMS ({len(social_media)})</b>',
                                self.styles['CustomHeading']))

        if social_media:
            elements.append(Paragraph(
                'Note: These are potential accounts. Manual verification required.',
                self.styles['SmallText']
            ))
            elements.append(Spacer(1, 0.1*inch))

            # Create table data
            table_data = [['Platform', 'Confidence', 'URL']]
            for account in social_media:
                table_data.append([
                    account.get('platform', 'Unknown'),
                    account.get('confidence', 'Unknown'),
                    account.get('url', 'N/A')[:50] + '...' if len(account.get('url', '')) > 50 else account.get('url', 'N/A')
                ])

            social_table = Table(table_data, colWidths=[1.5*inch, 1.2*inch, 3.3*inch])
            social_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.zps_blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(social_table)
        else:
            elements.append(Paragraph('No social media platforms checked.', self.styles['CustomBody']))

        elements.append(Spacer(1, 0.2*inch))

    def _add_online_mentions(self, elements):
        """Add online mentions and listings"""
        results = self.investigation.raw_results
        mentions = results.get('online_mentions', {})

        total = mentions.get('total_found', 0)
        elements.append(Paragraph(f'<b>ONLINE MENTIONS & LISTINGS ({total} sources)</b>',
                                self.styles['CustomHeading']))

        # Scam databases
        sources = mentions.get('sources', [])
        if sources:
            elements.append(Paragraph('<b>Scam/Spam Databases:</b>', self.styles['CustomSubheading']))
            for source in sources:
                elements.append(Paragraph(
                    f'  • <b>{source.get("name")}:</b> {source.get("type")} - {source.get("url", "N/A")[:60]}...',
                    self.styles['SmallText']
                ))
            elements.append(Spacer(1, 0.1*inch))

        # Business listings
        business = mentions.get('business_listings', [])
        if business:
            elements.append(Paragraph('<b>Business Directories:</b>', self.styles['CustomSubheading']))
            for listing in business:
                elements.append(Paragraph(
                    f'  • <b>{listing.get("name")}:</b> {listing.get("type")}',
                    self.styles['SmallText']
                ))

        if not sources and not business:
            elements.append(Paragraph('No online mention sources available.', self.styles['CustomBody']))

        elements.append(Spacer(1, 0.2*inch))

    def _add_evidence_hash(self, elements):
        """Add evidence integrity hash"""
        elements.append(Paragraph('<b>EVIDENCE INTEGRITY</b>', self.styles['CustomHeading']))

        hash_text = f'Evidence Hash (SHA-256): {self.investigation.evidence_hash}'
        elements.append(Paragraph(hash_text, self.styles['CustomBody']))

        note = Paragraph(
            '<i>This cryptographic hash ensures the integrity of investigation results. '
            'Any modification to the data will change this hash value, making tampering detectable.</i>',
            self.styles['SmallText']
        )
        elements.append(Spacer(1, 0.05*inch))
        elements.append(note)
        elements.append(Spacer(1, 0.2*inch))

    def _add_footer(self, elements):
        """Add report footer"""
        elements.append(Spacer(1, 0.3*inch))

        footer_text = f'''
        <b>CERTIFICATION</b><br/>
        I, {self.investigator.full_name} ({self.investigator.badge_number}), {self.investigator.rank},
        certify that this investigation was conducted in accordance with Zambia Police Service procedures
        and that the information contained herein is accurate to the best of my knowledge.<br/><br/>

        Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>
        Investigation ID: {self.investigation.id}<br/><br/>

        <i>This document is CONFIDENTIAL and intended for law enforcement use only.
        Unauthorized disclosure is prohibited.</i>
        '''

        elements.append(Paragraph(footer_text, self.styles['SmallText']))

    def generate(self, output_path):
        """
        Generate the PDF report

        Args:
            output_path: Path where PDF should be saved

        Returns:
            Path to generated PDF file
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

        # Build document content
        elements = []

        # Add sections
        self._add_header(elements)
        self._add_investigation_header(elements)

        elements.append(PageBreak())

        self._add_phone_validation(elements)
        self._add_carrier_location_info(elements)
        self._add_risk_assessment(elements)

        elements.append(PageBreak())

        self._add_social_media_findings(elements)
        self._add_online_mentions(elements)
        self._add_evidence_hash(elements)
        self._add_footer(elements)

        # Build PDF
        doc.build(elements)

        return output_path
