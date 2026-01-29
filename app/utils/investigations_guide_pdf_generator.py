"""
OSINT Investigations Guide PDF Generator
CyberTrace - Zambia Police Service

Generate professional PDF user guide for OSINT Investigations
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os


class InvestigationsGuidePDF:
    """Generate PDF user guide for OSINT Investigations"""

    def __init__(self, logo_path=None):
        """
        Initialize PDF guide generator

        Args:
            logo_path: Path to police logo image
        """
        self.logo_path = logo_path or 'app/static/img/zp_logo.jpg'
        self.styles = getSampleStyleSheet()
        self.zps_blue = colors.HexColor('#000663')
        self.zps_green = colors.HexColor('#008000')

        # Create custom styles
        self._create_custom_styles()

    def _create_custom_styles(self):
        """Create custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=20,
            textColor=self.zps_blue,
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.zps_blue,
            spaceAfter=10,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='CustomSubheading',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=self.zps_blue,
            spaceAfter=8,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=6
        ))

        self.styles.add(ParagraphStyle(
            name='SmallBody',
            parent=self.styles['Normal'],
            fontSize=9,
            alignment=TA_JUSTIFY,
            spaceAfter=4
        ))

    def _add_header(self, elements):
        """Add guide header"""
        if os.path.exists(self.logo_path):
            logo = Image(self.logo_path, width=1.2*inch, height=1.2*inch)
            header_data = [
                [logo, Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>CYBERCRIME INVESTIGATION UNIT<br/><font size="12">OSINT Investigation Tools</font><br/><font size="11" color="green">User Guide & Training Manual</font>',
                                self.styles['CustomTitle'])]
            ]
            header_table = Table(header_data, colWidths=[1.5*inch, 5*inch])
            header_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (0, 0), 'LEFT'),
                ('ALIGN', (1, 0), (1, 0), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(header_table)
        else:
            title = Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>OSINT Investigation Tools<br/>User Guide',
                            self.styles['CustomTitle'])
            elements.append(title)

        elements.append(Spacer(1, 0.3*inch))

        info_data = [
            ['Document Type:', 'Training Manual & User Guide'],
            ['Module:', 'OSINT Investigation Tools'],
            ['Version:', '1.0'],
            ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Classification:', 'INTERNAL USE - POLICE OFFICERS ONLY']
        ]

        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 0.4*inch))

    def _add_introduction(self, elements):
        """Add introduction"""
        elements.append(Paragraph('<b>INTRODUCTION TO OSINT INVESTIGATIONS</b>', self.styles['CustomHeading']))

        intro_text = """
        Open Source Intelligence (OSINT) is the collection and analysis of information from publicly
        available sources for use in intelligence and investigation contexts. This manual will guide
        you through using CyberTrace OSINT tools to gather digital evidence legally and effectively.
        """
        elements.append(Paragraph(intro_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.1*inch))

        elements.append(Paragraph('<b>Why Use OSINT?</b>', self.styles['CustomSubheading']))
        benefits = [
            'Legal - All information from public sources',
            'Fast - Automated tools save hours of manual research',
            'Comprehensive - Check multiple databases simultaneously',
            'Evidence Quality - Documented with timestamps and hashes',
            'Case Integration - Automatically linked to case files'
        ]
        for benefit in benefits:
            elements.append(Paragraph(f'• {benefit}', self.styles['SmallBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_before_starting(self, elements):
        """Add prerequisites"""
        elements.append(Paragraph('<b>BEFORE YOU START</b>', self.styles['CustomHeading']))

        warning_text = """
        <b>IMPORTANT:</b> Every investigation must be linked to an official case.
        You cannot run investigations without first creating or being assigned to a case.
        """
        elements.append(Paragraph(warning_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.1*inch))

        steps = [
            'Check if you have access to a case (Go to Cases menu)',
            'If NO case: Click "Create New Case" and fill in information',
            'If case exists but you cannot see it: Ask Lead Investigator to add you',
            'After you have a case: Select it when running OSINT tools'
        ]
        for step in steps:
            elements.append(Paragraph(f'{step}', self.styles['SmallBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_email_osint(self, elements):
        """Add Email OSINT section"""
        elements.append(PageBreak())
        elements.append(Paragraph('<b>EMAIL OSINT INVESTIGATION</b>', self.styles['CustomHeading']))

        elements.append(Paragraph('<b>What It Does:</b>', self.styles['CustomSubheading']))
        elements.append(Paragraph('Investigates email addresses to uncover identity, breach history, and associated accounts.', self.styles['CustomBody']))
        elements.append(Spacer(1, 0.1*inch))

        elements.append(Paragraph('<b>When to Use:</b>', self.styles['CustomSubheading']))
        use_cases = ['Fraud investigations', 'Phishing/scam cases', 'Identity theft', 'Cybercrime', 'Email-based threats']
        for case in use_cases:
            elements.append(Paragraph(f'• {case}', self.styles['SmallBody']))
        elements.append(Spacer(1, 0.15*inch))

        elements.append(Paragraph('<b>Step-by-Step Instructions:</b>', self.styles['CustomSubheading']))
        email_steps = [
            ('1. Access Tool', 'Go to Investigations → Email OSINT'),
            ('2. Select Case', 'Choose your case from dropdown menu'),
            ('3. Enter Email', 'Type the email address to investigate'),
            ('4. Start Investigation', 'Click "Start Investigation" button'),
            ('5. Wait 5-15 seconds', 'System gathers information automatically'),
            ('6. Review Results', 'Check all sections of the report'),
            ('7. Download PDF', 'Save report to case file'),
            ('8. Verify Findings', 'Manually check social media accounts')
        ]
        for step_title, step_desc in email_steps:
            elements.append(Paragraph(f'<b>{step_title}:</b> {step_desc}', self.styles['SmallBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_best_practices(self, elements):
        """Add best practices"""
        elements.append(PageBreak())
        elements.append(Paragraph('<b>BEST PRACTICES</b>', self.styles['CustomHeading']))

        practices_data = [
            ['DO', 'DON\'T'],
            ['Link all investigations to cases', 'Run investigations without a case'],
            ['Download PDF reports', 'Rely only on screen views'],
            ['Verify social media manually', 'Interact with suspect accounts'],
            ['Take screenshots', 'Share results with unauthorized persons'],
            ['Note evidence hash', 'Forget chain of custody'],
            ['Cross-reference sources', 'Trust single source only'],
            ['Follow legal procedures', 'Exceed authorized scope'],
        ]

        practices_table = Table(practices_data, colWidths=[3*inch, 3*inch])
        practices_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.zps_blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(practices_table)
        elements.append(Spacer(1, 0.2*inch))

    def _add_troubleshooting(self, elements):
        """Add troubleshooting"""
        elements.append(Paragraph('<b>TROUBLESHOOTING</b>', self.styles['CustomHeading']))

        trouble_data = [
            ['Issue', 'Solution'],
            ['Cannot see cases', 'Create a case first or ask to be added to existing case'],
            ['Investigation fails', 'Wait 2 minutes and retry. Check input format.'],
            ['Rate limit error', 'Too many requests. Wait 2-3 minutes.'],
            ['Results show "Not Available"', 'Normal - not all data exists for every target'],
            ['PDF download fails', 'Check pop-up blocker. Try different browser.'],
        ]

        trouble_table = Table(trouble_data, colWidths=[2.2*inch, 4*inch])
        trouble_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.zps_blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(trouble_table)
        elements.append(Spacer(1, 0.2*inch))

    def _add_footer(self, elements):
        """Add footer"""
        elements.append(PageBreak())
        footer_text = f'''
        <para align=center>
        <b>ZAMBIA POLICE SERVICE - CYBERCRIME INVESTIGATION UNIT</b><br/>
        <font color="blue"><b>INTERNAL USE - POLICE OFFICERS ONLY</b></font><br/>
        <br/>
        This manual is for official police use only.<br/>
        <br/>
        Guide: OSINT Investigation Tools User Manual<br/>
        Version: 1.0<br/>
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        Platform: CyberTrace OSINT Platform<br/>
        <br/>
        <i>Electronically generated from CyberTrace</i>
        </para>
        '''
        elements.append(Paragraph(footer_text, self.styles['CustomBody']))

    def generate(self, output_path):
        """Generate the PDF guide"""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )

        elements = []
        self._add_header(elements)
        self._add_introduction(elements)
        self._add_before_starting(elements)
        self._add_email_osint(elements)
        self._add_best_practices(elements)
        self._add_troubleshooting(elements)
        self._add_footer(elements)

        doc.build(elements)
        return output_path
