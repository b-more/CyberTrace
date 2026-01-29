"""
Case Management Guide PDF Generator
CyberTrace - Zambia Police Service

Generate professional PDF user guide for Case Management module
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from datetime import datetime
import os


class CaseManagementGuidePDF:
    """Generate PDF user guide for Case Management"""

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
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=20,
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

        # Body style
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=6
        ))

        # Small body style
        self.styles.add(ParagraphStyle(
            name='SmallBody',
            parent=self.styles['Normal'],
            fontSize=9,
            alignment=TA_JUSTIFY,
            spaceAfter=4
        ))

    def _add_header(self, elements):
        """Add guide header with logo"""
        if os.path.exists(self.logo_path):
            logo = Image(self.logo_path, width=1.2*inch, height=1.2*inch)

            header_data = [
                [logo, Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>CYBERCRIME INVESTIGATION UNIT<br/><font size="12">Case Management System</font><br/><font size="11" color="green">User Guide & Training Manual</font>',
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
            title = Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>CYBERCRIME INVESTIGATION UNIT<br/>Case Management System<br/>User Guide & Training Manual',
                            self.styles['CustomTitle'])
            elements.append(title)

        elements.append(Spacer(1, 0.3*inch))

        # Document info box
        info_data = [
            ['Document Type:', 'Training Manual & User Guide'],
            ['Module:', 'Case Management System'],
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
        """Add introduction section"""
        elements.append(Paragraph('<b>INTRODUCTION</b>', self.styles['CustomHeading']))

        intro_text = """
        Welcome to the CyberTrace Case Management System. This guide will help you effectively
        manage criminal cases from creation to closure. Whether you're creating your first case
        or managing complex investigations, this manual provides step-by-step instructions
        for all case management tasks.
        """
        elements.append(Paragraph(intro_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.1*inch))

        purpose_text = """
        <b>What is a Case?</b> A case is a digital folder containing all information about a
        specific criminal investigation including OSINT investigations, evidence, team members,
        legal documents, and a complete timeline of all activities.
        """
        elements.append(Paragraph(purpose_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_creating_cases(self, elements):
        """Add case creation guide"""
        elements.append(Paragraph('<b>CREATING A NEW CASE</b>', self.styles['CustomHeading']))

        # Step-by-step instructions
        steps = [
            ('<b>STEP 1: Click "New Case" Button</b>', 'Click the green "New Case" button at the top right. Only officers with case creation permissions can create cases.'),
            ('<b>STEP 2: Enter Case Title</b>', 'Provide a clear, descriptive title. Example: "Email Fraud - John Doe" or "Cybercrime Investigation - ABC Company"'),
            ('<b>STEP 3: Write Detailed Description</b>', 'Include: What happened? When? Who reported it? What evidence do you have?'),
            ('<b>STEP 4: Select Case Type</b>', 'Choose the appropriate category: Fraud, Cybercrime, Identity Theft, Financial Crime, or Other.'),
            ('<b>STEP 5: Set Priority Level</b>', 'Critical (immediate danger), High (serious crime), Medium (standard), or Low (minor incidents).'),
            ('<b>STEP 6: Submit</b>', 'System automatically generates case number (e.g., ZPS-2025-0001) and sets you as Lead Investigator.')
        ]

        for step_title, step_desc in steps:
            elements.append(Paragraph(step_title, self.styles['CustomSubheading']))
            elements.append(Paragraph(step_desc, self.styles['SmallBody']))
            elements.append(Spacer(1, 0.1*inch))

        elements.append(Spacer(1, 0.2*inch))

    def _add_case_statuses(self, elements):
        """Add case status information"""
        elements.append(PageBreak())
        elements.append(Paragraph('<b>UNDERSTANDING CASE STATUS</b>', self.styles['CustomHeading']))

        status_data = [
            ['Status', 'Meaning', 'Action Required'],
            ['OPEN', 'Just created, ready to begin', 'Start collecting evidence, run OSINT investigations'],
            ['INVESTIGATING', 'Active investigation', 'Continue investigations, document findings, update regularly'],
            ['PENDING', 'Awaiting warrants/approvals', 'Follow up on pending items, update when ready'],
            ['CLOSED', 'Investigation complete', 'No action. View-only for reports and evidence'],
            ['ARCHIVED', 'Long-term storage', 'Read-only historical reference']
        ]

        status_table = Table(status_data, colWidths=[1.2*inch, 2.3*inch, 2.7*inch])
        status_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.zps_blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(status_table)
        elements.append(Spacer(1, 0.2*inch))

    def _add_priority_levels(self, elements):
        """Add priority level information"""
        elements.append(Paragraph('<b>PRIORITY LEVELS EXPLAINED</b>', self.styles['CustomHeading']))

        priority_data = [
            ['Priority', 'When to Use', 'Examples'],
            ['CRITICAL', 'Immediate danger, ongoing crimes', 'Active cyber attacks, threats to life, major financial fraud in progress'],
            ['HIGH', 'Serious crimes, time-sensitive', 'Recent large-scale fraud, identity theft with ongoing losses'],
            ['MEDIUM', 'Standard investigations', 'Most fraud cases, historical cybercrime investigations'],
            ['LOW', 'Minor incidents', 'Old cases, low-value fraud, informational reports']
        ]

        priority_table = Table(priority_data, colWidths=[1*inch, 2.2*inch, 3*inch])
        priority_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.zps_blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(priority_table)
        elements.append(Spacer(1, 0.2*inch))

    def _add_linking_investigations(self, elements):
        """Add information about linking investigations"""
        elements.append(Paragraph('<b>LINKING INVESTIGATIONS TO CASES</b>', self.styles['CustomHeading']))

        link_text = """
        <b>Every investigation must be linked to a case.</b> When using any OSINT tool
        (Email, Phone, IP Address, etc.), you must select which case the investigation belongs to.
        This ensures all evidence is properly documented and legally admissible.
        """
        elements.append(Paragraph(link_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.15*inch))

        elements.append(Paragraph('<b>Example Workflow:</b>', self.styles['CustomSubheading']))
        workflow_steps = [
            '1. Create a case: "Email Fraud Investigation - Victim Jane Smith"',
            '2. Navigate to Email OSINT tool',
            '3. Select your case from the dropdown menu',
            '4. Enter suspect\'s email address',
            '5. Run investigation',
            '6. Results automatically saved to your case',
            '7. View all investigations in case detail page'
        ]
        for step in workflow_steps:
            elements.append(Paragraph(step, self.styles['SmallBody']))

        elements.append(Spacer(1, 0.2*inch))

    def _add_best_practices(self, elements):
        """Add best practices"""
        elements.append(PageBreak())
        elements.append(Paragraph('<b>BEST PRACTICES</b>', self.styles['CustomHeading']))

        dos_donts = [
            ('DO', [
                'Create a new case for each investigation',
                'Use clear, descriptive case titles',
                'Write detailed descriptions with all known information',
                'Set accurate priority levels',
                'Link ALL investigations to the correct case',
                'Update case status as investigation progresses',
                'Add notes regularly to track progress',
                'Close cases when investigation is complete'
            ]),
            ('DON\'T', [
                'Use vague titles like "Case 1" or "Test"',
                'Leave case descriptions empty',
                'Run investigations without selecting a case',
                'Share case information with unauthorized persons',
                'Delete cases (archive instead)',
                'Forget to update case status',
                'Leave cases open indefinitely',
                'Work on cases you\'re not assigned to'
            ])
        ]

        for title, items in dos_donts:
            elements.append(Paragraph(f'<b>{title}:</b>', self.styles['CustomSubheading']))
            for item in items:
                elements.append(Paragraph(f'• {item}', self.styles['SmallBody']))
            elements.append(Spacer(1, 0.15*inch))

    def _add_case_lifecycle(self, elements):
        """Add case lifecycle"""
        elements.append(Paragraph('<b>CASE LIFECYCLE</b>', self.styles['CustomHeading']))

        lifecycle_text = """
        <b>Typical case workflow:</b><br/>
        OPEN → INVESTIGATING → PENDING (if needed) → INVESTIGATING → CLOSED → ARCHIVED (if old)
        """
        elements.append(Paragraph(lifecycle_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_troubleshooting(self, elements):
        """Add troubleshooting section"""
        elements.append(Paragraph('<b>TROUBLESHOOTING</b>', self.styles['CustomHeading']))

        trouble_data = [
            ['Issue', 'Solution'],
            ['Can\'t see "New Case" button', 'You don\'t have permission. Contact supervisor for access.'],
            ['Can\'t see a specific case', 'You must be Lead Investigator or Assigned Officer. Ask lead to add you.'],
            ['Can\'t run investigation without case', 'Create a case first. All investigations must link to a case.'],
            ['Case number not showing', 'Case numbers are auto-generated. You cannot edit them.'],
            ['Need to reopen closed case', 'Contact Senior Investigator or Admin to reopen.']
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
        """Add guide footer"""
        elements.append(PageBreak())

        footer_text = f'''
        <para align=center>
        <b>ZAMBIA POLICE SERVICE - CYBERCRIME INVESTIGATION UNIT</b><br/>
        <font color="blue"><b>INTERNAL USE - POLICE OFFICERS ONLY</b></font><br/>
        <br/>
        This training manual is for official police use only. Protect from unauthorized disclosure.<br/>
        <br/>
        <b>Document Information:</b><br/>
        Guide: Case Management System User Manual<br/>
        Version: 1.0<br/>
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        Platform: CyberTrace OSINT Platform<br/>
        <br/>
        <b>For Technical Support:</b><br/>
        Contact your unit supervisor or CyberTrace system administrator<br/>
        <br/>
        <i>This guide is electronically generated from the CyberTrace platform</i>
        </para>
        '''

        elements.append(Paragraph(footer_text, self.styles['CustomBody']))

    def generate(self, output_path):
        """
        Generate the PDF guide

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
        self._add_introduction(elements)
        self._add_creating_cases(elements)
        self._add_case_statuses(elements)
        self._add_priority_levels(elements)
        self._add_linking_investigations(elements)
        self._add_best_practices(elements)
        self._add_case_lifecycle(elements)
        self._add_troubleshooting(elements)
        self._add_footer(elements)

        # Build PDF
        doc.build(elements)

        return output_path
