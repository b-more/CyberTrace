"""
Email OSINT Guide PDF Generator
CyberTrace - Zambia Police Service

Generate professional PDF user guide for Email OSINT module
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak, ListFlowable, ListItem
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from datetime import datetime
import os


class EmailOSINTGuidePDF:
    """Generate PDF user guide for Email OSINT Investigation Tool"""

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
        # Logo and title table
        if os.path.exists(self.logo_path):
            logo = Image(self.logo_path, width=1.2*inch, height=1.2*inch)

            header_data = [
                [logo, Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>CYBERCRIME INVESTIGATION UNIT<br/><font size="12">Email OSINT Investigation Tool</font><br/><font size="11" color="green">User Guide & Training Manual</font>',
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
            title = Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>CYBERCRIME INVESTIGATION UNIT<br/>Email OSINT Investigation Tool<br/>User Guide & Training Manual',
                            self.styles['CustomTitle'])
            elements.append(title)

        elements.append(Spacer(1, 0.3*inch))

        # Document info box
        info_data = [
            ['Document Type:', 'Training Manual & User Guide'],
            ['Module:', 'Email OSINT Investigation'],
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
        Welcome to the Email OSINT Investigation Tool user guide. This manual is designed to help
        all police officers, regardless of technical background, effectively use this powerful
        investigative tool. Whether you're new to digital investigations or an experienced
        cybercrime investigator, this guide will walk you through every step of conducting
        email-based investigations.
        """
        elements.append(Paragraph(intro_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.1*inch))

        purpose_text = """
        <b>Purpose of This Tool:</b> The Email OSINT Investigation Tool helps you investigate
        email addresses in fraud, cybercrime, and other criminal cases by automatically gathering
        intelligence from multiple sources including data breach databases, social media platforms,
        domain registrations, and security records.
        """
        elements.append(Paragraph(purpose_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_quick_start(self, elements):
        """Add quick start guide"""
        elements.append(Paragraph('<b>STEP-BY-STEP: HOW TO START AN INVESTIGATION</b>', self.styles['CustomHeading']))

        # Step 1
        elements.append(Paragraph('<b>STEP 1: Select a Case</b>', self.styles['CustomSubheading']))
        step1_points = [
            '<b>What to do:</b> Look for the dropdown box labeled "Select Case" with a folder icon.',
            '<b>Why:</b> Every investigation must be linked to an official case for proper documentation and legal compliance.',
            '<b>How:</b> Click on the dropdown and select your active case from the list. You\'ll see the case number, title, and status.',
            '<b>Important:</b> If you don\'t see your case, contact your supervisor to request access or create a new case first.'
        ]
        for point in step1_points:
            elements.append(Paragraph(f'• {point}', self.styles['SmallBody']))
        elements.append(Spacer(1, 0.15*inch))

        # Step 2
        elements.append(Paragraph('<b>STEP 2: Enter the Email Address</b>', self.styles['CustomSubheading']))
        step2_points = [
            '<b>What to do:</b> Find the text box labeled "Email Address" with an envelope icon.',
            '<b>How:</b> Type or paste the email address you want to investigate (e.g., suspect@gmail.com).',
            '<b>Tips:</b> Make sure there are no extra spaces. The email must be in correct format (example@domain.com). Copy directly from your case file to avoid typing errors.'
        ]
        for point in step2_points:
            elements.append(Paragraph(f'• {point}', self.styles['SmallBody']))
        elements.append(Spacer(1, 0.15*inch))

        # Step 3
        elements.append(Paragraph('<b>STEP 3: Click "Start Investigation"</b>', self.styles['CustomSubheading']))
        step3_text = '<b>What to do:</b> Click the big blue button that says "Start Investigation".'
        elements.append(Paragraph(f'• {step3_text}', self.styles['SmallBody']))
        elements.append(Paragraph('• <b>What happens next:</b> The system will automatically:', self.styles['SmallBody']))

        auto_checks = [
            'Check if the email address is valid and deliverable',
            'Search for data breaches involving this email',
            'Look up domain registration information',
            'Check DNS security records',
            'Search for social media accounts',
            'Calculate a risk score'
        ]
        for check in auto_checks:
            elements.append(Paragraph(f'  - {check}', self.styles['SmallBody']))

        elements.append(Paragraph('• <b>Wait time:</b> This usually takes 5-15 seconds. Please be patient and don\'t close the browser.', self.styles['SmallBody']))
        elements.append(Paragraph('• <b>Note:</b> All your actions are automatically logged for audit purposes.', self.styles['SmallBody']))
        elements.append(Spacer(1, 0.15*inch))

        # Step 4
        elements.append(Paragraph('<b>STEP 4: Review Your Results</b>', self.styles['CustomSubheading']))
        step4_points = [
            '<b>What to do:</b> After the investigation completes, you\'ll see a detailed report page.',
            '<b>Next actions:</b> Read the risk assessment at the top, review each section carefully, click "Download PDF Report" to save an official copy, and verify any social media accounts manually.'
        ]
        for point in step4_points:
            elements.append(Paragraph(f'• {point}', self.styles['SmallBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_understanding_results(self, elements):
        """Add section on understanding results"""
        elements.append(PageBreak())
        elements.append(Paragraph('<b>UNDERSTANDING YOUR INVESTIGATION RESULTS</b>', self.styles['CustomHeading']))

        # Risk Score Section
        elements.append(Paragraph('<b>1. Risk Score - What Does It Mean?</b>', self.styles['CustomSubheading']))
        elements.append(Paragraph('The risk score is a number from 0 to 100 that tells you how suspicious this email address appears.', self.styles['CustomBody']))
        elements.append(Spacer(1, 0.1*inch))

        risk_data = [
            ['Score Range', 'Risk Level', 'What It Means', 'What You Should Do'],
            ['0-39', 'LOW RISK', 'Very few or no suspicious indicators', 'Continue with normal procedures. Email appears legitimate.'],
            ['40-69', 'MODERATE RISK', 'Some concerning factors detected', 'Investigate more carefully. Look for additional evidence.'],
            ['70-100', 'HIGH RISK', 'Multiple serious red flags present', 'Priority case! Report to supervisor immediately.']
        ]

        risk_table = Table(risk_data, colWidths=[0.9*inch, 1.1*inch, 1.8*inch, 2.4*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.zps_blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 1), (-1, 1), colors.lightgreen),
            ('BACKGROUND', (0, 2), (-1, 2), colors.lightyellow),
            ('BACKGROUND', (0, 3), (-1, 3), colors.lightpink),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 0.2*inch))

        # Risk Flags Section
        elements.append(Paragraph('<b>2. Risk Flags - Warning Signs to Watch</b>', self.styles['CustomSubheading']))

        flags = [
            ('Multiple Data Breaches', 'Email found in 2+ data breaches. Passwords may be available to criminals on dark web.'),
            ('Recent Breaches', 'Breached within last 2 years. Active threat - information may be currently used by criminals.'),
            ('Disposable/Temporary Email', 'From temporary service (10minutemail, guerrillamail). Strong fraud indicator.'),
            ('No SPF/DMARC Records', 'Domain lacks email security. Can be easily spoofed by scammers.'),
            ('Invalid/Non-Existent Email', 'Email doesn\'t exist. Suspect may have provided fake information.')
        ]

        for flag_name, flag_desc in flags:
            elements.append(Paragraph(f'<b>{flag_name}:</b> {flag_desc}', self.styles['SmallBody']))
            elements.append(Spacer(1, 0.05*inch))

        elements.append(Spacer(1, 0.2*inch))

    def _add_social_media_section(self, elements):
        """Add social media section"""
        elements.append(Paragraph('<b>3. Social Media Accounts - Finding the Suspect Online</b>', self.styles['CustomSubheading']))

        elements.append(Paragraph('The system automatically searches 13+ platforms including GitHub, LinkedIn, Twitter/X, Facebook, Instagram, Reddit, and more.', self.styles['CustomBody']))
        elements.append(Spacer(1, 0.1*inch))

        # Confidence levels
        elements.append(Paragraph('<b>Understanding Confidence Levels:</b>', self.styles['SmallBody']))
        confidence_data = [
            ['Level', 'Meaning', 'Action Required'],
            ['HIGH', 'Account definitely exists. Verified through API.', 'Trust this result. Visit profile.'],
            ['MEDIUM', 'Account likely exists but not 100% verified.', 'Visit profile to confirm ownership.'],
            ['LOW', 'Possible match, needs verification.', 'Check carefully. May be different person.']
        ]

        conf_table = Table(confidence_data, colWidths=[1*inch, 2.5*inch, 2.7*inch])
        conf_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(conf_table)
        elements.append(Spacer(1, 0.15*inch))

        # How to use findings
        elements.append(Paragraph('<b>How to Use Social Media Findings:</b>', self.styles['SmallBody']))
        social_steps = [
            'Click "Visit" button next to each found account',
            'Verify ownership: Check if profile picture, name, location match your suspect',
            'Take screenshots: Capture relevant posts, photos, connections as evidence',
            'Look for: Location tags, associates, posted threats, evidence of crimes',
            'Document everything in your case file',
            '<b>Important:</b> Don\'t interact with suspect\'s accounts (no liking, commenting, following)'
        ]
        for step in social_steps:
            elements.append(Paragraph(f'{step}', self.styles['SmallBody']))

        elements.append(Spacer(1, 0.2*inch))

    def _add_data_breach_section(self, elements):
        """Add data breach section"""
        elements.append(PageBreak())
        elements.append(Paragraph('<b>4. Data Breaches - Has This Email Been Compromised?</b>', self.styles['CustomSubheading']))

        elements.append(Paragraph('Data comes from HaveIBeenPwned (HIBP) - a trusted database of 12+ billion compromised accounts from 600+ data breaches.', self.styles['CustomBody']))
        elements.append(Spacer(1, 0.1*inch))

        # What you'll see
        breach_info_data = [
            ['Field', 'What It Means'],
            ['Breach Name', 'Company/website that was hacked (e.g., LinkedIn, Adobe, Yahoo)'],
            ['Breach Date', 'When the hack occurred. Recent dates (within 2 years) more concerning.'],
            ['Accounts Affected', 'Total users compromised. Shows scale of breach.'],
            ['Verified', 'HIBP confirmed this breach is real and legitimate.'],
            ['Sensitive', 'Includes very private information (passwords, financial data). High risk!'],
            ['Data Classes', 'Specific information stolen (see below)']
        ]

        breach_table = Table(breach_info_data, colWidths=[1.5*inch, 4.7*inch])
        breach_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.zps_blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(breach_table)
        elements.append(Spacer(1, 0.15*inch))

        # Critical warning box
        warning_text = """
        <b><font color="red">CRITICAL WARNING!</font></b><br/>
        If you see "Passwords" in the Data Classes:<br/>
        • Assume the password has been cracked (decoded) by hackers<br/>
        • The password is likely available on dark web marketplaces<br/>
        • Criminals may have already used it to access other accounts<br/>
        • <b>For victims:</b> Advise immediate password change on ALL accounts<br/>
        • <b>For suspects:</b> They may have had identity stolen or using stolen credentials
        """
        elements.append(Paragraph(warning_text, self.styles['SmallBody']))
        elements.append(Spacer(1, 0.2*inch))

        # What to do when you find breaches
        elements.append(Paragraph('<b>What to Do When You Find Breaches:</b>', self.styles['SmallBody']))
        breach_actions = [
            'Count the breaches: Multiple breaches = higher risk',
            'Check dates: Breaches in last 2 years are active threats',
            'Review data classes: Note what was stolen, especially passwords and financial data',
            'For victims: Inform them and recommend password changes and fraud monitoring',
            'For suspects: Document in case file. May indicate use of compromised credentials',
            'Always include breaches in your official investigation report'
        ]
        for action in breach_actions:
            elements.append(Paragraph(f'• {action}', self.styles['SmallBody']))

        elements.append(Spacer(1, 0.2*inch))

    def _add_best_practices(self, elements):
        """Add best practices section"""
        elements.append(Paragraph('<b>BEST PRACTICES FOR INVESTIGATIONS</b>', self.styles['CustomHeading']))

        practices = [
            ('<b>Case Linking:</b>', 'Always link investigations to active cases for proper documentation and legal compliance.'),
            ('<b>Download Reports:</b>', 'Generate PDF report immediately after investigation for your case file.'),
            ('<b>Evidence Hash:</b>', 'Note the SHA-256 hash shown in results for legal chain of custody.'),
            ('<b>Manual Verification:</b>', 'Always verify social media accounts manually before drawing conclusions.'),
            ('<b>Cross-Reference:</b>', 'Combine email OSINT findings with other investigation methods for complete picture.'),
            ('<b>Legal Compliance:</b>', 'Ensure proper authorization before conducting investigations.'),
            ('<b>Privacy Protection:</b>', 'Handle all investigation data according to police service data protection policies.'),
            ('<b>Documentation:</b>', 'Keep detailed notes of all findings in your case management system.')
        ]

        for practice, desc in practices:
            elements.append(Paragraph(f'{practice} {desc}', self.styles['CustomBody']))
            elements.append(Spacer(1, 0.05*inch))

        elements.append(Spacer(1, 0.2*inch))

    def _add_troubleshooting(self, elements):
        """Add troubleshooting section"""
        elements.append(Paragraph('<b>TROUBLESHOOTING COMMON ISSUES</b>', self.styles['CustomHeading']))

        troubleshoot_data = [
            ['Issue', 'Solution'],
            ['Investigation Failed', 'Wait 2 minutes and retry. Check email format is correct.'],
            ['API Rate Limit Error', 'Too many requests. Wait 2-3 minutes before next investigation.'],
            ['No Cases Available', 'Create a new case first or request case assignment from supervisor.'],
            ['Some Results Missing', 'Domain may not have all records. This is normal for some domains.'],
            ['Social Media Not Loading', 'Platform may be temporarily unavailable. Note in report and retry later.'],
            ['PDF Download Fails', 'Check your browser pop-up blocker settings. Try different browser.']
        ]

        trouble_table = Table(troubleshoot_data, colWidths=[2.2*inch, 4*inch])
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
        This training manual is for official police use only. It contains operational procedures
        and investigative techniques that must be protected from unauthorized disclosure.<br/>
        <br/>
        <b>Document Information:</b><br/>
        Guide: Email OSINT Investigation Tool User Manual<br/>
        Version: 1.0<br/>
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        Platform: CyberTrace OSINT Platform<br/>
        <br/>
        <b>For Technical Support:</b><br/>
        Contact your unit supervisor or the CyberTrace system administrator<br/>
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
        self._add_quick_start(elements)
        self._add_understanding_results(elements)
        self._add_social_media_section(elements)
        self._add_data_breach_section(elements)
        self._add_best_practices(elements)
        self._add_troubleshooting(elements)
        self._add_footer(elements)

        # Build PDF
        doc.build(elements)

        return output_path
