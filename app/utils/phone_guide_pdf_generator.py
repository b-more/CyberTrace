"""
Phone OSINT Guide PDF Generator
CyberTrace - Zambia Police Service

Generate professional PDF user guide for Phone OSINT module
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os


class PhoneOSINTGuidePDF:
    """Generate PDF user guide for Phone OSINT Investigation Tool"""

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
                [logo, Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>CYBERCRIME INVESTIGATION UNIT<br/><font size="12">Phone OSINT Investigation Tool</font><br/><font size="11" color="green">User Guide & Training Manual</font>',
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
            title = Paragraph('<b>ZAMBIA POLICE SERVICE</b><br/>CYBERCRIME INVESTIGATION UNIT<br/>Phone OSINT Investigation Tool<br/>User Guide & Training Manual',
                            self.styles['CustomTitle'])
            elements.append(title)

        elements.append(Spacer(1, 0.3*inch))

        # Document info box
        info_data = [
            ['Document Type:', 'Training Manual & User Guide'],
            ['Module:', 'Phone OSINT Investigation'],
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
        Welcome to the Phone OSINT Investigation Tool user guide. This manual is designed to help
        all police officers, regardless of technical background, effectively use this powerful
        investigative tool for phone number investigations. This guide will walk you through every
        step of conducting phone-based investigations.
        """
        elements.append(Paragraph(intro_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.1*inch))

        purpose_text = """
        <b>Purpose of This Tool:</b> The Phone OSINT Investigation Tool helps you investigate
        phone numbers to uncover carrier information, validate numbers, detect fraud indicators,
        and identify geographic locations. All investigations are automatically documented and
        linked to your case files.
        """
        elements.append(Paragraph(purpose_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_getting_started(self, elements):
        """Add getting started section"""
        elements.append(Paragraph('<b>GETTING STARTED</b>', self.styles['CustomHeading']))

        elements.append(Paragraph('<b>Step 1: Access the Phone OSINT Tool</b>', self.styles['CustomSubheading']))
        step1 = """
        From the CyberTrace dashboard, click on "Phone Number OSINT" in the left sidebar, or
        navigate to the Investigations page and select "Phone Investigation".
        """
        elements.append(Paragraph(step1, self.styles['CustomBody']))

        elements.append(Paragraph('<b>Step 2: Select Your Case</b>', self.styles['CustomSubheading']))
        step2 = """
        Every investigation must be linked to a case. Select the appropriate case from the dropdown
        menu. If you don't see your case, it may be closed or you may not have access.
        """
        elements.append(Paragraph(step2, self.styles['CustomBody']))

        elements.append(Paragraph('<b>Step 3: Enter Phone Number</b>', self.styles['CustomSubheading']))
        step3 = """
        Enter the phone number you want to investigate. You can enter it in any of these formats:
        <br/>• International: +260 97 1234567
        <br/>• National: 0971234567
        <br/>• Country code: 260971234567
        <br/><br/>
        The system will automatically parse and validate the format.
        """
        elements.append(Paragraph(step3, self.styles['CustomBody']))

        elements.append(Paragraph('<b>Step 4: Run Investigation</b>', self.styles['CustomSubheading']))
        step4 = """
        Click "Start Investigation". Results appear instantly. The investigation is automatically
        saved to your case with evidence hash for chain of custody.
        """
        elements.append(Paragraph(step4, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_understanding_results(self, elements):
        """Add results interpretation section"""
        elements.append(Paragraph('<b>UNDERSTANDING INVESTIGATION RESULTS</b>', self.styles['CustomHeading']))

        elements.append(Paragraph('<b>Phone Validation</b>', self.styles['CustomSubheading']))
        validation_text = """
        The validation section shows if the phone number is properly formatted and active.
        Key fields include:
        <br/>• <b>Valid Number:</b> Confirms number follows international standards
        <br/>• <b>Number Type:</b> Mobile, Landline, VoIP, or Premium Rate
        <br/>• <b>Country Code:</b> International dialing code
        <br/>• <b>Formats:</b> International, national, and E.164 formats
        """
        elements.append(Paragraph(validation_text, self.styles['CustomBody']))

        elements.append(Paragraph('<b>Carrier Information</b>', self.styles['CustomSubheading']))
        carrier_text = """
        Shows the telecommunications provider operating the number. Common Zambian carriers
        include Airtel Zambia, MTN Zambia, and Zamtel. Unknown carriers may indicate VoIP
        services or foreign providers.
        """
        elements.append(Paragraph(carrier_text, self.styles['CustomBody']))

        elements.append(Paragraph('<b>Location Information</b>', self.styles['CustomSubheading']))
        location_text = """
        Geographic data based on number registration (not current physical location):
        <br/>• <b>Country:</b> Where the number is registered
        <br/>• <b>Region:</b> General area (e.g., Lusaka, Copperbelt)
        <br/>• <b>Timezones:</b> Local time zones
        <br/><br/>
        <b>Important:</b> This shows registration location, not real-time device location.
        For live tracking, request carrier assistance with court order.
        """
        elements.append(Paragraph(location_text, self.styles['CustomBody']))

        elements.append(Paragraph('<b>Risk Assessment</b>', self.styles['CustomSubheading']))
        risk_text = """
        Fraud risk score (0-100) with three levels:
        """
        elements.append(Paragraph(risk_text, self.styles['CustomBody']))

        risk_data = [
            ['Score', 'Level', 'Meaning'],
            ['0-39', 'LOW RISK', 'Normal phone number, standard investigation'],
            ['40-69', 'MODERATE RISK', 'Some concerns, enhanced verification needed'],
            ['70-100', 'HIGH RISK', 'Multiple fraud indicators, priority investigation']
        ]

        risk_table = Table(risk_data, colWidths=[1*inch, 1.5*inch, 3.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.zps_blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 1), (-1, 1), colors.lightgreen),
            ('BACKGROUND', (0, 2), (-1, 2), colors.yellow),
            ('BACKGROUND', (0, 3), (-1, 3), colors.lightpink),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 0.2*inch))

    def _add_fraud_indicators(self, elements):
        """Add fraud indicators section"""
        elements.append(Paragraph('<b>KEY FRAUD INDICATORS</b>', self.styles['CustomHeading']))

        elements.append(Paragraph('<b>1. VoIP Numbers (High Risk)</b>', self.styles['CustomSubheading']))
        voip_text = """
        Voice over IP numbers work through the internet instead of traditional phone networks.
        <br/><b>Why Dangerous:</b> Easy to create anonymously, hard to trace, can spoof caller ID
        <br/><b>Common In:</b> Romance scams, advance fee fraud, phishing
        <br/><b>Action:</b> Treat as high-priority suspect, request additional verification
        """
        elements.append(Paragraph(voip_text, self.styles['SmallBody']))

        elements.append(Paragraph('<b>2. Premium Rate Numbers (High Risk)</b>', self.styles['CustomSubheading']))
        premium_text = """
        Calling these numbers charges high fees to the caller.
        <br/><b>Why Dangerous:</b> Used in billing fraud where victims are tricked into calling
        <br/><b>Common In:</b> "Call back" scams, false prize notifications
        <br/><b>Action:</b> Investigate potential billing fraud operation
        """
        elements.append(Paragraph(premium_text, self.styles['SmallBody']))

        elements.append(Paragraph('<b>3. Unknown Carrier (Moderate Risk)</b>', self.styles['CustomSubheading']))
        carrier_text = """
        Cannot identify the telecommunications provider.
        <br/><b>Why Concerning:</b> Makes tracing difficult, may be VoIP or foreign
        <br/><b>Action:</b> Contact ZICTA or telecom authorities for carrier identification
        """
        elements.append(Paragraph(carrier_text, self.styles['SmallBody']))

        elements.append(Paragraph('<b>4. Foreign Numbers (Information)</b>', self.styles['CustomSubheading']))
        foreign_text = """
        Number registered in another country.
        <br/><b>Why Significant:</b> Cross-border investigation required
        <br/><b>Common In:</b> International fraud rings, money laundering
        <br/><b>Action:</b> Consider Interpol cooperation or mutual legal assistance
        """
        elements.append(Paragraph(foreign_text, self.styles['SmallBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_best_practices(self, elements):
        """Add best practices section"""
        elements.append(Paragraph('<b>INVESTIGATION BEST PRACTICES</b>', self.styles['CustomHeading']))

        practices = [
            "<b>Download PDF Immediately:</b> Always download the PDF report right after investigation for permanent documentation",
            "<b>Record Evidence Hash:</b> Note the SHA-256 hash in your case file for chain of custody",
            "<b>Verify with Carrier:</b> For serious cases, request subscriber details from carrier (may require court order)",
            "<b>Request Call Data Records:</b> Obtain CDR (Call Data Records) with court authorization for call history",
            "<b>Cross-Reference:</b> Compare phone number findings with other investigation evidence",
            "<b>Monitor VoIP Carefully:</b> VoIP numbers require extra verification steps",
            "<b>International Cooperation:</b> For foreign numbers, follow Interpol protocols",
            "<b>Legal Authority:</b> Real-time location tracking requires judicial approval"
        ]

        for practice in practices:
            elements.append(Paragraph(f"• {practice}", self.styles['CustomBody']))

        elements.append(Spacer(1, 0.2*inch))

    def _add_legal_considerations(self, elements):
        """Add legal section"""
        elements.append(Paragraph('<b>LEGAL & PRIVACY CONSIDERATIONS</b>', self.styles['CustomHeading']))

        legal_text = """
        <b>Important Legal Requirements:</b>
        <br/>• Subscriber information requests require proper legal authority
        <br/>• Call data records (CDR) require court order
        <br/>• Real-time location tracking requires judicial approval
        <br/>• International numbers may require mutual legal assistance treaties
        <br/>• Always follow Zambia Police Service protocols and procedures
        <br/>• Maintain proper chain of custody documentation
        <br/>• Document all investigative steps in case file
        <br/><br/>
        <b>Privacy Protection:</b> All investigations are logged with full audit trail.
        Misuse of this tool for unauthorized surveillance is strictly prohibited and
        may result in criminal prosecution.
        """
        elements.append(Paragraph(legal_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.2*inch))

    def _add_footer(self, elements):
        """Add guide footer"""
        elements.append(Spacer(1, 0.3*inch))

        footer_text = """
        <b>For Technical Support:</b> Contact CyberTrace Support Team
        <br/><b>For Training:</b> Cybercrime Investigation Unit - Training Department
        <br/><br/>
        <i>This document is for official Zambia Police Service use only.
        Unauthorized distribution is prohibited.</i>
        """
        elements.append(Paragraph(footer_text, self.styles['SmallBody']))

    def generate(self, output_path):
        """
        Generate the PDF guide

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
        self._add_introduction(elements)
        self._add_getting_started(elements)

        elements.append(PageBreak())

        self._add_understanding_results(elements)
        self._add_fraud_indicators(elements)

        elements.append(PageBreak())

        self._add_best_practices(elements)
        self._add_legal_considerations(elements)
        self._add_footer(elements)

        # Build PDF
        doc.build(elements)

        return output_path
