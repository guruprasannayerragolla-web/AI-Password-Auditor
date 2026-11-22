import json
import csv
from io import StringIO, BytesIO
from typing import Dict, Any, List

HAS_REPORTLAB = False
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    pass

def export_as_json(audit_data: Dict[str, Any]) -> str:
    """
    Exports the audit results as a formatted JSON string.
    """
    return json.dumps(audit_data, indent=4)

def export_as_csv(audit_data: Dict[str, Any]) -> str:
    """
    Exports the key audit findings as a single-row CSV spreadsheet representation.
    """
    output = StringIO()
    writer = csv.writer(output)
    
    headers = [
        "Security Score", "Shannon Entropy", "Effective Entropy", "Risk Level", 
        "Classification", "Dictionary Match", "Keyboard Patterns Count", 
        "Personal Info Exposed", "Crack Time Formatted", "ML Risk Level"
    ]
    
    # Flatten patterns & exposures
    patterns_count = len(audit_data.get("patterns_detected", []))
    pi_exposed = len(audit_data.get("personal_info_exposed", []))
    
    row = [
        audit_data.get("security_score"),
        audit_data.get("entropy_score"),
        audit_data.get("effective_entropy"),
        audit_data.get("risk_level"),
        audit_data.get("classification"),
        "Yes" if audit_data.get("dictionary_matched") else "No",
        patterns_count,
        pi_exposed,
        audit_data.get("crack_time_formatted"),
        audit_data.get("ml_risk_prediction")
    ]
    
    writer.writerow(headers)
    writer.writerow(row)
    return output.getvalue()

def generate_pdf_report(audit_data: Dict[str, Any]) -> BytesIO:
    """
    Compiles a highly professional PDF Audit Report using ReportLab.
    Returns a BytesIO stream containing the PDF document.
    """
    if not HAS_REPORTLAB:
        raise ImportError(
            "ReportLab library is not installed. Please run 'pip install reportlab' to enable PDF generation."
        )
        
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=25
    )
    
    h2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=15,
        spaceAfter=10
    )
    
    body_style = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#334155'),
        leading=14,
        spaceAfter=8
    )
    
    bullet_style = ParagraphStyle(
        'BulletText',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=5
    )
    
    story = []
    
    # Header Title Banner
    story.append(Paragraph("AI Password Auditor - Security Report", title_style))
    story.append(Paragraph("Intelligent Cryptographic Assessment & ML Risk Prediction System", subtitle_style))
    
    # Section 1: Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    
    score = audit_data.get("security_score", 0)
    risk = audit_data.get("risk_level", "MEDIUM")
    
    # Define score color block
    if score >= 80:
        score_color = "#10B981" # Green
    elif score >= 50:
        score_color = "#F59E0B" # Orange
    else:
        score_color = "#EF4444" # Red
        
    summary_text = (
        f"This security assessment evaluated the submitted password strength and predicted its vulnerability "
        f"against state-of-the-art hacking systems. The overall Security Score is <b>{score}/100</b>, "
        f"yielding a threat rating of <b>{risk}</b>. The assessment is based on combining "
        f"Shannon Entropy calculations with pattern detection heuristics and Random Forest machine learning models."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))
    
    # Key metrics table
    data = [
        [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Value / Analysis Output</b>", body_style)],
        [Paragraph("Security Score", body_style), Paragraph(f"<font color='{score_color}'><b>{score}/100</b></font>", body_style)],
        [Paragraph("Shannon Entropy", body_style), Paragraph(f"{audit_data.get('entropy_score')} bits", body_style)],
        [Paragraph("Effective Entropy", body_style), Paragraph(f"{audit_data.get('effective_entropy')} bits ({audit_data.get('classification')})", body_style)],
        [Paragraph("Estimated Crack Time (GPU)", body_style), Paragraph(f"{audit_data.get('crack_time_formatted')}", body_style)],
        [Paragraph("ML Risk Prediction", body_style), Paragraph(f"<b>{audit_data.get('ml_risk_prediction')}</b> (Confidence: {round(audit_data.get('ml_confidence', 0)*100, 1)}%)", body_style)]
    ]
    
    table = Table(data, colWidths=[200, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (1,0), colors.HexColor('#F8FAFC')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
    ]))
    
    story.append(table)
    story.append(Spacer(1, 15))
    
    # Section 2: Vulnerability Analysis
    story.append(Paragraph("2. Threat & Vulnerability Findings", h2_style))
    story.append(Paragraph("The analysis engine evaluated the password against several distinct threat patterns:", body_style))
    
    # Dictionary Match
    dict_status = "<b>Vulnerable</b>: Password contains a dictionary term or derivative." if audit_data.get("dictionary_matched") else "<b>Secure</b>: No dictionary patterns matched."
    story.append(Paragraph(f"&bull; <b>Dictionary Check</b>: {dict_status}", bullet_style))
    
    # Patterns
    patterns = audit_data.get("patterns_detected", [])
    if patterns:
        patterns_str = ", ".join([f"{p['pattern_type']} ('{p['pattern_value']}')" for p in patterns])
        story.append(Paragraph(f"&bull; <b>Detected Patterns</b>: Vulnerable structures found: {patterns_str}", bullet_style))
    else:
        story.append(Paragraph("&bull; <b>Detected Patterns</b>: No sequences, keyboard walks, or repetitions detected.", bullet_style))
        
    # Personal Info Exposure
    pi_exposures = audit_data.get("personal_info_exposed", [])
    if pi_exposures:
        exps_str = ", ".join([f"{e['field_exposed']} match ('{e['matched_substring']}')" for e in pi_exposures])
        story.append(Paragraph(f"&bull; <b>Identity Leakage</b>: Password leaks personal profile data: {exps_str}", bullet_style))
    else:
        story.append(Paragraph("&bull; <b>Identity Leakage</b>: No matches against personal details (name, email, organization).", bullet_style))
        
    # XAI Text
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Explainable AI (XAI) Insight:</b>", body_style))
    story.append(Paragraph(f"<i>{audit_data.get('xai_explanation')}</i>", body_style))
    
    story.append(Spacer(1, 15))
    
    # Section 3: Remediation & Recommendations
    story.append(Paragraph("3. Actionable Security Recommendations", h2_style))
    story.append(Paragraph("Implement the following checklist to secure this password:", body_style))
    
    recommendations = audit_data.get("recommendations", [])
    if recommendations:
        for r in recommendations:
            story.append(Paragraph(f"&bull; [{r['priority']}] {r['recommendation_text']}", bullet_style))
    else:
        story.append(Paragraph("&bull; The password matches security guidelines. Keep practicing safe storage using a password manager.", bullet_style))
        
    # Build Document
    doc.build(story)
    buffer.seek(0)
    return buffer
