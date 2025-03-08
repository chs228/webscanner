import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PreformattedText
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO

# --- Vulnerability Payloads (same as before) ---
SQLI_PAYLOADS = ["'", "\"", "--", ";", "OR 1=1", "OR 1=1--"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>"]


# --- Scanning Functions (same as before -  copy from the previous code) ---
def scan_page(url, base_url):
    vulnerabilities = {"sqli": [], "xss": []}
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            form_details = get_form_details(form, url)
            if form_details:
                for payload in SQLI_PAYLOADS:
                    is_sqli_vulnerable, sqli_details = test_sqli(form_details, url, payload)
                    if is_sqli_vulnerable:
                        vulnerabilities["sqli"].append(sqli_details)
                for payload in XSS_PAYLOADS:
                    is_xss_vulnerable, xss_details = test_xss(form_details, url, payload)
                    if is_xss_vulnerable:
                        vulnerabilities["xss"].append(xss_details)
    except requests.exceptions.RequestException as e:
        st.error(f"Error accessing {url}: {e}") # Use st.error for Streamlit error display
    return vulnerabilities

def get_form_details(form, page_url):
    details = {}
    try:
        action = form.attrs.get("action").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details["action"] = urljoin(page_url, action) if action else page_url
        details["method"] = method
        details["inputs"] = inputs
        return details
    except AttributeError:
        st.warning(f"Warning: Could not fully parse form on {page_url}. Form might be incomplete or malformed.") # st.warning for Streamlit warning
        return None

def test_sqli(form_details, page_url, payload):
    data = {}
    for input_detail in form_details["inputs"]:
        if input_detail["name"]:
            data[input_detail["name"]] = payload
        else:
            pass
    try:
        if form_details["method"] == "post":
            response = requests.post(form_details["action"], data=data, timeout=10)
        else:
            response = requests.get(form_details["action"], params=data, timeout=10)
        response.raise_for_status()
        sqli_error_keywords = ["sql", "mysql", "error", "syntax", "database", "oracle", "msql", "sqlexception"]
        if any(keyword in response.text.lower() for keyword in sqli_error_keywords):
            return True, {
                "type": "SQL Injection",
                "url": page_url,
                "form_details": form_details,
                "payload_used": payload,
                "response_status": response.status_code,
                "response_text": response.text[:500] + "..." if len(response.text) > 500 else response.text
            }
    except requests.exceptions.RequestException as e:
        st.error(f"Request error during SQLi test on {page_url}: {e}") # st.error
    return False, None

def test_xss(form_details, page_url, payload):
    data = {}
    for input_detail in form_details["inputs"]:
        if input_detail["name"]:
            data[input_detail["name"]] = payload
        else:
            pass
    try:
        if form_details["method"] == "post":
            response = requests.post(form_details["action"], data=data, timeout=10)
        else:
            response = requests.get(form_details["action"], params=data, timeout=10)
        response.raise_for_status()
        if payload in response.text:
            return True, {
                "type": "Reflected XSS",
                "url": page_url,
                "form_details": form_details,
                "payload_used": payload,
                "response_status": response.status_code,
                "response_text": response.text[:500] + "..." if len(response.text) > 500 else response.text
            }
    except requests.exceptions.RequestException as e:
        st.error(f"Request error during XSS test on {page_url}: {e}") # st.error
    return False, None

def get_all_links(url):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    links = set()
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = urljoin(base_url, href)
            if base_url in absolute_url:
                links.add(absolute_url)
    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching links from {url}: {e}") # st.error
    return links


# --- Report Generation for PDF (Modified for Streamlit and BytesIO) ---
def generate_report_pdf(target_url, vulnerabilities):
    buffer = BytesIO() # Use BytesIO to create PDF in memory
    doc = SimpleDocTemplate(buffer, pagesize=letter) # DocTemplate to buffer
    styles = getSampleStyleSheet()
    Story = []

    # --- Report Content (same as before, but using reportlab objects) ---
    Story.append(Paragraph(f"<b>Security Scan Report for: {target_url}</b>", styles['h1']))
    Story.append(Spacer(1, 0.2*inch))
    Story.append(Paragraph(f"This report summarizes the security scan conducted on the website: <b>{target_url}</b>. "
                           f"The scan focused on detecting common web vulnerabilities, specifically SQL Injection and Cross-Site Scripting (XSS).",
                           styles['Normal']))
    Story.append(Spacer(1, 0.1*inch))

    if not vulnerabilities["sqli"] and not vulnerabilities["xss"]:
        Story.append(Paragraph("<b>Scan Summary: No High Severity Vulnerabilities Detected</b>", styles['h2']))
        Story.append(Paragraph("During this scan, no immediate SQL Injection or Cross-Site Scripting (XSS) vulnerabilities were detected. "
                               "This is a positive finding, but it's important to remember that this scan is not exhaustive and only covers "
                               "a limited set of vulnerability types.  Continuous security monitoring and more comprehensive testing are recommended.",
                               styles['Normal']))
        Story.append(Spacer(1, 0.2*inch))
    else:
        Story.append(Paragraph("<b>Scan Summary: Vulnerabilities Detected</b>", styles['h2']))
        Story.append(Paragraph("The security scan identified the following potential vulnerabilities. Please review the details below and take immediate action to remediate them.", styles['Normal']))
        Story.append(Spacer(1, 0.2*inch))

    if vulnerabilities["sqli"]:
        Story.append(Paragraph("<b>SQL Injection Vulnerabilities Found (Severity: High)</b>", styles['h2']))
        Story.append(Paragraph("SQL Injection vulnerabilities can allow attackers to directly interact with your database, potentially leading to data theft, modification, or complete system compromise. Immediate remediation is critical.", styles['Normal']))
        Story.append(Spacer(1, 0.1*inch))
        for vuln in vulnerabilities["sqli"]:
            Story.append(Paragraph(f"  - <b>URL:</b> {vuln['url']}", styles['Normal']))
            Story.append(Paragraph(f"    <b>Form Action:</b> {vuln['form_details']['action']}", styles['Normal']))
            Story.append(Paragraph(f"    <b>Method:</b> {vuln['form_details']['method']}", styles['Normal']))
            Story.append(Paragraph(f"    <b>Payload Used:</b> {vuln['payload_used']}", styles['Normal']))
            Story.append(Paragraph(f"    <b>Response Status:</b> {vuln['response_status']}", styles['Normal']))
            Story.append(PreformattedText(f"    Response Snippet:\n{vuln['response_text']}", styles['Code'])) # PreformattedText for code-like snippet
            Story.append(Spacer(1, 0.05*inch))
            Story.append(Paragraph("    <b>Recommendation:</b> Use parameterized queries or prepared statements for database interactions. Validate and sanitize all user inputs. Implement the principle of least privilege for database access.", styles['Italic']))
            Story.append(Spacer(1, 0.1*inch))

    if vulnerabilities["xss"]:
        Story.append(Paragraph("<b>Cross-Site Scripting (XSS) Vulnerabilities Found (Severity: Medium)</b>", styles['h2']))
        Story.append(Paragraph("XSS vulnerabilities can allow attackers to inject malicious scripts into your website, potentially stealing user credentials, redirecting users to malicious sites, or defacing your website. Remediation is important to protect user security.", styles['Normal']))
        Story.append(Spacer(1, 0.1*inch))
        for vuln in vulnerabilities["xss"]:
            Story.append(Paragraph(f"  - <b>URL:</b> {vuln['url']}", styles['Normal']))
            Story.append(Paragraph(f"    <b>Form Action:</b> {vuln['form_details']['action']}", styles['Normal']))
            Story.append(Paragraph(f"    <b>Method:</b> {vuln['form_details']['method']}", styles['Normal']))
            Story.append(Paragraph(f"    <b>Payload Used:</b> {vuln['payload_used']}", styles['Normal']))
            Story.append(Paragraph(f"    <b>Response Status:</b> {vuln['response_status']}", styles['Normal']))
            Story.append(PreformattedText(f"    Response Snippet:\n{vuln['response_text']}", styles['Code'])) # PreformattedText
            Story.append(Spacer(1, 0.05*inch))
            Story.append(Paragraph("    <b>Recommendation:</b> Implement proper input encoding and output escaping. Use Content Security Policy (CSP) headers to mitigate XSS risks. Regularly review and update your website's code.", styles['Italic']))
            Story.append(Spacer(1, 0.1*inch))

    Story.append(Paragraph("<b>General Web Security Best Practices</b>", styles['h2']))
    Story.append(Paragraph("Regardless of the findings of this scan, consider these general security best practices to improve the overall security posture of your web application:", styles['Normal']))
    Story.append(Spacer(1, 0.1*inch))
    Story.append(Paragraph("  - <b>Stay Updated:</b> Regularly update all software components, including web frameworks, libraries, and server software, to patch known vulnerabilities.", styles['Bullet']))
    Story.append(Paragraph("  - <b>Input Validation:</b> Implement robust input validation on both the client-side and server-side to prevent injection attacks.", styles['Bullet']))
    Story.append(Paragraph("  - <b>Secure Authentication and Authorization:</b> Use strong authentication mechanisms and enforce proper authorization to control access to resources.", styles['Bullet']))
    Story.append(Paragraph("  - <b>Regular Security Audits:</b> Conduct regular security audits and penetration testing by security professionals to identify and address vulnerabilities proactively.", styles['Bullet']))
    Story.append(Paragraph("  - <b>Security Awareness Training:</b> Train developers and staff on secure coding practices and common web security vulnerabilities.", styles['Bullet']))
    Story.append(Spacer(1, 0.2*inch))

    Story.append(Paragraph("<b>Important Disclaimer and Limitations</b>", styles['h2']))
    Story.append(Paragraph("This security scan was performed using a basic automated scanner and is intended for preliminary vulnerability assessment only.  "
                           "It is not a substitute for a comprehensive security audit or penetration testing by experienced security professionals. ", styles['Normal']))
    Story.append(Paragraph("<b>Limitations:</b>", styles['Normal']))
    Story.append(Paragraph("  - <b>Limited Scope:</b> This scan focused primarily on SQL Injection and Cross-Site Scripting (XSS) vulnerabilities and may not detect other types of vulnerabilities (e.g., Broken Access Control, CSRF, etc.).", styles['Bullet']))
    Story.append(Paragraph("  - <b>Basic Payloads:</b> The scanner uses a limited set of basic payloads. More sophisticated attacks may not be detected.", styles['Bullet']))
    Story.append(Paragraph("  - <b>False Positives/Negatives:</b> Automated scanners can produce false positives (reporting vulnerabilities that are not actually present) and false negatives (missing real vulnerabilities).", styles['Bullet']))
    Story.append(Paragraph("  - <b>Website Complexity:</b> The effectiveness of the scanner may vary depending on the complexity and structure of the target website.", styles['Bullet']))
    Story.append(Spacer(1, 0.2*inch))
    Story.append(Paragraph("<b>Recommendation:</b> For a thorough security assessment, it is highly recommended to engage professional security experts to conduct a comprehensive penetration test and security audit.", styles['Normal']))


    doc.build(Story)
    pdf_data = buffer.getvalue() # Get PDF content as bytes
    buffer.close()
    return pdf_data


# --- Streamlit App ---
def main_streamlit():
    st.title("Web Application Security Scanner")
    st.markdown("A basic scanner for SQL Injection and XSS vulnerabilities (Educational Purposes)")
    st.markdown("---")

    st.warning("⚠️ **Ethical and Legal Warning:**  Scanning websites without explicit, written permission is illegal and unethical. This tool is for educational and authorized security testing ONLY. Use responsibly and only on websites you have permission to test.")
    st.markdown("---")

    target_url = st.text_input("Enter Target Website URL:", placeholder="https://example.com")
    email_address = st.text_input("Optional: Enter your email for report (or leave blank to download only):", placeholder="your_email@example.com")

    if st.button("Start Scan"):
        if not target_url:
            st.error("Please enter a target URL.")
            return

        parsed_target_url = urlparse(target_url)
        if not parsed_target_url.scheme:
            target_url = "http://" + target_url

        base_url = f"{parsed_target_url.scheme}://{parsed_target_url.netloc}"
        pages_to_scan = set([target_url])
        scanned_pages = set()
        all_vulnerabilities = {"sqli": [], "xss": []}
        scan_status = st.empty() # Placeholder for scan status messages

        with st.spinner(text="Scanning website... Please wait..."):
            while pages_to_scan:
                current_url = pages_to_scan.pop()
                if current_url in scanned_pages:
                    continue

                scan_status.text(f"Scanning page: {current_url}") # Update status
                page_vulnerabilities = scan_page(current_url, base_url)
                all_vulnerabilities["sqli"].extend(page_vulnerabilities["sqli"])
                all_vulnerabilities["xss"].extend(page_vulnerabilities["xss"])
                scanned_pages.add(current_url)

                new_links = get_all_links(current_url)
                pages_to_scan.update(new_links - scanned_pages)

        scan_status.empty() # Clear status message when scan is done
        st.success("Scan completed!")

        st.subheader("Scan Summary")
        if not all_vulnerabilities["sqli"] and not all_vulnerabilities["xss"]:
            st.write("No SQL Injection or XSS vulnerabilities found.")
        else:
            if all_vulnerabilities["sqli"]:
                st.warning(f"SQL Injection vulnerabilities found: {len(all_vulnerabilities['sqli'])}")
            if all_vulnerabilities["xss"]:
                st.warning(f"XSS vulnerabilities found: {len(all_vulnerabilities['xss'])}")

        # --- Vulnerability Details Expander ---
        if all_vulnerabilities["sqli"] or all_vulnerabilities["xss"]:
            with st.expander("Vulnerability Details (Click to expand)"):
                if all_vulnerabilities["sqli"]:
                    st.markdown("#### SQL Injection Vulnerabilities:")
                    for vuln in all_vulnerabilities["sqli"]:
                        st.markdown(f"**URL:** {vuln['url']}")
                        st.write(f"- **Form Action:** {vuln['form_details']['action']}")
                        st.write(f"- **Method:** {vuln['form_details']['method']}")
                        st.write(f"- **Payload:** `{vuln['payload_used']}`") # Use code style for payload
                        st.write(f"- **Response Status:** {vuln['response_status']}")
                        st.code(f"Response Snippet:\n{vuln['response_text']}", language=None) # Use st.code
                        st.markdown("---")

                if all_vulnerabilities["xss"]:
                    st.markdown("#### XSS Vulnerabilities:")
                    for vuln in all_vulnerabilities["xss"]:
                        st.markdown(f"**URL:** {vuln['url']}")
                        st.write(f"- **Form Action:** {vuln['form_details']['action']}")
                        st.write(f"- **Method:** {vuln['form_details']['method']}")
                        st.write(f"- **Payload:** `{vuln['payload_used']}`") # Code style
                        st.write(f"- **Response Status:** {vuln['response_status']}")
                        st.code(f"Response Snippet:\n{vuln['response_text']}", language=None) # st.code
                        st.markdown("---")

        # --- Generate and Offer PDF Report Download ---
        pdf_report = generate_report_pdf(target_url, all_vulnerabilities)
        st.download_button(
            label="Download PDF Report",
            data=pdf_report,
            file_name="security_scan_report.pdf",
            mime="application/pdf"
        )

        # --- Email Report (Optional -  Still needs email config to work fully) ---
        if email_address:
            st.info("Email functionality (sending report via email) is not fully implemented in this Streamlit version due to credential security concerns. Download the PDF and send it manually if needed.")
            # To enable email, you would need to securely handle credentials (e.g., Streamlit secrets or user input - carefully!)
            # and uncomment/adapt the send_email function and call it here.

    st.markdown("---")
    st.info("This Streamlit application provides a basic web security scan for educational purposes. For comprehensive security assessments, consult with security professionals and use dedicated security testing tools.")


if __name__ == "__main__":
    main_streamlit()
