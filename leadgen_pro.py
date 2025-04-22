import streamlit as st
import pandas as pd
import smtplib
import time
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
import pytz
import dns.resolver
import re
import socket
import hashlib
import os
from dotenv import load_dotenv
import plotly.express as px
from streamlit_tags import st_tags
from streamlit_extras.stylable_container import stylable_container

# Load environment variables
load_dotenv()

# Constants
TZ = pytz.timezone('Asia/Kolkata')
MAX_SAFE_DAILY = 200
VERSION = "3.0.0"

# ========== SERVICE TEMPLATES ==========
SERVICES = {
    'web_development': {
        'name': 'Web Development',
        'subject': 'Custom Web Solution for {business}',
        'text': """Dear {first_name},

I noticed {business} could benefit from:
✓ 3x faster website performance
✓ Mobile-optimized design
✓ Secure payment gateways

We helped {similar_business} increase conversions by 65%.

Free technical audit: {link}/web-audit

Best,
{your_name}""",
        'html': """<html><body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Custom Web Solution</h2>
                <p>Dear {first_name},</p>
                <p>I noticed {business} could benefit from:</p>
                <ul style="list-style-type: none; padding-left: 0;">
                    <li style="margin-bottom: 10px;">✓ 3x faster website performance</li>
                    <li style="margin-bottom: 10px;">✓ Mobile-optimized design</li>
                    <li style="margin-bottom: 10px;">✓ Secure payment gateways</li>
                </ul>
                <p>We helped {similar_business} increase conversions by 65%.</p>
                <p><a href="{link}/web-audit" style="background-color: #3498db; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px; display: inline-block;">Get Free Audit</a></p>
                <p>Best,<br>{your_name}</p>
            </div>
        </body></html>"""
    }
}

class AuthManager:
    def __init__(self):
        self.token = None
        
    def authenticate(self, email, password):
        if email and password:
            self.token = hashlib.sha256(f"{email}{password}".encode()).hexdigest()
            st.session_state.auth_token = self.token
            return True
        return False
    
    def check_auth(self):
        return bool(st.session_state.get('auth_token'))

class EmailValidator:
    @staticmethod
    def validate(email):
        """Advanced email validation with multiple checks"""
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            return False
            
        domain = email.split('@')[1]
        disposable_domains = ['mailinator.com', 'tempmail.com']
        if any(domain in email for domain in disposable_domains):
            return False
            
        try:
            dns.resolver.resolve(domain, 'MX')
            return True
        except:
            return False

class CampaignEngine:
    def __init__(self):
        self.sent_log = []
        self.case_studies = {
            'web_development': ['TechSolutions Inc', 'DigitalCraft LLC']
        }
    
    def send_email(self, lead, service_key, config):
        service = SERVICES[service_key]
        
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{config['your_name']} <{config['email']}>"
        msg['To'] = lead['email']
        msg['Subject'] = service['subject'].format(business=lead.get('business', 'your business'))
        
        text = service['text'].format(
            first_name=lead.get('first_name', 'there'),
            business=lead.get('business', 'your business'),
            similar_business=random.choice(self.case_studies[service_key]),
            link=config['website'],
            your_name=config['your_name']
        )
        
        html = service['html'].format(
            first_name=lead.get('first_name', 'there'),
            business=lead.get('business', 'your business'),
            similar_business=random.choice(self.case_studies[service_key]),
            link=config['website'],
            your_name=config['your_name']
        )
        
        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        
        try:
            with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
                server.starttls()
                server.login(config['email'], config['app_password'])
                server.sendmail(config['email'], [lead['email']], msg.as_string())
            
            log_entry = {
                'email': lead['email'],
                'time': datetime.now(TZ),
                'service': service_key,
                'status': 'success'
            }
            self.sent_log.append(log_entry)
            return True
        except Exception as e:
            self.sent_log.append({
                'email': lead['email'],
                'time': datetime.now(TZ),
                'service': service_key,
                'status': f'failed: {str(e)}'
            })
            return False

class LeadGenDashboard:
    def __init__(self):
        st.set_page_config(
            page_title="LeadGen Pro",
            page_icon="🚀",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        self.auth = AuthManager()
        if not self.auth.check_auth():
            self.show_login()
            return
            
        self.engine = CampaignEngine()
        self.config = self.load_config()
        self.setup_ui()
    
    def handle_login(self):
        email = st.session_state.get("login_email")
        password = st.session_state.get("login_password")
        
        if email and password:
            if self.auth.authenticate(email, password):
                st.rerun()
            else:
                st.error("Invalid credentials")
    
    def show_login(self):
        """Modern login screen"""
        with stylable_container(
            key="login_container",
            css_styles="""
                {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
            """
        ):
            col1, col2, col3 = st.columns([1, 3, 1])
            with col2:
                with stylable_container(
                    key="login_box",
                    css_styles="""
                        {
                            background: rgba(255, 255, 255, 0.95);
                            padding: 2rem;
                            border-radius: 10px;
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                        }
                    """
                ):
                    st.markdown("<h1 style='text-align: center; color: #2c3e50;'>LeadGen Pro</h1>", unsafe_allow_html=True)
                    
                    with st.form("login_form"):
                        st.text_input("Email", key="login_email")
                        st.text_input("Password", type="password", key="login_password")
                        
                        if st.form_submit_button("Login", use_container_width=True):
                            self.handle_login()
                    
                    st.markdown(f"<p style='text-align: center; color: #7f8c8d;'>Version {VERSION}</p>", unsafe_allow_html=True)
    
    def load_config(self):
        """Load configuration from env or session state"""
        if 'config' not in st.session_state:
            st.session_state.config = {
                'email': os.getenv('ZOHO_EMAIL', 'your@email.com'),
                'app_password': os.getenv('ZOHO_APP_PASSWORD', ''),
                'your_name': os.getenv('YOUR_NAME', 'Your Name'),
                'website': os.getenv('WEBSITE', 'https://yourwebsite.com'),
                'smtp_server': 'smtp.zoho.com',
                'smtp_port': 587,
                'daily_limit': 100,
                'timezone': 'Asia/Kolkata'
            }
        return st.session_state.config
    
    def setup_ui(self):
        """Main application interface"""
        st.title("🚀 LeadGen Pro")
        
        with st.sidebar:
            st.image("https://via.placeholder.com/150x50?text=LeadGen+Pro", use_column_width=True)
            st.markdown("---")
            st.metric("Total Sent", len(self.engine.sent_log))
            st.markdown("---")
            
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()
            
            if st.button("🚪 Logout", use_container_width=True):
                del st.session_state.auth_token
                st.rerun()
        
        tab1, tab2, tab3 = st.tabs(["📤 Campaign", "📊 Analytics", "⚙️ Settings"])
        
        with tab1:
            self.campaign_tab()
        with tab2:
            self.analytics_tab()
        with tab3:
            self.settings_tab()
    
    def campaign_tab(self):
        """Campaign management interface"""
        st.subheader("Launch New Campaign")
        
        uploaded_file = st.file_uploader("📁 Upload Leads CSV", type=['csv'], help="CSV must contain at least an 'email' column")
        
        if uploaded_file:
            try:
                leads_df = pd.read_csv(uploaded_file)
                
                if 'email' not in leads_df.columns:
                    st.error("CSV must contain an 'email' column")
                    return
                
                st.success(f"✅ Loaded {len(leads_df)} leads")
                
                with st.expander("👀 Preview Data"):
                    st.dataframe(leads_df.head(3))
                
                service_key = st.selectbox(
                    "✉️ Select Email Template",
                    options=list(SERVICES.keys()),
                    format_func=lambda x: SERVICES[x]['name'],
                    help="Choose which email template to use"
                )
                
                with st.expander("⚡ Advanced Settings"):
                    delay = st.slider("Delay between emails (seconds)", 1, 10, 3)
                    self.config['daily_limit'] = st.slider("Daily send limit", 10, MAX_SAFE_DAILY, 100)
                
                if st.button("🔥 Launch Campaign", type="primary", use_container_width=True):
                    with st.spinner("Validating emails..."):
                        valid_leads = leads_df[leads_df['email'].apply(EmailValidator.validate)]
                        invalid_count = len(leads_df) - len(valid_leads)
                        
                        if invalid_count > 0:
                            st.warning(f"Filtered out {invalid_count} invalid emails")
                    
                    if len(valid_leads) > 0:
                        self.run_campaign(service_key, valid_leads, delay)
                    else:
                        st.error("No valid emails found in the uploaded file")
            
            except Exception as e:
                st.error(f"Error processing CSV: {str(e)}")
    
    def run_campaign(self, service_key, leads_df, delay):
        """Execute email campaign"""
        total_emails = min(len(leads_df), self.config['daily_limit'])
        progress_bar = st.progress(0)
        status_text = st.empty()
        results = []
        
        for i, (_, lead) in enumerate(leads_df.head(total_emails).iterrows()):
            success = self.engine.send_email(lead.to_dict(), service_key, self.config)
            results.append(success)
            
            progress = (i + 1) / total_emails
            progress_bar.progress(progress)
            status_text.text(f"Sending {i+1}/{total_emails} - {lead['email']}")
            
            time.sleep(delay)
        
        success_rate = sum(results)/len(results)*100
        st.success(f"""
        ## 🎉 Campaign Complete!
        - **Total Sent:** {len(results)}
        - **Success Rate:** {success_rate:.1f}%
        - **Failed Attempts:** {len(results) - sum(results)}
        """)
        
        # Download log
        log_df = pd.DataFrame(self.engine.sent_log)
        st.download_button(
            label="📥 Download Campaign Log",
            data=log_df.to_csv(index=False),
            file_name=f"campaign_log_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            use_container_width=True
        )
    
    def analytics_tab(self):
        """Campaign performance analytics"""
        st.subheader("Campaign Analytics")
        
        if not self.engine.sent_log:
            st.info("No campaign data yet. Run a campaign to see analytics.")
            return
        
        log_df = pd.DataFrame(self.engine.sent_log)
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Sent", len(log_df))
        col2.metric("Success Rate", f"{len(log_df[log_df['status'] == 'success'])/len(log_df)*100:.1f}%")
        col3.metric("Unique Services", log_df['service'].nunique())
        
        st.subheader("Performance Over Time")
        daily_stats = log_df.groupby(log_df['time'].dt.date).agg({
            'email': 'count',
            'status': lambda x: (x == 'success').mean()
        }).rename(columns={'email': 'count', 'status': 'success_rate'})
        
        fig = px.line(daily_stats, 
                     title="Daily Email Performance",
                     labels={'value': 'Count', 'variable': 'Metric'},
                     height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    def settings_tab(self):
        """System configuration"""
        st.subheader("Settings")
        
        with st.form("config_form"):
            st.markdown("### SMTP Configuration")
            self.config['email'] = st.text_input("Zoho Email", self.config['email'])
            self.config['app_password'] = st.text_input("Zoho App Password", type="password", value=self.config['app_password'])
            
            st.markdown("### Campaign Settings")
            self.config['your_name'] = st.text_input("Your Name", self.config['your_name'])
            self.config['website'] = st.text_input("Website URL", self.config['website'])
            self.config['daily_limit'] = st.slider("Daily Email Limit", 10, MAX_SAFE_DAILY, self.config['daily_limit'])
            
            if st.form_submit_button("💾 Save Settings"):
                st.success("Settings saved!")
                
                # Test SMTP connection
                with st.spinner("Testing SMTP connection..."):
                    if self.test_smtp_connection():
                        st.success("✅ SMTP connection successful!")
                    else:
                        st.error("❌ SMTP connection failed")
    
    def test_smtp_connection(self):
        """Test SMTP connection to Zoho"""
        try:
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['email'], self.config['app_password'])
            return True
        except Exception as e:
            st.error(f"SMTP Error: {str(e)}")
            return False

if __name__ == "__main__":
    LeadGenDashboard()