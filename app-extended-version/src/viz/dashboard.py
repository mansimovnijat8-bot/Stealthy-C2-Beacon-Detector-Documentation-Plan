# src/viz/dashboard.py
#!/usr/bin/env python3
"""
Real-time C2 Detection Dashboard
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import time
from pathlib import Path
import logging
from typing import Dict, List, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('Dashboard')

class C2Dashboard:
    def __init__(self):
        self.alert_file = "data/alerts/c2_alerts.json"
        self.log_file = "data/logs/c2_detector.log"
        self.config_file = "config.json"
        
        # Ensure directories exist
        Path("data/alerts").mkdir(parents=True, exist_ok=True)
        Path("data/logs").mkdir(parents=True, exist_ok=True)
        
        # Initialize session state
        if 'last_update' not in st.session_state:
            st.session_state.last_update = datetime.now()
        if 'alerts_data' not in st.session_state:
            st.session_state.alerts_data = []
        if 'log_data' not in st.session_state:
            st.session_state.log_data = []
    
    def load_alerts(self) -> List[Dict]:
        """Load alerts from JSON file"""
        alerts = []
        try:
            if Path(self.alert_file).exists():
                with open(self.alert_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            alert = json.loads(line.strip())
                            alerts.append(alert)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Error loading alerts: {e}")
        
        return alerts
    
    def load_logs(self) -> List[Dict]:
        """Load logs from log file"""
        logs = []
        try:
            if Path(self.log_file).exists():
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        logs.append(line.strip())
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
        
        return logs[-100:]  # Last 100 lines
    
    def load_config(self) -> Dict:
        """Load configuration"""
        try:
            if Path(self.config_file).exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
        return {}
    
    def create_alert_summary(self, alerts: List[Dict]) -> Dict:
        """Create alert summary statistics"""
        summary = {
            'total': len(alerts),
            'by_severity': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'by_type': {},
            'by_protocol': {'dns': 0, 'http': 0, 'conn': 0, 'ssl': 0},
            'recent_alerts': []
        }
        
        for alert in alerts:
            # Severity count
            severity = alert.get('severity', 'UNKNOWN')
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
            
            # Alert type count
            alert_type = alert.get('alert_type', 'UNKNOWN')
            summary['by_type'][alert_type] = summary['by_type'].get(alert_type, 0) + 1
            
            # Protocol count
            log_type = alert.get('log_type', 'unknown')
            if log_type in summary['by_protocol']:
                summary['by_protocol'][log_type] += 1
            
            # Recent alerts (last 24 hours)
            alert_time = alert.get('timestamp')
            if alert_time:
                if isinstance(alert_time, str):
                    alert_time = datetime.fromisoformat(alert_time.replace('Z', ''))
                if datetime.now() - alert_time < timedelta(hours=24):
                    summary['recent_alerts'].append(alert)
        
        return summary
    
    def create_severity_chart(self, severity_data: Dict):
        """Create severity pie chart"""
        fig = px.pie(
            values=list(severity_data.values()),
            names=list(severity_data.keys()),
            title='Alert Severity Distribution',
            color=list(severity_data.keys()),
            color_discrete_map={'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'green'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    def create_protocol_chart(self, protocol_data: Dict):
        """Create protocol bar chart"""
        fig = px.bar(
            x=list(protocol_data.keys()),
            y=list(protocol_data.values()),
            title='Alerts by Protocol',
            labels={'x': 'Protocol', 'y': 'Count'},
            color=list(protocol_data.keys())
        )
        st.plotly_chart(fig, use_container_width=True)
    
    def create_timeline_chart(self, alerts: List[Dict]):
        """Create alert timeline"""
        if not alerts:
            return
        
        timeline_data = []
        for alert in alerts:
            alert_time = alert.get('timestamp')
            if alert_time:
                if isinstance(alert_time, str):
                    alert_time = datetime.fromisoformat(alert_time.replace('Z', ''))
                timeline_data.append({
                    'time': alert_time,
                    'severity': alert.get('severity', 'UNKNOWN'),
                    'type': alert.get('alert_type', 'UNKNOWN')
                })
        
        if timeline_data:
            df = pd.DataFrame(timeline_data)
            fig = px.scatter(
                df, x='time', y='severity', color='type',
                title='Alert Timeline',
                labels={'time': 'Time', 'severity': 'Severity'}
            )
            st.plotly_chart(fig, use_container_width=True)
    
    def display_recent_alerts(self, alerts: List[Dict]):
        """Display recent alerts table"""
        if not alerts:
            st.info("No recent alerts")
            return
        
        recent_alerts = sorted(alerts, key=lambda x: x.get('timestamp', ''), reverse=True)[:10]
        
        for alert in recent_alerts:
            with st.expander(f"🚨 {alert.get('alert_type', 'Unknown')} - {alert.get('severity', 'Unknown')}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Source:** {alert.get('source_ip', 'Unknown')}")
                    st.write(f"**Time:** {alert.get('timestamp', 'Unknown')}")
                    st.write(f"**Score:** {alert.get('severity_score', 0)}")
                
                with col2:
                    st.write(f"**Protocol:** {alert.get('log_type', 'Unknown')}")
                    st.write(f"**Description:** {alert.get('description', 'No description')}")
                
                if 'domain' in alert:
                    st.write(f"**Domain:** {alert.get('domain')}")
                if 'uri' in alert:
                    st.write(f"**URI:** {alert.get('uri')}")
    
    def display_system_stats(self):
        """Display system statistics"""
        col1, col2, col3, col4 = st.columns(4)
        
        alerts = self.load_alerts()
        summary = self.create_alert_summary(alerts)
        
        with col1:
            st.metric("Total Alerts", summary['total'])
        with col2:
            st.metric("High Severity", summary['by_severity']['HIGH'])
        with col3:
            st.metric("Medium Severity", summary['by_severity']['MEDIUM'])
        with col4:
            st.metric("Low Severity", summary['by_severity']['LOW'])
    
    def run_dashboard(self):
        """Run the dashboard"""
        st.set_page_config(
            page_title="C2 Detection Dashboard",
            page_icon="🚨",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Sidebar
        st.sidebar.title("C2 Detection Dashboard")
        st.sidebar.info("Real-time monitoring of C2 beacon activities")
        
        # Auto-refresh
        refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 15)
        auto_refresh = st.sidebar.checkbox("Auto-refresh", value=True)
        
        if auto_refresh:
            time.sleep(refresh_interval)
            st.rerun()
        
        # Main content
        st.title("🚨 C2 Beacon Detection Dashboard")
        st.markdown("---")
        
        # System stats
        self.display_system_stats()
        st.markdown("---")
        
        # Load data
        alerts = self.load_alerts()
        summary = self.create_alert_summary(alerts)
        logs = self.load_logs()
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            self.create_severity_chart(summary['by_severity'])
        
        with col2:
            self.create_protocol_chart(summary['by_protocol'])
        
        # Timeline
        self.create_timeline_chart(alerts)
        st.markdown("---")
        
        # Recent alerts
        st.subheader("📋 Recent Alerts")
        self.display_recent_alerts(summary['recent_alerts'])
        
        # Logs
        st.subheader("📝 Recent Logs")
        with st.expander("View Logs"):
            for log in logs[-20:]:  # Last 20 lines
                st.code(log, language='text')
        
        # Footer
        st.markdown("---")
        st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        st.caption("C2 Detection System v2.0")

def main():
    """Main function to run the dashboard"""
    dashboard = C2Dashboard()
    dashboard.run_dashboard()

if __name__ == "__main__":
    main()
