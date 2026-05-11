import streamlit as st
import pandas as pd
from sqlalchemy import create_engine
import plotly.express as px
import time

st.set_page_config(page_title="Sauron War Room", layout="wide", page_icon="👁️")
st.title("👁️ SAURON: Distributed C2 Threat Intelligence")

DB_URL = "postgresql://sauron_admin:swampizzo@sauron-db/threat_intel"
engine = create_engine(DB_URL)

def load_data():
    try:
        return pd.read_sql("SELECT * FROM attacks", engine)
    except Exception:
        return pd.DataFrame()

df = load_data()

col1, col2, col3 = st.columns(3)
if not df.empty:
    col1.metric("Total Attacks", len(df))
    col2.metric("Unique Threats", df['attacker_id'].nunique())
    col3.metric("Active Sensors", df['agent_id'].nunique())
else:
    col1.metric("Total Attacks", 0)
    col2.metric("Unique Threats", 0)
    col3.metric("Active Sensors", 0)

st.subheader("🌍 Real-time Global Attack Map")
if not df.empty and 'latitude' in df.columns:
    map_df = df[df['latitude'] != 0]
    if not map_df.empty:
        fig = px.scatter_geo(map_df, 
                             lat='latitude', 
                             lon='longitude', 
                             color='service',
                             hover_name='attacker_id',
                             hover_data=['city', 'country'],
                             projection="natural earth",
                             template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Waiting for attacks with valid geolocation data...")
else:
    st.info("No attack data available yet.")


st.subheader("🛡️ Recent Telemetry")
if not df.empty:
    st.dataframe(df.sort_values(by='timestamp', ascending=False).head(10), use_container_width=True)


time.sleep(5)
st.rerun()