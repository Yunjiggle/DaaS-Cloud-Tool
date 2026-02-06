"""
DaaS Forensic Investigation - Cross-Layer Correlation Tool
Streamlit UI Application
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from cross_layer_correlation.aws_correlator import AWSCorrelator
from cross_layer_correlation.azure_correlator import AzureCorrelator
from datetime import datetime
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="DaaS Forensic Investigation Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for compact single-page layout
st.markdown("""
<style>
    @import url('https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css');

    * {
        font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, system-ui, Roboto, sans-serif;
    }

    /* Compact page layout */
    .block-container {
        padding-top: 3.5rem !important;
        padding-bottom: 0 !important;
    }

    /* Section header banner */
    .section-header {
        background: linear-gradient(135deg, #1B2A4A 0%, #2D4373 100%);
        color: white !important;
        padding: 10px 20px;
        font-size: 1.3rem;
        font-weight: 700;
        border-radius: 6px;
        margin: 0.5rem 0 0.4rem 0;
        letter-spacing: 0.02em;
    }

    .section-subtitle {
        font-size: 1.05rem;
        font-weight: 600;
        color: #555;
        margin: 0 0 0.2rem 0;
    }

    /* User section with left border */
    .user-section {
        margin: 0.3rem 0 0.1rem 0;
        padding: 4px 0 4px 14px;
    }

    .user-header {
        font-size: 1.2rem;
        font-weight: 700;
        color: #1B2A4A;
    }

    .activity-count {
        font-size: 0.95rem;
        color: #555;
    }

    /* Body text - dark color */
    .stMarkdown p {
        font-size: 1rem !important;
        margin-bottom: 0.15rem !important;
        color: #1a1a1a !important;
    }

    .stMarkdown strong {
        font-size: 1.05rem !important;
        color: #111 !important;
    }

    /* Dataframe cells - readable, dark text */
    [data-testid="stDataFrame"] td, [data-testid="stDataFrame"] th,
    [data-testid="stDataFrame"] [role="gridcell"] {
        font-size: 0.88rem !important;
        padding: 4px 8px !important;
        color: #1a1a1a !important;
    }

    /* Dataframe header - dark background for visibility */
    [data-testid="stDataFrame"] [data-testid="glideDataEditor"] [role="columnheader"] {
        background-color: #1B2A4A !important;
        color: white !important;
        font-weight: 700 !important;
        font-size: 0.9rem !important;
    }

    /* Horizontal blocks */
    [data-testid="stHorizontalBlock"] {
        gap: 0.5rem;
    }

    /* ===== Print styles ===== */
    @page {
        size: A4 landscape;
        margin: 0.5cm;
    }

    @media print {
        /* Hide Streamlit UI chrome */
        header, footer,
        [data-testid="stToolbar"],
        [data-testid="stDecoration"],
        [data-testid="stStatusWidget"],
        .stDeployButton,
        [data-testid="stSidebar"],
        [data-testid="collapsedControl"] {
            display: none !important;
        }

        /* Full width without sidebar */
        .block-container {
            padding-top: 0.3rem !important;
            max-width: 100% !important;
        }

        /* Prevent page breaks inside user sections */
        .user-section,
        [data-testid="stHorizontalBlock"] {
            break-inside: avoid;
            page-break-inside: avoid;
        }

        /* Keep section header with its content */
        .section-header {
            break-after: avoid;
            page-break-after: avoid;
        }
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("Configuration")
platform = st.sidebar.selectbox(
    "Select DaaS Platform",
    ["AWS WorkSpaces", "Azure Virtual Desktop"]
)

# Demo mode toggle
st.sidebar.markdown("---")
demo_mode = st.sidebar.checkbox("🚀 Demo Mode (Auto-load sample data)", value=False)

st.sidebar.markdown("---")
st.sidebar.markdown("### About")
st.sidebar.markdown("""
This tool performs cross-layer correlation analysis for DaaS environments.

**Features:**
- User-VM-Time Mapping
- Security Activity Detection
- Activity Timeline Reconstruction
""")

# Main content
if platform == "AWS WorkSpaces":
    # Demo mode - auto load files
    if demo_mode:

        from pathlib import Path
        project_root = Path(__file__).parent.parent
        aws_log_dir = project_root / "[1] AWS Log" / "(1) Dedicated"

        # Auto-load file paths
        eventbridge_paths = [
            aws_log_dir / f"AWS_EVENT_BRIDGE_{i}.csv" for i in range(1, 7)
        ]
        query_paths = [
            aws_log_dir / "USER_A_QUERY_LOGS.csv",
            aws_log_dir / "USER_B_QUERY_LOGS.csv"
        ]
        vpc_paths = [
            aws_log_dir / "USER_A_VPC_LOGS.csv",
            aws_log_dir / "USER_B_VPC_LOGS.csv"
        ]
        mapping_path = aws_log_dir / "workspace_user_mapping.json"

        eventbridge_files = [str(p) for p in eventbridge_paths if p.exists()]
        query_logs_files = [str(p) for p in query_paths if p.exists()]
        vpc_logs_files = [str(p) for p in vpc_paths if p.exists()]
        workspace_mapping_file = str(mapping_path) if mapping_path.exists() else None

        use_auto_files = True
    else:
        col1, col2, col3 = st.columns(3)

        with col1:
            st.subheader("Upload Event Bridge Logs")
            eventbridge_files = st.file_uploader(
                "Event Bridge WorkSpaces Access Logs (CSV)",
                type=['csv'],
                key='eventbridge',
                accept_multiple_files=True
            )

        with col2:
            st.subheader("Upload Query Logs")
            query_logs_files = st.file_uploader(
                "Route 53 Query Logs per User (CSV)",
                type=['csv'],
                key='query_logs',
                accept_multiple_files=True
            )

        with col3:
            st.subheader("Upload VPC Flow Logs")
            vpc_logs_files = st.file_uploader(
                "VPC Flow Logs per User (CSV)",
                type=['csv'],
                key='vpc_logs',
                accept_multiple_files=True
            )

        use_auto_files = False
        workspace_mapping_file = None

    if eventbridge_files and query_logs_files:
        with st.spinner("Analyzing logs..."):
            # Initialize correlator
            correlator = AWSCorrelator()

            # Load workspace user mapping if available
            if workspace_mapping_file:
                correlator.load_workspace_user_mapping(workspace_mapping_file)

            # Extract user labels from filenames
            user_labels = []
            if use_auto_files:
                # Demo mode: extract from file paths
                for f in query_logs_files:
                    if 'USER_A' in f:
                        user_labels.append('USER_A')
                    elif 'USER_B' in f:
                        user_labels.append('USER_B')
                    else:
                        user_labels.append(Path(f).stem)
            else:
                # Manual upload mode: extract from file names
                for f in query_logs_files:
                    if 'USER_A' in f.name or 'A_' in f.name:
                        user_labels.append('USER_A')
                    elif 'USER_B' in f.name or 'B_' in f.name:
                        user_labels.append('USER_B')
                    else:
                        user_labels.append(f.name.split('.')[0])

            # Load logs
            eventbridge_df = correlator.load_eventbridge_logs(eventbridge_files)
            query_logs_df = correlator.load_query_logs(query_logs_files, user_labels)

            # Load VPC logs if provided
            if vpc_logs_files:
                vpc_user_labels = []
                if use_auto_files:
                    # Demo mode
                    for f in vpc_logs_files:
                        if 'USER_A' in f:
                            vpc_user_labels.append('USER_A')
                        elif 'USER_B' in f:
                            vpc_user_labels.append('USER_B')
                        else:
                            vpc_user_labels.append(Path(f).stem)
                else:
                    # Manual upload mode
                    for f in vpc_logs_files:
                        if 'USER_A' in f.name or 'A_' in f.name:
                            vpc_user_labels.append('USER_A')
                        elif 'USER_B' in f.name or 'B_' in f.name:
                            vpc_user_labels.append('USER_B')
                        else:
                            vpc_user_labels.append(f.name.split('.')[0])
                vpc_logs_df = correlator.load_vpc_logs(vpc_logs_files, vpc_user_labels)

            # Generate mappings
            user_vm_mapping = correlator.generate_user_vm_mapping()
            activity_timeline = correlator.detect_all_activities()
            timeline = correlator.generate_timeline()
            stats = correlator.get_summary_statistics()

        # ==================== 01. Overview ====================
        st.markdown('<div class="section-header">01. Overview</div>', unsafe_allow_html=True)
        st.markdown('<p class="section-subtitle">User-Workspace-Time Mapping</p>', unsafe_allow_html=True)

        if len(user_vm_mapping) > 0:
            fig_sessions = go.Figure()
            color_palette = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']
            unique_users = user_vm_mapping['User'].unique()
            user_colors = {user: color_palette[i % len(color_palette)] for i, user in enumerate(unique_users)}

            for _, session in user_vm_mapping.iterrows():
                user = session['User']
                hover_text = (f"<b>{user}</b><br>"
                             f"Workspace: {session['Workspace ID']}<br>"
                             f"Start: {session['Session Start']}<br>"
                             f"End: {session['Session End']}<br>"
                             f"IP: {session['Client IP']}<extra></extra>")

                fig_sessions.add_trace(go.Scatter(
                    x=[session['Session Start'], session['Session End']],
                    y=[user, user],
                    mode='lines+markers',
                    name=user,
                    line=dict(color=user_colors.get(user, '#808080'), width=10),
                    marker=dict(size=10, symbol='circle'),
                    hovertemplate=hover_text,
                    showlegend=False
                ))

            # Tight x-axis range
            time_min = user_vm_mapping['Session Start'].min()
            time_max = user_vm_mapping['Session End'].max()
            time_pad = (time_max - time_min) * 0.03

            fig_sessions.update_layout(
                height=max(120, len(unique_users) * 45),
                xaxis_title="Time",
                yaxis_title="User",
                hovermode='closest',
                margin=dict(l=80, r=20, t=10, b=35),
                xaxis=dict(
                    tickfont=dict(size=12, color='#1a1a1a'),
                    title_font=dict(color='#1a1a1a'),
                    range=[time_min - time_pad, time_max + time_pad]
                ),
                yaxis=dict(
                    tickfont=dict(size=13, color='#1a1a1a'),
                    title_font=dict(color='#1a1a1a'),
                    categoryorder='array',
                    categoryarray=sorted(unique_users)
                )
            )

            st.plotly_chart(fig_sessions, use_container_width=True)

        # Build both table datasets
        user_summary = []
        for user in user_vm_mapping['User'].unique():
            user_sessions = user_vm_mapping[user_vm_mapping['User'] == user]
            for _, session in user_sessions.iterrows():
                user_summary.append({
                    'User': user,
                    'Workspace': session['Workspace ID'],
                    'Login': str(session['Session Start'])[:19],
                    'Logout': str(session['Session End'])[:19],
                    'IP': session['Client IP'],
                    'Platform': session['Platform']
                })

        workspace_summary = []
        for workspace_id in user_vm_mapping['Workspace ID'].unique():
            ws_sessions = user_vm_mapping[user_vm_mapping['Workspace ID'] == workspace_id]
            users = ws_sessions['User'].unique()
            workspace_summary.append({
                'Workspace': workspace_id,
                'Sessions': len(ws_sessions),
                'Users': ', '.join(users),
                'First Access': str(ws_sessions['Session Start'].min())[:19],
                'Last Access': str(ws_sessions['Session End'].max())[:19]
            })

        # Fixed container height for both tables (based on larger table)
        max_rows = max(len(user_summary), len(workspace_summary), 1)
        table_container_h = 36 + max_rows * 35

        # Side-by-side tables in fixed-height containers
        detail_col1, detail_col2 = st.columns(2)

        with detail_col1:
            st.markdown("**User → Workspace Sessions**")
            if user_summary:
                with st.container(height=table_container_h, border=False):
                    st.dataframe(pd.DataFrame(user_summary), use_container_width=True, hide_index=True)

        with detail_col2:
            st.markdown("**Workspace → User Access List**")
            if workspace_summary:
                with st.container(height=table_container_h, border=False):
                    st.dataframe(pd.DataFrame(workspace_summary), use_container_width=True, hide_index=True,
                        column_config={
                            'Sessions': st.column_config.NumberColumn(width=50),
                        })

        # ==================== 02. User Activity Timeline ====================
        if len(activity_timeline) > 0:
            st.markdown('<div class="section-header">02. User Activity Timeline</div>', unsafe_allow_html=True)

            unique_users = activity_timeline['User'].unique()
            user_border_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

            for idx, user in enumerate(unique_users):
                user_activities = activity_timeline[activity_timeline['User'] == user]
                border_color = user_border_colors[idx % len(user_border_colors)]

                st.markdown(
                    f'<div class="user-section" style="border-left: 4px solid {border_color};">'
                    f'<span class="user-header">👤 {user}</span><br>'
                    f'<span class="activity-count"><b>{len(user_activities)} activities detected</b></span>'
                    f'</div>',
                    unsafe_allow_html=True
                )

                table_col, chart_col = st.columns(2)

                with table_col:
                    table_data = []
                    for _, activity in user_activities.iterrows():
                        row = {
                            'Activity Type': activity['Activity Type'],
                            'Target': activity.get('Domain', activity.get('Port', 'N/A')),
                            'Count': activity.get('Query Count', activity.get('Attempts', 'N/A')),
                            'Start Time': activity['Start Time'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(activity.get('Start Time')) else 'N/A',
                            'Details': activity.get('Details', 'N/A')
                        }
                        table_data.append(row)
                    if table_data:
                        st.dataframe(pd.DataFrame(table_data), use_container_width=True, height=200, hide_index=True,
                            column_config={
                                'Count': st.column_config.NumberColumn(width=50),
                            })

                with chart_col:
                    chart_data = user_activities.copy()

                    # Target label for hover
                    chart_data['Target'] = chart_data.apply(
                        lambda r: r.get('Domain', r.get('Port', 'N/A'))
                                  if pd.notna(r.get('Domain', None))
                                  else str(r.get('Details', 'N/A'))[:40],
                        axis=1
                    )

                    if 'Start Time' in chart_data.columns and len(chart_data) > 0:
                        # Separate chart per activity type (each with own tight x-axis)
                        activity_types = chart_data['Activity Type'].unique()
                        fig_activity = make_subplots(
                            rows=len(activity_types), cols=1,
                            shared_xaxes=False,
                            vertical_spacing=0.15,
                            subplot_titles=[f"{at}" for at in activity_types]
                        )

                        act_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728']
                        for i, at in enumerate(activity_types):
                            at_data = chart_data[chart_data['Activity Type'] == at]
                            at_min = at_data['Start Time'].min()
                            at_max = at_data['Start Time'].max()
                            at_pad = (at_max - at_min) * 0.1 if at_max != at_min else pd.Timedelta(minutes=3)

                            fig_activity.add_trace(
                                go.Scatter(
                                    x=at_data['Start Time'],
                                    y=[at] * len(at_data),
                                    mode='markers',
                                    marker=dict(size=8, color=act_colors[i % len(act_colors)]),
                                    text=at_data['Target'],
                                    hovertemplate='<b>%{text}</b><br>Time: %{x}<extra></extra>',
                                    showlegend=False
                                ),
                                row=i + 1, col=1
                            )
                            fig_activity.update_xaxes(
                                range=[at_min - at_pad, at_max + at_pad],
                                tickfont=dict(size=10, color='#1a1a1a'),
                                row=i + 1, col=1
                            )
                            fig_activity.update_yaxes(
                                showticklabels=False,
                                row=i + 1, col=1
                            )

                        row_h = max(80, 180 // len(activity_types))
                        fig_activity.update_layout(
                            height=max(200, len(activity_types) * row_h),
                            hovermode='closest',
                            margin=dict(l=10, r=10, t=25, b=30),
                        )
                        # Style subplot titles
                        for ann in fig_activity['layout']['annotations']:
                            ann['font'] = dict(size=11, color='#1a1a1a')
                            ann['x'] = 0
                            ann['xanchor'] = 'left'

                        st.plotly_chart(fig_activity, use_container_width=True)


elif platform == "Azure Virtual Desktop":
    # Demo mode - auto load files
    if demo_mode:

        from pathlib import Path
        project_root = Path(__file__).parent.parent
        azure_log_dir = project_root / "[6] Azure Log"

        # Auto-load file paths (use larger file with multiple users)
        interactive_path = azure_log_dir / "InteractiveSignIns_AuthDetails_2025-12-14_2025-12-20.csv"
        noninteractive_path = azure_log_dir / "NonInteractiveSignIns_2025-11-29_2025-12-29.csv"

        interactive_file = str(interactive_path) if interactive_path.exists() else None
        noninteractive_file = str(noninteractive_path) if noninteractive_path.exists() else None

        use_auto_files = True
    else:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Upload Interactive Sign-in Logs")
            interactive_file = st.file_uploader(
                "Interactive Sign-in Logs (CSV)",
                type=['csv'],
                key='interactive'
            )

        with col2:
            st.subheader("Upload Non-Interactive Sign-in Logs")
            noninteractive_file = st.file_uploader(
                "Non-Interactive Sign-in Logs (CSV/JSON)",
                type=['csv', 'json'],
                key='noninteractive'
            )

        use_auto_files = False

    if noninteractive_file:
        with st.spinner("Analyzing logs..."):
            # Initialize correlator
            correlator = AzureCorrelator()

            # Load logs
            if interactive_file:
                interactive_df = correlator.load_interactive_signin_logs(interactive_file)

            noninteractive_df = correlator.load_noninteractive_signin_logs(noninteractive_file)

            # Generate mappings
            user_vm_mapping = correlator.generate_user_vm_mapping()
            allocation_analysis = correlator.analyze_vm_allocation_pattern()
            activity_timeline = correlator.detect_all_activities()
            fragmentation = correlator.detect_evidence_fragmentation()
            timeline = correlator.generate_timeline()
            stats = correlator.get_summary_statistics()

        # ==================== 01. Overview ====================
        st.markdown('<div class="section-header">01. Overview</div>', unsafe_allow_html=True)
        st.markdown('<p class="section-subtitle">User-VM-Time Mapping</p>', unsafe_allow_html=True)

        color_palette = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']

        if len(user_vm_mapping) > 0:
            all_users = sorted(user_vm_mapping['User'].unique())
            user_colors = {user: color_palette[i % len(color_palette)] for i, user in enumerate(all_users)}
            filtered_mapping = user_vm_mapping

            fig_sessions = go.Figure()
            unique_vms = sorted(filtered_mapping['VM Identifier'].unique())
            vm_display_names = {}
            for vm_id in unique_vms:
                vm_sessions = filtered_mapping[filtered_mapping['VM Identifier'] == vm_id]
                vm_display_names[vm_id] = vm_sessions.iloc[0].get('VM Name', vm_id)

            legend_shown = set()
            for _, session in filtered_mapping.iterrows():
                user = session['User']
                vm_id = session['VM Identifier']
                vm_display = session.get('VM Name', vm_id)
                hover_text = (f"<b>User: {user}</b><br>"
                             f"VM: {vm_display}<br>"
                             f"Start: {session['Session Start']}<br>"
                             f"End: {session['Session End']}<br>"
                             f"IP: {session['IP Address']}<extra></extra>")
                show_legend = user not in legend_shown
                legend_shown.add(user)
                fig_sessions.add_trace(go.Scatter(
                    x=[session['Session Start'], session['Session End']],
                    y=[vm_display, vm_display],
                    mode='lines+markers',
                    name=user.split('@')[0],
                    line=dict(color=user_colors.get(user, '#808080'), width=10),
                    marker=dict(size=10, symbol='circle'),
                    hovertemplate=hover_text,
                    showlegend=show_legend,
                    legendgroup=user
                ))

            time_min = filtered_mapping['Session Start'].min()
            time_max = filtered_mapping['Session End'].max()
            time_pad = (time_max - time_min) * 0.03
            fig_sessions.update_layout(
                height=max(120, len(unique_vms) * 45),
                hovermode='closest',
                margin=dict(l=120, r=20, t=10, b=40),
                xaxis=dict(
                    range=[time_min - time_pad, time_max + time_pad],
                    type='date',
                    tickfont=dict(size=12, color='#1a1a1a'),
                ),
                yaxis=dict(
                    categoryorder='array',
                    categoryarray=[vm_display_names[vm_id] for vm_id in unique_vms],
                    tickfont=dict(size=13, color='#1a1a1a'),
                ),
                showlegend=True,
                legend=dict(title="", orientation="h", yanchor="top", y=-0.15, xanchor="center", x=0.5, font=dict(size=10))
            )
            st.plotly_chart(fig_sessions, use_container_width=True)

            # Side-by-side tables
            user_summary = []
            for user in filtered_mapping['User'].unique():
                user_sess = filtered_mapping[filtered_mapping['User'] == user]
                for _, s in user_sess.iterrows():
                    user_summary.append({
                        'User': user,
                        'VM': s.get('VM Name', s['VM Identifier']),
                        'Login': str(s['Session Start'])[:19],
                        'Logout': str(s['Session End'])[:19],
                        'IP': s['IP Address']
                    })
            vm_summary = []
            for vm_id in filtered_mapping['VM Identifier'].unique():
                vm_sess = filtered_mapping[filtered_mapping['VM Identifier'] == vm_id]
                vm_display = vm_sess.iloc[0].get('VM Name', vm_id)
                for user in vm_sess['User'].unique():
                    user_vm_sess = vm_sess[vm_sess['User'] == user]
                    vm_summary.append({
                        'VM': vm_display,
                        'User': user.split('@')[0],
                        'Sessions': len(user_vm_sess),
                        'First Access': str(user_vm_sess['Session Start'].min())[:19],
                        'Last Access': str(user_vm_sess['Session End'].max())[:19]
                    })

            max_rows = max(len(user_summary), len(vm_summary), 1)
            table_container_h = 36 + max_rows * 35

            detail_col1, detail_col2 = st.columns(2)
            with detail_col1:
                st.markdown("**User → VM Sessions**")
                if user_summary:
                    with st.container(height=table_container_h, border=False):
                        st.dataframe(pd.DataFrame(user_summary), use_container_width=True, hide_index=True)
            with detail_col2:
                st.markdown("**VM → User Access List**")
                if vm_summary:
                    with st.container(height=table_container_h, border=False):
                        st.dataframe(pd.DataFrame(vm_summary), use_container_width=True, hide_index=True)

        # ==================== 02. User Activity Timeline ====================
        if len(user_vm_mapping) > 0:
            st.markdown('<div class="section-header">02. User Activity Timeline</div>', unsafe_allow_html=True)

            unique_users = sorted(user_vm_mapping['User'].unique())
            user_border_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

            for idx, user in enumerate(unique_users):
                user_sessions = user_vm_mapping[user_vm_mapping['User'] == user].copy()
                user_sessions = user_sessions.sort_values('Session Start')
                border_color = user_border_colors[idx % len(user_border_colors)]

                st.markdown(
                    f'<div class="user-section" style="border-left: 4px solid {border_color};">'
                    f'<span class="user-header">👤 {user}</span><br>'
                    f'<span class="activity-count"><b>{len(user_sessions)} sessions</b></span>'
                    f'</div>',
                    unsafe_allow_html=True
                )

                table_col, chart_col = st.columns(2)

                with table_col:
                    table_rows = []
                    for _, session in user_sessions.iterrows():
                        vm_display = session.get('VM Name', session['VM Identifier'])
                        duration = session['Session End'] - session['Session Start']
                        table_rows.append({
                            'VM': vm_display,
                            'Session Start': session['Session Start'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Session End': session['Session End'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Duration': str(duration).split('.')[0],
                            'IP': session['IP Address']
                        })
                    if table_rows:
                        tbl_h = 36 + len(table_rows) * 35
                        st.dataframe(pd.DataFrame(table_rows), use_container_width=True,
                                     height=tbl_h, hide_index=True)

                with chart_col:
                    fig_user = go.Figure()
                    vm_colors = {}
                    user_vms = user_sessions['VM Identifier'].unique()
                    for i, vm_id in enumerate(user_vms):
                        vm_display = user_sessions[user_sessions['VM Identifier'] == vm_id].iloc[0].get('VM Name', vm_id)
                        vm_colors[vm_id] = (vm_display, color_palette[i % len(color_palette)])

                    legend_shown_user = set()
                    for _, session in user_sessions.iterrows():
                        vm_id = session['VM Identifier']
                        vm_display, vm_color = vm_colors[vm_id]
                        show_legend = vm_id not in legend_shown_user
                        legend_shown_user.add(vm_id)
                        hover_text = (f"<b>{vm_display}</b><br>"
                                     f"Start: {session['Session Start']}<br>"
                                     f"End: {session['Session End']}<br>"
                                     f"IP: {session['IP Address']}<extra></extra>")
                        fig_user.add_trace(go.Scatter(
                            x=[session['Session Start'], session['Session End']],
                            y=[vm_display, vm_display],
                            mode='lines+markers',
                            name=vm_display,
                            line=dict(color=vm_color, width=8),
                            marker=dict(size=8, symbol='circle'),
                            hovertemplate=hover_text,
                            showlegend=show_legend,
                            legendgroup=vm_display
                        ))

                    t_min = user_sessions['Session Start'].min()
                    t_max = user_sessions['Session End'].max()
                    t_pad = (t_max - t_min) * 0.05 if t_max != t_min else pd.Timedelta(hours=1)
                    fig_user.update_layout(
                        height=max(100, len(user_vms) * 40 + 50),
                        hovermode='closest',
                        margin=dict(l=100, r=20, t=5, b=40),
                        showlegend=True,
                        legend=dict(title="", orientation="h", yanchor="top", y=-0.15, xanchor="center", x=0.5, font=dict(size=10)),
                        xaxis=dict(
                            range=[t_min - t_pad, t_max + t_pad],
                            tickfont=dict(size=10, color='#1a1a1a'),
                        ),
                        yaxis=dict(
                            categoryorder='array',
                            categoryarray=sorted([vm_colors[vm][0] for vm in user_vms]),
                            tickfont=dict(size=10, color='#1a1a1a'),
                        )
                    )
                    st.plotly_chart(fig_user, use_container_width=True)
