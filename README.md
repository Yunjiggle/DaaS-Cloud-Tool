# DaaS Forensic Investigation Framework

A forensic investigation framework for Desktop-as-a-Service (DaaS) environments, addressing evidence fragmentation and intermixing challenges in multi-session virtual desktop infrastructures.

## Repository Structure

```
├── Cross-Layer Correlation Tool/   # Cross-layer log correlation and user-VM-time mapping
├── VDI Artifact Integrator/        # SID-based multi-VM artifact integration and analysis
└── Sample Results/                 # Example analysis outputs
```

## Cross-Layer Correlation Tool

Correlates Access Layer authentication logs with Control Layer activity logs to generate user-VM-time mapping tables. Supports both AWS WorkSpaces and Azure Virtual Desktop environments.

**Usage:**
```bash
pip install -r requirements.txt
streamlit run app.py
```

## VDI Artifact Integrator

Integrates forensic artifacts distributed across multiple VMs using Security Identifiers (SID) as pivots. Extracts and analyzes Prefetch files, Edge browsing history, Security event logs, and SOFTWARE registry hives from E01/VHD disk images.

**Usage:**
```bash
pip install -r requirements.txt
python -m src.gui.main_window
```

## Sample Results

### AWS WorkSpaces Analysis
![AWS Result](Sample%20Results/AWS-result.png)

### Azure Virtual Desktop Analysis
![Azure Result](Sample%20Results/Azure-result.png)
