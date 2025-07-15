# WhisperCatcher: Demystifying Unauthorized and Encrypted Private Data Transmission in Android Applications

## Overview

WhisperCatcher is an automated tool designed for detecting unauthorized and encrypted private data transmission behaviors in Android applications.  By integrating network traffic semantic guided static code analysis, dynamic instrumentation, and llm-based private data extraction, WhisperCatcher can effectively identify private data transmissions before the user consents to the privacy policy, and significantly outperforming existing approaches.
<div align="center">
<img src="imgs/overview.png" width="80%"/>
</div>
## Methodology

WhisperCatcher employs the following four-stage pipeline.

- Raw Traffic Capturing
  - capture the raw traffic generated during the app's startup phase, before the user consents to the privacy policy
  - plaintext traffic/https-encrypted traffic will be directly used for identifying unauthorized private data transmissions
  - app-encrypted traffic will be further analyzed
- Traffic Semantics Analysis
  - extract semantic keywords from the captured traffic
- Transmission Functions Identification
  - perform traffic semantics guided static code analysis
  - extract key functions that may contain plaintext form private data
- Private Data Extraction and Analysis
  - instrumentation
  - employ LLM to identify transmitted private data in complex scenarios

## Evaluation

### Capabilities for Data Transmission Detection

<div align="center">
<img src="imgs/data-transmission-detection-capabilities.png" width="50%"/>
</div>

### Effectiveness

<div align="center">
<img src="imgs/effectiveness.png" width="50%"/>
</div>

## Installation & Setup

### Prerequisites

- Python 3.8+ (recommended python version: 3.11)
- Rooted Android device
- Android SDK Tools
- Java JDK (>=8)
- mitmproxy environment configured

> **References:**
> [1] [Mtimproxy Installation](https://docs.mitmproxy.org/stable/overview-installation/)
> [2] [Getting Started with Mitmproxy](https://docs.mitmproxy.org/stable/overview-getting-started/)

### Quick Start

#### Install dependencies

```bash
pip install -r requirements.txt
```

#### Environment setup

1. **mitmproxy**: Make sure the traffic capturing works between your Android device and host PC
2. **Frida**: Push `frida-server` to your Android device (default: `/data/local/tmp/`, rename it to `fs16.1.5arm64`) or use the provided file `tmp/fs16.1.5arm64`
3. **Android SDK**: Add `${ANDROID_HOME}/platform-tools` to `PATH`
4. **Java**: Add JDK (>=8) to `PATH`
5. **Config**: Edit `src/config.py` for your configuration

#### Launch

```bash
python src/whispercatcher.py
```

For more details, please refer to our paper.
