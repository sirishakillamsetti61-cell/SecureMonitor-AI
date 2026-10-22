\# SecureMonitor AI



\*\*AI-Driven Behavioral Fingerprinting for Real-Time IoT Security and Anomaly Detection\*\*



\## About the Project



SecureMonitor AI is a security monitoring project designed to identify unusual system and IoT device behaviour, classify risk levels, and display alerts through a web dashboard.



\## Key Features



\- \*\*Risk Classification:\*\* NORMAL, MEDIUM, and HIGH risk levels.

\- \*\*System Monitoring:\*\* Monitors system metrics such as CPU, RAM, and disk usage.

\- \*\*IoT Monitoring:\*\* Supports an ESP32-based sensor monitoring setup.

\- \*\*Web Dashboard:\*\* Displays monitoring information and risk status using Flask.

\- \*\*Alerts:\*\* Supports risk alerts through the dashboard and configured notifications.

\- \*\*Remote Monitoring:\*\* Provides endpoints for registered monitoring agents to send device metrics.



\## Technology Stack



\- Python

\- Flask

\- HTML, CSS, and JavaScript

\- ESP32 and Arduino-compatible firmware

\- DHT22 temperature and humidity sensor

\- HC-SR501 PIR motion sensor

\- Git and GitHub



\## Project Files



| File | Purpose |

|---|---|

| `app.py` | Main Flask web application |

| `monitor\_agent.py` | Collects and sends system metrics |

| `requirements.txt` | Python dependencies |

| `REMOTE\_SETUP.md` | Remote monitoring setup instructions |



\## Run Locally



1\. Install Python 3.

2\. Open a terminal in the project directory.

3\. Install dependencies:



&#x20;  ```bash

&#x20;  pip install -r requirements.txt

&#x20;  ```



4\. Configure the required environment variables according to `REMOTE\_SETUP.md`.

5\. Start the application:



&#x20;  ```bash

&#x20;  python app.py

&#x20;  ```



6\. Open `http://127.0.0.1:5000` in your browser.



\## Security Notes



\- Keep API tokens, passwords, and secret environment variables private.

\- Do not commit `.env` files or local databases.

\- Use HTTPS and appropriate authentication for remote monitoring.

\- Keep local hardware-control functionality restricted to trusted local access.

\- Sensor simulation values are not equivalent to calibrated physical measurements.



\## Project Status



This project supports local monitoring, simulated risk testing, and remote device monitoring. Actual hardware readings require compatible physical hardware and appropriate connections.



\## Author



\*\*Sirisha Killamsetti\*\*

