# get-os-cve 🛡️

Author: **[m4r4v](https://github.com/m4r4v)**

`get-os-cve` is a Python script that automatically detects the operating system it's running on, queries the National Vulnerability Database (NVD), and reports any known Common Vulnerabilities and Exposures (CVEs) associated with that OS.

---

## What It Does

The main purpose of this script is to provide a quick and easy way to check if a system has known security vulnerabilities. It's designed to be self-sufficient, meaning it can discover information about new operating systems it hasn't seen before, making it a flexible tool for security awareness.

---

## How It Works

The script follows a simple yet powerful workflow:

1.  **OS Detection**: It first uses Python's built-in `platform` module to identify the host operating system (e.g., Debian 12, macOS 14).
2.  **Local CPE Mapping**: It checks a built-in Python dictionary, `CPE_MAP`, to see if it already has the corresponding Common Platform Enumeration (CPE) string, which is the official NVD name for a piece of software or OS.
3.  **Dynamic CPE Discovery**: If the OS is not in the local map, the script queries the **NVD CPE API**. It uses the OS name as a keyword to search for and find the correct CPE string automatically. This allows the script to adapt to new environments without needing manual updates.
4.  **CVE Fetching**: With the correct CPE string, it then makes a second API call to the **NVD CVE API** to fetch a list of all vulnerabilities associated with that specific OS version.
5.  **Display Results**: Finally, it parses the results and prints a clean, readable list of found CVEs, including their ID, severity score, and a description.

---

## Prerequisites

To run this script, you'll need:
* Python 3.6+
* The `requests` library

---

## How to Use

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/m4r4v/get-os-cve
    cd get-os-cve
    ```

2.  **Setup a Virtual Environment** (Recommended)
    It's best practice to create a virtual environment to manage project dependencies.
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies**
    Install the required `requests` library from the `requirements.txt` file.
    ```bash
    pip install -r requirements.txt
    ```

4.  **Add NVD API Key** (Optional but Recommended)
    For a higher request rate and more reliable performance, get a free API key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).

    Once you have your key, open `main.py` and paste it into the `NVD_API_KEY` variable:
    ```python
    NVD_API_KEY = "YOUR_API_KEY_HERE"
    ```

5.  **Run the Script**
    Execute the script from your terminal.
    ```bash
    python main.py
    ```

---

## Example Output

```
--- CVE Check Bot Initializing ---
✅ Detected OS: debian_12
ℹ️ OS 'debian_12' not in local map. Searching NVD API...
✅ Discovered CPE: cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*

🔍 Searching for CVEs with CPE: cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*

Found 28 vulnerabilities. Displaying details:

------------------------------------------------------------
ID: CVE-2007-6388
Severity Score: 6.8
Description: Multiple stack-based buffer overflows in (1) CCE_play.ln.c and (2) xl_play.ln.c in JoeModules/cca/ in unicon-imc2 3.0.1, as used by jzchen and other applications, allow local users to gain privileges via a long HOME environment variable.

------------------------------------------------------------
ID: CVE-2008-2797
Severity Score: 2.1
Description: htdig, including 1999.12.14 in Red Hat Enterprise Linux and c6d-3.0 in Debian GNU/Linux, sets the wrong group owners hip of .htdig cache, which allows local users to write data to other users' terminals.
...
```

---

## Next Steps 🚀

Here are some ideas to make the application even better:

* **Cache Discovered CPEs**: Save the CPEs found through the API to a local file (e.g., `cpe_cache.json`). This would speed up future runs on the same OS and reduce API calls.
* **Filter by Severity**: Add command-line arguments to filter the results. For example, `python main.py --min-severity 7.0` could show only High or Critical vulnerabilities.
* **Advanced Output Formats**: Add options to export the list of vulnerabilities to different formats, like **CSV** or **JSON**, making it easier to use the data in other tools or reports.
* **Batch Processing**: Allow the script to accept a file with a list of CPEs as input, so it can check for vulnerabilities for multiple systems at once.
* **Improved Error Handling**: Add more robust error handling for different types of network failures or unexpected API responses from the NVD.
