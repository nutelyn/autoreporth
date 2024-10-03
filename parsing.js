function greetTime(){
    // Declare the class to get current time
    const time = new Date();
    // Get only the hour
    let currentHour = time.getHours();
    // Return the greeting based on the time range
    if (currentHour > 4 && currentHour <= 10){
        return "Selamat Pagi,";
    }
    else if (currentHour > 10 && currentHour <= 14){
        return "Selamat Siang,";
    }
    else if (currentHour > 14 && currentHour <= 19){
        return "Selamat Sore,";
    }
    else if ((currentHour > 19 && currentHour <= 24) || currentHour <= 4){
        return "Selamat malam,";
    }
}

function getDate(){
    // Create Date() class
    const time = new Date();
    
    // Formatting the time
    let options = { day: '2-digit', month: 'long', year: 'numeric' };
    let date = time.toLocaleDateString('in-ID', options)
    return date;
}

const severityMap = {
    "OpenLDAP connection open": "low",
    "Successful sudo to ROOT executed": "low",
    "Log file rotated": "low",
    "Processes running for all users were queried with ps command": "low",
    "Listened ports status changed": "low",
    "Login session closed": "low",
    "Login session opened": "low",
    "Potentially Bad Traffic": "low",
    "GPL SNMP public access udp": "low",
    "Unknown Traffic": "low",
    "stream5: TCP Small Segment Threshold Exceeded": "low",
    "stream5: Bad segment, adjusted size <= 0": "low",
    "GPL ICMP_INFO PING *NIX": "low",
    "stream5: Limit on number of overlapping TCP packets reached": "low",
    "http_inspect: CHUNK SIZE MISMATCH DETECTED": "low",
    "SERVER-IIS Microsoft Windows IIS FastCGI request header buffer overflow attempt": "low",
    "ET INFO Dotted Quad Host PDF Request": "low",
    "Host-based anomaly detection event (rootcheck)": "low",
    "Service startup type was changed": "low",
    "ssh: Protocol mismatch": "low",
    "SSHD authentication success": "low",
    "Windows Logon Success": "low",
    "ET SCAN Suspicious inbound to PostgreSQL port 5432": "low",
    "stream5: TCP Timestamp is outside of PAWS window": "low",
    "ET INFO Observed DNS Query to .cloud TLD": "low",
    "SERVER-ORACLE database username buffer overflow": "low",
    "GPL SNMP private access udp": "low",
    "ET SCAN Suspicious inbound to Oracle SQL port 5432": "low",
    "ET SCAN Suspicious inbound to Oracle SQL port 1521": "low",
    "Unexpected error while resolving domain": "medium",
    "User authentication failure": "medium",
    "APP-DETECT Teamviewer control server ping": "medium",
    "OS-WINDOWS Microsoft Windows getbulk request attempt": "medium",
    "OS-WINDOWS Microsoft Windows SMB anonymous session IPC share access attempt": "medium",
    "INDICATOR-COMPROMISE 403 Forbidden": "medium",
    "OpenLDAP authentication failed": "medium",
    "ET TROJAN DNS Reply Sinkhole Microsoft NO-IP Domain": "high",
    "ET TROJAN Known Hostile Domain ant.trenz.pl Lookup": "high"
}

function formatLogs(inputText) {
    const lines = inputText.split('\n');
    let formattedOutput = '';

    for (let i = 0; i < lines.length; i++) {
        const currentLine = lines[i].trim(); // Trim whitespace for the current line

        if (currentLine) { // Proceed only if the current line is not empty
            if (currentLine.startsWith('#')) {
                // If it's a header, add it to the output
                formattedOutput += `\n${currentLine}\n`;
            } else {
                // Check if the next line exists and is a number (event count)
                if (i + 1 < lines.length) {
                    const nextLine = lines[i + 1].trim(); // Trim whitespace for the next line

                    // Ensure nextLine is not empty and matches the expected format (number)
                    if (nextLine && /^\d[\d,]*$/.test(nextLine)) {
                        const severity = severityMap[currentLine] || "";
                        formattedOutput += `- ${currentLine} = ${nextLine} event(s) [Severity: ${severity}]\n`;
                        i++; // Increment i to skip the next line since it's processed
                    } else {
                        // Handle unexpected next line format
                        formattedOutput += `- ${currentLine} = [Missing event count] event(s) [Severity: ]\n`;
                    }
                } else {
                    // If there's no next line, handle the case
                    formattedOutput += `- ${currentLine} = [Missing event count] event(s) [Severity: ]\n`;
                }
            }
        }
    }
    return formattedOutput;
}

const cfHeaders = {
    "Source IP Addresses": "# Top IP Addresses:\n",
    "Paths": "\n# Paths:\n",
    "Countries": "\n# Top Countries:\n",
    "Hosts": "\n# Hosts:\n",
    "Source ASNs": "\n# Top ASNs:\n",
    "Firewall rules": "\n# Firewall rules:\n",
    "Rate limiting rules": "\n# Rate limiting rules:\n",
    "Managed rules": "\n# Managed rules:\n",
    "HTTP DDoS rules": "\n# HTTP DDoS rules:\n",
    "HTTP Methods": "\n# HTTP Methods: "
};

const httpMethods = [
    'GET', 'HEAD', 'OPTIONS', 'TRACE',
    'PUT', 'DELETE', 'POST', 'PATCH',
    'CONNECT'
];

function ceefFormatLogs(inputText){
    // Predefined
    let date = getDate();
    let predef = `Kami infokan ada serangan yang berlangsung pada ${date} sejak pukul [WAKTU] dan sudah ditangani CloudFlare. Untuk informasi lebih detail sebagai berikut:
\n`;

    // Preparing the inputs for parsing
    const lines = inputText.split('\n');
    let formattedOutput = predef;
    // Parsing
    for (let i = 0; i < lines.length; i++){
        let currentLine = lines[i].trim();
        // If some dummy paste it in
        if (currentLine === "Top events by source"){
            i++;
            continue;
        }
        // If it's a count
        else if (/(^\d*$)|(\d*k$)/.test(currentLine)){
            continue;
        }
        // If it's user agent
        else if (currentLine === "User Agents"){
            while(!(lines[i+1].trim() in cfHeaders)){
                i++;
                currentLine = lines[i].trim();
            }
        }
        // If for some reason the input is empty
        else if (currentLine === ""){
            continue;
        }
        // Process good input
        else {
            // If it's a header
            if (currentLine in cfHeaders){
                formattedOutput += cfHeaders[currentLine];
            }
            // For http method section
            else if (httpMethods.includes(currentLine)){
                // Check if there is still antoher item
                if (lines[i+2]){
                    formattedOutput += `${currentLine}, `;
                }
                else {
                    formattedOutput += `${currentLine}`;
                }
            }
            else if (currentLine === "No data"){
                formattedOutput += `- N/A\n`;
            }
            else {
                formattedOutput += `- ${currentLine}\n`;
            }
        }

    }
    return formattedOutput;
}

module.exports = { formatLogs, ceefFormatLogs, greetTime };