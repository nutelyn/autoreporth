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
                        formattedOutput += `- ${currentLine} = ${nextLine} event(s) [severity: ${severity}]\n`;
                        i++; // Increment i to skip the next line since it's processed
                    } else {
                        // Handle unexpected next line format
                        formattedOutput += `- ${currentLine} = [Missing event count] event(s) [severity: ]\n`;
                    }
                } else {
                    // If there's no next line, handle the case
                    formattedOutput += `- ${currentLine} = [Missing event count] event(s) [severity: ]\n`;
                }
            }
        }
    }
    return formattedOutput;
}

function ceefFormatLogs(){
    
}

module.exports = { formatLogs, ceefFormatLogs };