const predefinedText =
`hello, this is kacang

# Top 10 HIDS
Unexpected error while resolving domain    
4,662
OpenLDAP connection open    
3,723
Successful sudo to ROOT executed    
488
Unknown OSSEC Event    
430
OpenLDAP authentication failed    
275
User authentication failure    
200
Listened ports status changed    
188
Windows Logon Success    
181
Login session opened    
64
Login session closed    
62

# Top 10 NIDS
Potentially Bad Traffic    
145,900
stream5: TCP Small Segment Threshold Exceeded    
7,883
Reset Outside Window    
7,854
GPL SNMP public access udp    
3,082
GPL WEB_SERVER 403 Forbidden    
731
INDICATOR-COMPROMISE 403 Forbidden    
731
NO CONTENT-LENGTH OR TRANSFER-ENCODING IN HTTP RESPONSE    
609
ET POLICY Vulnerable Java Version 1.7.x Detected    
582
ET SCAN Suspicious inbound to Oracle SQL port 1521    
471
ET POLICY Windows Update P2P Activity    
383`;

function formatLogs(inputText) {
    const lines = inputText.split('\n');
    let formattedOutput = '';

    for (let i = 0; i < lines.length; i += 2) {
        const message = lines[i];
        const events = lines[i + 1] || '';
        formattedOutput += `- ${message.trim()} = ${events.trim()} event(s) [severity: ]\n`
    }

    return formattedOutput;
}

let formattedText = formatLogs(predefinedText);
console.log(formattedText);