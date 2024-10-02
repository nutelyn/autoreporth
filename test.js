function ceefFormatLogs(inputText){
    // Predefined
    let date = getDate();
    let predef = `Kami infokan ada serangan yang berlangsung pada ${date} sejak pukul [WAKTU] dan sudah ditangani CloudFlare. Untuk informasi lebih detail sebagai berikut:
\n\n`;

    // Preparing the inputs for parsing
    const lines = inputText.split('\n');
    let formattedOutput = '';

    // Parsing
    for (let i = 0; i < lines.length; i++){
        let currentLine = lines[i].trim();
        // If some dummy paste it in
        if (currentLine === "Topeventsbysource"){
            i++;
            continue;
        }
        // If for some reason the input is empty
        switch (currentLine){
            case "SourceIPAddresses":
                formattedOutput += "# Top IP Addresses\n";
                i++;
                while(currentLine != "UserAgents"){
                    formattedOutput += currentLine;
                    i += 2;
                }
                break;
        }

}
return formattedOutput;
}

let inputText = prompt("INPUT:");
console.log(ceefFormatLogs(inputText));