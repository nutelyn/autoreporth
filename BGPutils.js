// Cache var
let cache = new Map();
// Cache for 1 hour (in ms)
const CACHE_EXPIRY = 60 * 60 * 1000;

/* All Dewaweb's IP Blocks */
const nmePrefixes = {
    '103.145.227.0/24': 'Dewaweb SG Servers',
    '103.152.243.0/24': 'Dewaweb SG Servers',
    '103.167.137.0/24': 'Dewacloud'
};
const mtenPrefixes = {
    '103.185.52.0/24': 'DewaVPS',
    '103.145.226.0/24': 'DewaVPS',
    '103.152.242.0/24': 'DewaVPS',
    '103.185.53.0/24': 'Dewaweb JKT Servers & Managed Customers',
    '103.167.136.0/24': 'Dewacloud',
    '103.185.44.0/24': 'Dewacloud',
}
const edgePrefixes = {
    '103.167.132.0/24': 'Dewacloud',
    '103.185.38.0/24': 'Dewacloud'
}
const contaboPrefixes = {
    '154.12.240.0/21': 'sea01.dewaweb.com',
    '85.239.232.0/21': 'sea02.dewaweb.com'
}

// Function to add labels to each prefix based on which source object they come from
function addAttrToPrefixes(prefixes, label, monitoring) {
    const labeledPrefixes = {};
    for (const [prefix, desc] of Object.entries(prefixes)) {
        labeledPrefixes[prefix] = {
            description: desc,
            label: label,
            monitoring: monitoring
        };
    }
    return labeledPrefixes;
}

/* Stormwall Checking
Finding out whether or not prefix is on stormwall */
function stormwallCheck(upstreams){

    // Check whether or not there is a stormwall upstream
    let isStormwall = false;
    upstreams.forEach(upstream => {
        if(upstream.asn === 59796) {
            isStormwall = true;
        }
    });

    // Logic for stormwall status
    if(isStormwall && (upstreams.length === 1)){
        return 'Full Stormwall';
    } else if (isStormwall && (upstreams.length > 1)) {
        return 'Partial Stormwall';
    } else {
        return 'No Stormwall';
    }
}

async function fetchData(prefix, url){

    let retries = 3; // Number of retry attempts
    let delay = 1000; // Initial delay in milliseconds

    while(retries > 0) {

        try {

            const headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive"
            };

            const response = await fetch(url, {
                method: 'GET',
                headers: headers
            });
    
            if (response.ok) {
                return await response.json();
            } else if (response.status === 429){
                const retryAfter = response.headers.get('Retry-after');
                const waitTime = retryAfter ? parseInt(retryAfter, 10) * 1000 : delay;
                console.warn(`Rate limited. Retrying in ${waitTime}s...`);

                // Wait before retrying
                await new Promise((resolve) => setTimeout(resolve, waitTime));
                // Exponential backoff
                delay *= 2; 
                retries--;
            } else {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
        } catch (error) {
            console.error(`Error fetching ${prefix}: ${error.message}`);
            retries--;
        }
    }

    console.error(`Failed to fetch data for prefix: ${prefix} after retries.`);
    // Return null if all retries fail
    return null;
}

/* Setup a delay */
async function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/* Get cache timestamp */
function cacheDiff() {
    let cachedData = null;
    if (cache.get('tableData')){
        cachedData = cache.get('tableData');

        const minute = 1000 * 60;
        const hour = minute * 60;
        const day = hour * 24;
        const year = day * 365;

        diffTime = Date.now() - cachedData.timestamp;
        diffTime = diffTime / minute;

        return Math.round(diffTime);
    } else {
        return null;
    }
}

/* Send an API request to bgpview.io
Process the request in a table format used in network page */
async function fetchBGPAPI(destroyCache){

    // Combine all prefixes to a list and add label
    const allPrefixes = {
        ...addAttrToPrefixes(nmePrefixes, 'NME Equinix SG, Singapore (mrtg.newmediaexpress.com)', 'mrtg.newmediaexpress.com'),
        ...addAttrToPrefixes(mtenPrefixes, 'NEX DC M-TEN Jakarta (prtg.cloudata.co.id)', 'prtg.cloudata.co.id'),
        ...addAttrToPrefixes(edgePrefixes, 'Edge2 DC, Kuningan, Jakarta (prtg-netmon.indo.net.id)', 'prtg-netmon.indo.net.id'),
        ...addAttrToPrefixes(contaboPrefixes, 'Contabo, Seattle, USA (prtg-netmon.indo.net.id)', 'prtg-netmon.indo.net.id')
    };

    // Array to store results in JSON 
    let results = [];

    if (destroyCache) {
        cache = new Map();
    }
    
    // Check if cached data exists and is still valid
    let cachedData = null;
    if (cache.get('tableData')){
        cachedData = cache.get('tableData');
    }
    if(cachedData && (Date.now() - cachedData.timestamp) < CACHE_EXPIRY) {
        console.log("Serving data from cache.");
        // Returning cached data if valid
        return cachedData.data;
    }
    
    // If no valid cache, fetch data
    for (const [prefix, attr] of Object.entries(allPrefixes)) {
        const url = new URL(`https://api.bgpview.io/prefix/${prefix}`);
        const desc = attr.description;
        const label = attr.label;
        const monitoring = attr.monitoring;

        const data = await fetchData(prefix, url);
        const upstreams = data.data.asns[0].prefix_upstreams;
        const stormwall = stormwallCheck(upstreams);

        upstreams.forEach(upstream => {
            // Find an existing entry with the same prefix, desc, and stormwall
            const existingEntry = results.find(result => 
                result.prefix === prefix &&
                result.desc === desc &&
                result.stormwall === stormwall &&
                result.label === label &&
                result.monitoring === monitoring
            );

            if (existingEntry) {
                existingEntry.upstream += `#${upstream.description} (AS${upstream.asn})`;
            } else {
                results.push({
                    prefix,
                    desc,
                    upstream: `${upstream.description} (AS${upstream.asn})`,
                    stormwall,
                    label,
                    monitoring
                });
            }
        });

        // Wait 0.5 second
        await delay(500);
    }

    // Cache the fetched data
    cache.set('tableData', {
        data: results,
        // Update the timestamp for cache expiry
        timestamp: Date.now()
    });

    return results;
}

module.exports = { fetchBGPAPI, cacheDiff };