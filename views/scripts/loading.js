async function fetchingData(call) {
    // Show the loading overlay
    document.getElementById('loading-overlay').removeAttribute('hidden');
    document.getElementById('data-container').setAttribute('hidden', true);
    document.getElementById("refreshButton").classList.add('fa-spin');

    try {
       // Fetch data from the server
       
       const response = await fetch(call); // Await the response
       if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
       }

       location.reload();
       
    } catch (error) {
       console.error('Error fetching data:', error);
       alert('Failed to load data');
    }
 }

 function hasData() {
    // Show the data container
    document.getElementById('data-container').removeAttribute('hidden');
    document.getElementById('loading-overlay').setAttribute('hidden', true);
    document.getElementById('refreshButton').classList.remove('fa-spin');
 }