let timeoutId; // Variable to hold the timeout
function showPopupAlert(message) {
    const popup = document.getElementById("popup-alert");
    const popupContent = popup.querySelector("p");
    const loadingBar = popup.querySelector(".loading-bar");

    // Reset the loading bar animation
    loadingBar.style.animation = "none"; // Stop animation
    void loadingBar.offsetWidth; // Trigger reflow to reset animation
    loadingBar.style.animation = "load 5s linear forwards"; // Restart animation

    // Set the message
    popupContent.textContent = message;

    // Show the alert
    popup.classList.add("visible");

    // Clear any existing timeout to prevent overlaps
    if (timeoutId) {
        clearTimeout(timeoutId);
    }

    // Hide the alert after 5 seconds
    timeoutId = setTimeout(() => {
        popup.classList.remove("visible");
    }, 5000);
}