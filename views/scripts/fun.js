
function generateRandomText() {
    // Random text generator
    const texts = [
        "MAX WANK A TANK MAX GAY",
        "KOH GER SAIL TO THE SEA, KOH GER SLAYYY",
    ];

    const randomIndex = Math.floor(Math.random() * texts.length);
    document.getElementById('random').innerText = texts[randomIndex];
}

function updatePosition(ship, posX, posY, speedX, speedY) {

    posX += speedX;
    posY += speedY;

    // Check for collision with walls
    if (posX + 100 > window.innerWidth || posX < 0) {
        speedX = -speedX; // Reverse direction
    }
    if (posY + 100 > window.innerHeight || posY < 0) {
        speedY = -speedY; // Reverse direction
    }

    // Update the position of the screensaver
    ship.style.left = posX + 'px';
    ship.style.top = posY + 'px';

    requestAnimationFrame(() => updatePosition(ship, posX, posY, speedX, speedY)); // Keep updating the position
}

function shipScreensaver() {
    // Ship screensaver
    const ship = document.getElementById('ship');

    if (!ship) {
        console.error("Element with ID 'ship' not found.");
        return;
    }

    let posX = Math.random() * window.innerWidth; // Random starting x position
    let posY = Math.random() * window.innerHeight; // Random starting y position
    let speedX = 2; // Speed in x direction
    let speedY = 2; // Speed in y direction

    ship.style.position = 'absolute'; // Ensure it's positioned correctly

    updatePosition(ship, posX, posY, speedX, speedY);
}

// Things to run
function randombs() {
    shipScreensaver();
    generateRandomText();
}