const analysisForm = document.querySelector("#ip-analysis-form");
const analyzeButton = document.querySelector("#analyze-button");
const loadingState = document.querySelector("#analysis-loading");

// Display logic for the loading state: after valid browser-side input, prevent
// duplicate submissions and keep the user informed during the server/API call.
if (analysisForm && analyzeButton && loadingState) {
    analysisForm.addEventListener("submit", () => {
        if (!analysisForm.checkValidity()) {
            return;
        }

        analysisForm.setAttribute("aria-busy", "true");
        analyzeButton.disabled = true;
        analyzeButton.textContent = "Analyzing...";
        loadingState.hidden = false;
    });

    // Browsers can restore a page from history with its prior disabled state.
    window.addEventListener("pageshow", () => {
        analysisForm.removeAttribute("aria-busy");
        analyzeButton.disabled = false;
        analyzeButton.textContent = "Analyze IP";
        loadingState.hidden = true;
    });
}
