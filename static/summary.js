document.addEventListener("submit", (event) => {
    const form = event.target.closest(".summary-form");
    if (!form || form.dataset.submitting === "true") {
        if (form) event.preventDefault();
        return;
    }

    form.dataset.submitting = "true";
    form.setAttribute("aria-busy", "true");
    const button = form.querySelector(".summary-submit");
    const regularLabel = form.querySelector(".submit-label");
    const loadingLabel = form.querySelector(".loading-label");
    const status = form.querySelector(".loading-status");
    if (button) button.disabled = true;
    if (regularLabel) regularLabel.hidden = true;
    if (loadingLabel) loadingLabel.hidden = false;
    if (status) status.textContent = "Retrieving ranked records and generating a validated summary.";
});

window.addEventListener("pageshow", (event) => {
    if (event.persisted && document.querySelector('.summary-form[data-submitting="true"]')) {
        window.location.reload();
    }
});
