document.querySelectorAll('[data-mitigation-field], [data-threat-name-field], [data-category-field]').forEach((field) => {
    const select = field.querySelector('select');
    const other = field.querySelector('[data-mitigation-other], [data-threat-name-other], [data-category-other]');
    const text = other.querySelector('input, textarea');
    const update = () => {
        const isOther = select.value === 'other';
        other.hidden = !isOther;
        text.required = isOther;
        text.disabled = !isOther;
    };
    select.addEventListener('change', update);
    update();
});

document.querySelectorAll('form[data-threat-save]').forEach((form) => {
    form.addEventListener('submit', (event) => {
        if (form.dataset.saving === 'true') {
            event.preventDefault();
            return;
        }
        form.dataset.saving = 'true';
        form.querySelectorAll('button[type="submit"]').forEach((button) => {
            button.disabled = true;
            button.textContent = 'Saving…';
        });
    });
});

window.addEventListener('pageshow', () => {
    document.querySelectorAll('form[data-threat-save]').forEach((form) => {
        delete form.dataset.saving;
        form.querySelectorAll('button[type="submit"]').forEach((button) => {
            button.disabled = false;
            button.textContent = 'Save threat';
        });
    });
});
