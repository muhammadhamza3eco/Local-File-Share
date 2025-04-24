// Custom ripple and focus effects removed as Material UI styling/components handle this.
// Add any application-specific client-side logic here if needed in the future.

document.addEventListener('DOMContentLoaded', function() {
    // Script for showing/hiding upload/create folder forms (Keep this part)
    const uploadBtn = document.getElementById('showUploadFormBtn');
    const createFolderBtn = document.getElementById('showCreateFolderFormBtn');
    const uploadForm = document.getElementById('uploadFormContainer');
    const createFolderForm = document.getElementById('createFolderFormContainer');
    const fileInput = document.getElementById('fileToUpload');
    const fileNameDisplay = document.getElementById('fileNameDisplay');

    if (uploadBtn && uploadForm) {
        uploadBtn.addEventListener('click', () => {
            uploadForm.style.display = 'block';
            if (createFolderForm) createFolderForm.style.display = 'none'; // Hide other form
        });
    }

    if (createFolderBtn && createFolderForm) {
        createFolderBtn.addEventListener('click', () => {
            createFolderForm.style.display = 'block';
            if (uploadForm) uploadForm.style.display = 'none'; // Hide other form
        });
    }

    // Display chosen file name
    if (fileInput && fileNameDisplay) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                fileNameDisplay.textContent = fileInput.files[0].name;
            } else {
                fileNameDisplay.textContent = '';
            }
        });
    }
});

// Function to hide forms (Keep this part)
function hideForm(formId) {
    const formContainer = document.getElementById(formId);
    if (formContainer) {
        formContainer.style.display = 'none';
        // Clear file input if hiding upload form
        if (formId === 'uploadFormContainer') {
             const fileInput = document.getElementById('fileToUpload');
             const fileNameDisplay = document.getElementById('fileNameDisplay');
             if(fileInput) fileInput.value = ''; // Clear the selected file
             if(fileNameDisplay) fileNameDisplay.textContent = ''; // Clear the displayed name
        }
    }
}

// Note: Password toggle scripts remain within login.ejs and signup.ejs as they are specific to those pages.
// Note: Log/File filtering scripts remain within activity-log.ejs and shared-public.ejs.
// --- Real-time Clock Display ---
function updateTime() {
    const timeDisplay = document.getElementById('current-time-display');
    if (timeDisplay) {
        const now = new Date();
        // Format time as HH:MM:SS (e.g., 14:05:02)
        const timeString = now.toLocaleTimeString('en-US', { hour12: false });
        // Format date as short format (e.g., 4/24/2025)
        const dateString = now.toLocaleDateString('en-US', { year: 'numeric', month: 'numeric', day: 'numeric' });
        timeDisplay.textContent = `${dateString} ${timeString}`;
    }
}

// Update the time immediately on load
document.addEventListener('DOMContentLoaded', updateTime);
// Update the time every second
setInterval(updateTime, 1000);