// Log Quality Analyzer JavaScript

// Global variables
let uploadInProgress = false;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeFileUpload();
    initializeTooltips();
    initializeCopyFeatures();
    initializeDragAndDrop();
});

// Initialize file upload functionality
function initializeFileUpload() {
    const fileInput = document.getElementById('file');
    const uploadForm = document.getElementById('uploadForm');
    
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelection);
    }
    
    if (uploadForm) {
        uploadForm.addEventListener('submit', handleFormSubmit);
    }
}

// Handle file selection
function handleFileSelection(event) {
    const file = event.target.files[0];
    const maxSize = 16 * 1024 * 1024; // 16MB
    
    if (file) {
        // Validate file size
        if (file.size > maxSize) {
            showAlert('File size exceeds 16MB limit. Please select a smaller file.', 'warning');
            event.target.value = '';
            return;
        }
        
        // Validate file type
        const allowedTypes = ['text/plain', 'application/octet-stream'];
        const allowedExtensions = ['.txt', '.log'];
        const fileName = file.name.toLowerCase();
        const hasValidExtension = allowedExtensions.some(ext => fileName.endsWith(ext));
        
        if (!hasValidExtension) {
            showAlert('Invalid file type. Please upload .txt or .log files only.', 'warning');
            event.target.value = '';
            return;
        }
        
        // Display file info
        displayFileInfo(file);
    }
}

// Display selected file information
function displayFileInfo(file) {
    const fileSize = formatFileSize(file.size);
    const fileInfo = `Selected: ${file.name} (${fileSize})`;
    
    // Update form text or create info element
    const existingInfo = document.getElementById('file-info');
    if (existingInfo) {
        existingInfo.textContent = fileInfo;
    } else {
        const infoElement = document.createElement('div');
        infoElement.id = 'file-info';
        infoElement.className = 'mt-2 text-muted small';
        infoElement.textContent = fileInfo;
        document.getElementById('file').parentNode.appendChild(infoElement);
    }
}

// Format file size for display
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Handle form submission
function handleFormSubmit(event) {
    const submitBtn = document.getElementById('submitBtn');
    
    if (uploadInProgress) {
        event.preventDefault();
        return;
    }
    
    uploadInProgress = true;
    
    if (submitBtn) {
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
        submitBtn.disabled = true;
        
        // Re-enable button if form submission fails
        setTimeout(function() {
            if (uploadInProgress) {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
                uploadInProgress = false;
            }
        }, 30000); // 30 second timeout
    }
}

// Initialize tooltips
function initializeTooltips() {
    const tooltipElements = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipElements.forEach(function(element) {
        new bootstrap.Tooltip(element);
    });
}

// Initialize copy-to-clipboard features
function initializeCopyFeatures() {
    const codeBlocks = document.querySelectorAll('code');
    codeBlocks.forEach(function(codeBlock) {
        codeBlock.style.cursor = 'pointer';
        codeBlock.title = 'Click to copy';
        codeBlock.addEventListener('click', function() {
            copyToClipboard(codeBlock.textContent, codeBlock);
        });
    });
}

// Copy text to clipboard
function copyToClipboard(text, element) {
    if (navigator.clipboard && window.isSecureContext) {
        // Use modern clipboard API
        navigator.clipboard.writeText(text).then(function() {
            showCopyFeedback(element);
        }).catch(function(err) {
            console.error('Failed to copy: ', err);
            fallbackCopyToClipboard(text, element);
        });
    } else {
        // Fallback for older browsers
        fallbackCopyToClipboard(text, element);
    }
}

// Fallback copy method for older browsers
function fallbackCopyToClipboard(text, element) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showCopyFeedback(element);
    } catch (err) {
        console.error('Fallback: Could not copy text: ', err);
    }
    
    document.body.removeChild(textArea);
}

// Show visual feedback for copy action
function showCopyFeedback(element) {
    const originalText = element.textContent;
    const originalTitle = element.title;
    
    element.textContent = 'Copied!';
    element.title = 'Copied to clipboard';
    element.style.backgroundColor = '#28a745';
    element.style.color = 'white';
    
    setTimeout(function() {
        element.textContent = originalText;
        element.title = originalTitle;
        element.style.backgroundColor = '';
        element.style.color = '';
    }, 1500);
}

// Initialize drag and drop functionality
function initializeDragAndDrop() {
    const uploadZone = document.querySelector('.upload-zone, .card-body');
    const fileInput = document.getElementById('file');
    
    if (uploadZone && fileInput) {
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });
        
        // Highlight drop zone when item is dragged over it
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadZone.addEventListener(eventName, highlight, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, unhighlight, false);
        });
        
        // Handle dropped files
        uploadZone.addEventListener('drop', handleDrop, false);
    }
}

// Prevent default drag behaviors
function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

// Highlight upload zone
function highlight(e) {
    e.currentTarget.classList.add('dragover');
}

// Remove highlight from upload zone
function unhighlight(e) {
    e.currentTarget.classList.remove('dragover');
}

// Handle dropped files
function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    
    if (files.length > 0) {
        const fileInput = document.getElementById('file');
        if (fileInput) {
            fileInput.files = files;
            handleFileSelection({ target: fileInput });
        }
    }
}

// Show alert messages
function showAlert(message, type = 'info') {
    // Remove existing alerts
    const existingAlerts = document.querySelectorAll('.alert.auto-alert');
    existingAlerts.forEach(alert => alert.remove());
    
    // Create new alert
    const alertElement = document.createElement('div');
    alertElement.className = `alert alert-${type} alert-dismissible fade show auto-alert`;
    alertElement.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert alert at top of container
    const container = document.querySelector('.container');
    if (container) {
        container.insertBefore(alertElement, container.firstChild);
    }
    
    // Auto-dismiss after 5 seconds
    setTimeout(function() {
        if (alertElement.parentNode) {
            alertElement.remove();
        }
    }, 5000);
}

// API Helper Functions
const API = {
    // Analyze log file via API
    analyze: async function(file) {
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API analysis error:', error);
            throw error;
        }
    },
    
    // Get current rules
    getRules: async function() {
        try {
            const response = await fetch('/api/rules');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('API get rules error:', error);
            throw error;
        }
    },
    
    // Update rules
    updateRules: async function(rules) {
        try {
            const response = await fetch('/api/rules', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(rules)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API update rules error:', error);
            throw error;
        }
    },
    
    // Get analysis history
    getHistory: async function() {
        try {
            const response = await fetch('/api/history');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('API get history error:', error);
            throw error;
        }
    }
};

// Utility Functions
const Utils = {
    // Debounce function for input events
    debounce: function(func, wait, immediate) {
        let timeout;
        return function executedFunction() {
            const context = this;
            const args = arguments;
            const later = function() {
                timeout = null;
                if (!immediate) func.apply(context, args);
            };
            const callNow = immediate && !timeout;
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
            if (callNow) func.apply(context, args);
        };
    },
    
    // Format timestamp for display
    formatTimestamp: function(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    },
    
    // Validate YAML content
    isValidYAML: function(content) {
        try {
            // Basic validation - check for common YAML issues
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                if (line.trim() === '' || line.trim().startsWith('#')) {
                    continue;
                }
                if (line.includes('\t')) {
                    return { valid: false, error: `Line ${i + 1}: Tabs not allowed in YAML` };
                }
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, error: error.message };
        }
    }
};

// Export for use in other scripts
window.LogAnalyzer = {
    API: API,
    Utils: Utils,
    showAlert: showAlert
};