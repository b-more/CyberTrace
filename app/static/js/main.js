// CyberTrace OSINT Platform - Main JavaScript

$(document).ready(function() {
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        $('.alert').fadeOut('slow');
    }, 5000);

    // Confirm dialog for dangerous actions
    $('.confirm-action').click(function(e) {
        if (!confirm('Are you sure you want to perform this action?')) {
            e.preventDefault();
        }
    });
});
