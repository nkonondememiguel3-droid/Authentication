package e.dream.learn.authentification.exception;

import e.dream.learn.authentification.model.dto.ApiErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Catches wrong password, unapproved MAC address, or invalid token errors.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleBadCredentials(BadCredentialsException ex) {
        log.warn("Authentication failure: {}", ex.getMessage());
        return buildResponse(HttpStatus.UNAUTHORIZED, "Unauthorized Access", ex.getMessage());
    }

    /**
     * Catches instances where a user account exists but has been deactivated (is_enabled = false).
     */
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ApiErrorResponse> handleDisabledAccount(DisabledException ex) {
        log.warn("Login blocked: Account is disabled.");
        return buildResponse(HttpStatus.FORBIDDEN, "Account Disabled", "Your account has been deactivated. Please contact an administrator.");
    }

    /**
     * Catches lookup failures if a token references an email/username that doesn't exist anymore.
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleUserNotFound(UsernameNotFoundException ex) {
        log.warn("User profile lookup failed: {}", ex.getMessage());
        return buildResponse(HttpStatus.NOT_FOUND, "Not Found", ex.getMessage());
    }

    /**
     * Catches role-based permission failures (e.g., an employee trying to access an administrator route via @PreAuthorize).
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        log.warn("RBAC Authorization blocked: User lacks required role privileges.");
        return buildResponse(HttpStatus.FORBIDDEN, "Access Denied", "You do not have the required permissions to perform this operation.");
    }

    /**
     * Ultimate fallback handler to catch unhandled bugs (e.g., database connection drops, null pointers).
     * This keeps the desktop application from crashing by passing a generic 500 error code.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleGenericException(Exception ex) {
        log.error("Unhandled systemic server error occurred:", ex);
        return buildResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected internal error occurred on the server. Please try again later."
        );
    }

    // Helper method to keep code clean and uniform
    private ResponseEntity<ApiErrorResponse> buildResponse(HttpStatus status, String error, String message) {
        ApiErrorResponse responseBody = new ApiErrorResponse(
                status.value(),
                error,
                message,
                LocalDateTime.now()
        );
        return new ResponseEntity<>(responseBody, status);
    }
}
