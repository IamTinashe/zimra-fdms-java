package com.zimra.fdms.exception;

/**
 * Network exception for HTTP transport layer failures
 * 
 * <p>Represents network-related errors that occur during HTTP communication.
 * Includes information about whether the error is retryable.
 */
public class NetworkException extends FdmsException {
    
    /**
     * Network error codes
     */
    public enum NetworkErrorCode {
        TIMEOUT("NET01", "Request timed out"),
        CONNECTION_REFUSED("NET02", "Connection refused"),
        DNS_LOOKUP_FAILED("NET03", "DNS lookup failed"),
        SSL_ERROR("NET04", "SSL/TLS error"),
        CIRCUIT_BREAKER_OPEN("NET05", "Circuit breaker is open"),
        NO_RESPONSE("NET06", "No response received"),
        REQUEST_ABORTED("NET07", "Request was aborted"),
        UNKNOWN("NET10", "Unknown network error");
        
        private final String code;
        private final String defaultMessage;
        
        NetworkErrorCode(String code, String defaultMessage) {
            this.code = code;
            this.defaultMessage = defaultMessage;
        }
        
        public String getCode() {
            return code;
        }
        
        public String getDefaultMessage() {
            return defaultMessage;
        }
    }
    
    private final String networkCode;
    private final boolean retryable;
    
    /**
     * Create a network exception
     * 
     * @param message Error message
     */
    public NetworkException(String message) {
        this(message, null, NetworkErrorCode.UNKNOWN.getCode(), true);
    }
    
    /**
     * Create a network exception with status code
     * 
     * @param message Error message
     * @param statusCode HTTP status code
     */
    public NetworkException(String message, Integer statusCode) {
        this(message, statusCode, NetworkErrorCode.UNKNOWN.getCode(), true);
    }
    
    /**
     * Create a network exception with full details
     * 
     * @param message Error message
     * @param statusCode HTTP status code
     * @param networkCode Network error code
     * @param retryable Whether the error is retryable
     */
    public NetworkException(String message, Integer statusCode, String networkCode, boolean retryable) {
        super(message, networkCode, statusCode);
        this.networkCode = networkCode;
        this.retryable = retryable;
    }
    
    /**
     * Get the network error code
     */
    public String getNetworkCode() {
        return networkCode;
    }
    
    /**
     * Check if this error is retryable
     */
    public boolean isRetryable() {
        return retryable;
    }
    
    /**
     * Create a timeout error
     * 
     * @param message Error message
     * @return NetworkException for timeout
     */
    public static NetworkException timeout(String message) {
        return new NetworkException(
            message != null ? message : NetworkErrorCode.TIMEOUT.getDefaultMessage(),
            408,
            NetworkErrorCode.TIMEOUT.getCode(),
            true
        );
    }
    
    /**
     * Create a timeout error with default message
     * 
     * @return NetworkException for timeout
     */
    public static NetworkException timeout() {
        return timeout(null);
    }
    
    /**
     * Create a connection refused error
     * 
     * @param message Error message
     * @return NetworkException for connection refused
     */
    public static NetworkException connectionRefused(String message) {
        return new NetworkException(
            message != null ? message : NetworkErrorCode.CONNECTION_REFUSED.getDefaultMessage(),
            null,
            NetworkErrorCode.CONNECTION_REFUSED.getCode(),
            true
        );
    }
    
    /**
     * Create a connection refused error with default message
     * 
     * @return NetworkException for connection refused
     */
    public static NetworkException connectionRefused() {
        return connectionRefused(null);
    }
    
    /**
     * Create a circuit breaker open error
     * 
     * @param retryAfterSeconds Seconds until retry is allowed
     * @return NetworkException for circuit breaker open
     */
    public static NetworkException circuitBreakerOpen(int retryAfterSeconds) {
        return new NetworkException(
            String.format("Circuit breaker is open. Retry after %d seconds", retryAfterSeconds),
            503,
            NetworkErrorCode.CIRCUIT_BREAKER_OPEN.getCode(),
            false
        );
    }
    
    /**
     * Create an SSL error
     * 
     * @param message Error message
     * @return NetworkException for SSL error
     */
    public static NetworkException sslError(String message) {
        return new NetworkException(
            message != null ? message : NetworkErrorCode.SSL_ERROR.getDefaultMessage(),
            null,
            NetworkErrorCode.SSL_ERROR.getCode(),
            false
        );
    }
    
    /**
     * Create an SSL error with default message
     * 
     * @return NetworkException for SSL error
     */
    public static NetworkException sslError() {
        return sslError(null);
    }
    
    /**
     * Create a DNS lookup failed error
     * 
     * @param hostname The hostname that failed to resolve
     * @return NetworkException for DNS lookup failure
     */
    public static NetworkException dnsLookupFailed(String hostname) {
        return new NetworkException(
            String.format("DNS lookup failed for host: %s", hostname),
            null,
            NetworkErrorCode.DNS_LOOKUP_FAILED.getCode(),
            true
        );
    }
}
