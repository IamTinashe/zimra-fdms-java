package com.zimra.fdms.client;

import java.util.Set;
import java.util.function.Predicate;

/**
 * Retry policy configuration for HTTP requests
 * 
 * <p>Configures how the HTTP client handles retries for failed requests.
 * Supports exponential backoff with configurable parameters.
 * 
 * <p>Example usage:
 * <pre>{@code
 * RetryPolicy policy = RetryPolicy.builder()
 *     .maxAttempts(3)
 *     .baseDelay(1000)
 *     .maxDelay(16000)
 *     .retryableStatusCodes(Set.of(408, 429, 500, 502, 503, 504))
 *     .build();
 * }</pre>
 */
public class RetryPolicy {
    
    private final int maxAttempts;
    private final long baseDelay; // milliseconds
    private final long maxDelay; // milliseconds
    private final Set<Integer> retryableStatusCodes;
    private final Predicate<Exception> retryablePredicate;
    private final boolean retryOnConnectionFailure;
    private final boolean retryOnTimeout;
    
    /**
     * Default retryable HTTP status codes
     */
    public static final Set<Integer> DEFAULT_RETRYABLE_STATUS_CODES = Set.of(
        408, // Request Timeout
        429, // Too Many Requests
        500, // Internal Server Error
        502, // Bad Gateway
        503, // Service Unavailable
        504  // Gateway Timeout
    );
    
    private RetryPolicy(Builder builder) {
        this.maxAttempts = builder.maxAttempts;
        this.baseDelay = builder.baseDelay;
        this.maxDelay = builder.maxDelay;
        this.retryableStatusCodes = builder.retryableStatusCodes;
        this.retryablePredicate = builder.retryablePredicate;
        this.retryOnConnectionFailure = builder.retryOnConnectionFailure;
        this.retryOnTimeout = builder.retryOnTimeout;
    }
    
    /**
     * Create a new builder for RetryPolicy
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Create a default retry policy
     */
    public static RetryPolicy defaultPolicy() {
        return builder().build();
    }
    
    /**
     * Create a policy with no retries
     */
    public static RetryPolicy noRetry() {
        return builder()
            .maxAttempts(1)
            .build();
    }
    
    /**
     * Calculate delay for a given attempt using exponential backoff
     * 
     * @param attempt The current attempt number (0-based)
     * @return The delay in milliseconds
     */
    public long calculateDelay(int attempt) {
        // Exponential backoff: baseDelay * 2^attempt
        long delay = (long) (baseDelay * Math.pow(2, attempt));
        return Math.min(delay, maxDelay);
    }
    
    /**
     * Check if a given HTTP status code is retryable
     * 
     * @param statusCode The HTTP status code
     * @return true if the status code is retryable
     */
    public boolean isRetryableStatusCode(int statusCode) {
        return retryableStatusCodes.contains(statusCode);
    }
    
    /**
     * Check if an exception is retryable
     * 
     * @param exception The exception to check
     * @return true if the exception is retryable
     */
    public boolean isRetryable(Exception exception) {
        if (retryablePredicate != null) {
            return retryablePredicate.test(exception);
        }
        
        // Default behavior
        String className = exception.getClass().getName();
        
        if (retryOnTimeout && className.contains("Timeout")) {
            return true;
        }
        
        if (retryOnConnectionFailure && (
            className.contains("ConnectException") ||
            className.contains("ConnectionException") ||
            className.contains("SocketException")
        )) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if another retry attempt should be made
     * 
     * @param currentAttempt The current attempt number (0-based)
     * @return true if another attempt should be made
     */
    public boolean shouldRetry(int currentAttempt) {
        return currentAttempt < maxAttempts - 1;
    }
    
    // Getters
    
    public int getMaxAttempts() {
        return maxAttempts;
    }
    
    public long getBaseDelay() {
        return baseDelay;
    }
    
    public long getMaxDelay() {
        return maxDelay;
    }
    
    public Set<Integer> getRetryableStatusCodes() {
        return retryableStatusCodes;
    }
    
    public boolean isRetryOnConnectionFailure() {
        return retryOnConnectionFailure;
    }
    
    public boolean isRetryOnTimeout() {
        return retryOnTimeout;
    }
    
    /**
     * Builder for RetryPolicy
     */
    public static class Builder {
        private int maxAttempts = 4; // 3 retries + 1 initial attempt
        private long baseDelay = 1000;
        private long maxDelay = 16000;
        private Set<Integer> retryableStatusCodes = DEFAULT_RETRYABLE_STATUS_CODES;
        private Predicate<Exception> retryablePredicate;
        private boolean retryOnConnectionFailure = true;
        private boolean retryOnTimeout = true;
        
        /**
         * Set maximum number of attempts (including initial attempt)
         * 
         * @param maxAttempts Number of attempts (1 = no retries)
         */
        public Builder maxAttempts(int maxAttempts) {
            if (maxAttempts < 1) {
                throw new IllegalArgumentException("maxAttempts must be at least 1");
            }
            this.maxAttempts = maxAttempts;
            return this;
        }
        
        /**
         * Set base delay for exponential backoff
         * 
         * @param baseDelay Base delay in milliseconds
         */
        public Builder baseDelay(long baseDelay) {
            if (baseDelay < 0) {
                throw new IllegalArgumentException("baseDelay must be non-negative");
            }
            this.baseDelay = baseDelay;
            return this;
        }
        
        /**
         * Set maximum delay cap
         * 
         * @param maxDelay Maximum delay in milliseconds
         */
        public Builder maxDelay(long maxDelay) {
            if (maxDelay < 0) {
                throw new IllegalArgumentException("maxDelay must be non-negative");
            }
            this.maxDelay = maxDelay;
            return this;
        }
        
        /**
         * Set retryable HTTP status codes
         * 
         * @param statusCodes Set of retryable status codes
         */
        public Builder retryableStatusCodes(Set<Integer> statusCodes) {
            this.retryableStatusCodes = statusCodes;
            return this;
        }
        
        /**
         * Set custom retryable predicate for exceptions
         * 
         * @param predicate Predicate to determine if exception is retryable
         */
        public Builder retryablePredicate(Predicate<Exception> predicate) {
            this.retryablePredicate = predicate;
            return this;
        }
        
        /**
         * Enable or disable retry on connection failure
         * 
         * @param retry true to retry on connection failures
         */
        public Builder retryOnConnectionFailure(boolean retry) {
            this.retryOnConnectionFailure = retry;
            return this;
        }
        
        /**
         * Enable or disable retry on timeout
         * 
         * @param retry true to retry on timeouts
         */
        public Builder retryOnTimeout(boolean retry) {
            this.retryOnTimeout = retry;
            return this;
        }
        
        /**
         * Build the RetryPolicy
         */
        public RetryPolicy build() {
            return new RetryPolicy(this);
        }
    }
}
