package com.zimra.fdms.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.zimra.fdms.config.FdmsConfig;
import com.zimra.fdms.exception.FdmsException;
import com.zimra.fdms.exception.NetworkException;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * HTTP transport layer for FDMS API
 * Handles all HTTP communication with retry logic, interceptors,
 * circuit breaker pattern, and connection pooling
 * 
 * <p>Features:
 * <ul>
 *   <li>Automatic retry with exponential backoff</li>
 *   <li>Circuit breaker pattern for resilience</li>
 *   <li>Request/response interceptors</li>
 *   <li>Request ID generation for traceability</li>
 *   <li>Comprehensive audit logging</li>
 *   <li>Connection keep-alive via connection pooling</li>
 * </ul>
 * 
 * <p>Example usage:
 * <pre>{@code
 * FdmsConfig config = FdmsConfig.builder()
 *     .deviceId("12345")
 *     .deviceModelName("TestDevice")
 *     .deviceModelVersion("1.0")
 *     // ... other config
 *     .build();
 * 
 * HttpClient client = new HttpClient(config);
 * HttpResponse response = client.get("/api/Device/12345/v1/GetStatus");
 * }</pre>
 */
public class HttpClient implements AutoCloseable {
    
    private static final Logger logger = LoggerFactory.getLogger(HttpClient.class);
    
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    
    private static final Set<String> SENSITIVE_FIELDS = Set.of(
        "authorization", "x-api-key", "privatekey", "private_key",
        "password", "activationkey", "activation_key", "certificate"
    );
    
    private final FdmsConfig config;
    private final OkHttpClient okHttpClient;
    private final ObjectMapper objectMapper;
    
    // Circuit breaker state
    private volatile CircuitState circuitState = CircuitState.CLOSED;
    private final AtomicInteger circuitFailureCount = new AtomicInteger(0);
    private final AtomicInteger circuitSuccessCount = new AtomicInteger(0);
    private final AtomicLong circuitOpenTime = new AtomicLong(0);
    private final CircuitBreakerConfig circuitConfig;
    
    // Custom interceptors
    private final List<Function<Request, Request>> requestInterceptors = new ArrayList<>();
    private final List<Function<Response, Response>> responseInterceptors = new ArrayList<>();
    
    // Audit logging callback
    private Consumer<HttpAuditEntry> auditLogCallback;
    
    /**
     * Circuit breaker states
     */
    public enum CircuitState {
        CLOSED,
        OPEN,
        HALF_OPEN
    }
    
    /**
     * Circuit breaker configuration
     */
    public static class CircuitBreakerConfig {
        private final int failureThreshold;
        private final long recoveryTimeout; // milliseconds
        private final int successThreshold;
        
        public CircuitBreakerConfig() {
            this(5, 30000, 3);
        }
        
        public CircuitBreakerConfig(int failureThreshold, long recoveryTimeout, int successThreshold) {
            this.failureThreshold = failureThreshold;
            this.recoveryTimeout = recoveryTimeout;
            this.successThreshold = successThreshold;
        }
        
        public int getFailureThreshold() { return failureThreshold; }
        public long getRecoveryTimeout() { return recoveryTimeout; }
        public int getSuccessThreshold() { return successThreshold; }
    }
    
    /**
     * HTTP response wrapper
     */
    public static class HttpResponse<T> {
        private final T data;
        private final int status;
        private final Map<String, String> headers;
        private final long duration;
        private final String requestId;
        
        public HttpResponse(T data, int status, Map<String, String> headers, long duration, String requestId) {
            this.data = data;
            this.status = status;
            this.headers = headers;
            this.duration = duration;
            this.requestId = requestId;
        }
        
        public T getData() { return data; }
        public int getStatus() { return status; }
        public Map<String, String> getHeaders() { return headers; }
        public long getDuration() { return duration; }
        public String getRequestId() { return requestId; }
    }
    
    /**
     * HTTP request options
     */
    public static class HttpRequestOptions {
        private Map<String, String> headers;
        private Map<String, String> params;
        private Integer timeout; // milliseconds
        private boolean skipRetry;
        private Map<String, Object> metadata;
        
        public HttpRequestOptions() {}
        
        public HttpRequestOptions headers(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }
        
        public HttpRequestOptions params(Map<String, String> params) {
            this.params = params;
            return this;
        }
        
        public HttpRequestOptions timeout(int timeout) {
            this.timeout = timeout;
            return this;
        }
        
        public HttpRequestOptions skipRetry(boolean skipRetry) {
            this.skipRetry = skipRetry;
            return this;
        }
        
        public HttpRequestOptions metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }
        
        public Map<String, String> getHeaders() { return headers; }
        public Map<String, String> getParams() { return params; }
        public Integer getTimeout() { return timeout; }
        public boolean isSkipRetry() { return skipRetry; }
        public Map<String, Object> getMetadata() { return metadata; }
    }
    
    /**
     * Audit log entry for HTTP requests
     */
    public static class HttpAuditEntry {
        private final String timestamp;
        private final String requestId;
        private final String method;
        private final String url;
        private final Map<String, String> headers;
        private final Object body;
        private final Map<String, Object> response;
        private final long duration;
        private final boolean success;
        private final String error;
        private final Integer retryAttempt;
        
        public HttpAuditEntry(Builder builder) {
            this.timestamp = builder.timestamp;
            this.requestId = builder.requestId;
            this.method = builder.method;
            this.url = builder.url;
            this.headers = builder.headers;
            this.body = builder.body;
            this.response = builder.response;
            this.duration = builder.duration;
            this.success = builder.success;
            this.error = builder.error;
            this.retryAttempt = builder.retryAttempt;
        }
        
        public static Builder builder() { return new Builder(); }
        
        // Getters
        public String getTimestamp() { return timestamp; }
        public String getRequestId() { return requestId; }
        public String getMethod() { return method; }
        public String getUrl() { return url; }
        public Map<String, String> getHeaders() { return headers; }
        public Object getBody() { return body; }
        public Map<String, Object> getResponse() { return response; }
        public long getDuration() { return duration; }
        public boolean isSuccess() { return success; }
        public String getError() { return error; }
        public Integer getRetryAttempt() { return retryAttempt; }
        
        public static class Builder {
            private String timestamp;
            private String requestId;
            private String method;
            private String url;
            private Map<String, String> headers;
            private Object body;
            private Map<String, Object> response;
            private long duration;
            private boolean success;
            private String error;
            private Integer retryAttempt;
            
            public Builder timestamp(String timestamp) { this.timestamp = timestamp; return this; }
            public Builder requestId(String requestId) { this.requestId = requestId; return this; }
            public Builder method(String method) { this.method = method; return this; }
            public Builder url(String url) { this.url = url; return this; }
            public Builder headers(Map<String, String> headers) { this.headers = headers; return this; }
            public Builder body(Object body) { this.body = body; return this; }
            public Builder response(Map<String, Object> response) { this.response = response; return this; }
            public Builder duration(long duration) { this.duration = duration; return this; }
            public Builder success(boolean success) { this.success = success; return this; }
            public Builder error(String error) { this.error = error; return this; }
            public Builder retryAttempt(Integer retryAttempt) { this.retryAttempt = retryAttempt; return this; }
            
            public HttpAuditEntry build() { return new HttpAuditEntry(this); }
        }
    }
    
    /**
     * Create a new HTTP client instance
     * 
     * @param config Resolved FDMS configuration
     */
    public HttpClient(FdmsConfig config) {
        this(config, new CircuitBreakerConfig());
    }
    
    /**
     * Create a new HTTP client instance with custom circuit breaker config
     * 
     * @param config Resolved FDMS configuration
     * @param circuitBreakerConfig Circuit breaker configuration
     */
    public HttpClient(FdmsConfig config, CircuitBreakerConfig circuitBreakerConfig) {
        this.config = Objects.requireNonNull(config, "Config must not be null");
        this.circuitConfig = Objects.requireNonNull(circuitBreakerConfig, "Circuit breaker config must not be null");
        
        // Configure ObjectMapper
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        
        // Build OkHttpClient with connection pooling and timeouts
        this.okHttpClient = new OkHttpClient.Builder()
            .connectTimeout(Duration.ofMillis(config.getTimeout()))
            .readTimeout(Duration.ofMillis(config.getTimeout()))
            .writeTimeout(Duration.ofMillis(config.getTimeout()))
            .connectionPool(new ConnectionPool(10, 5, TimeUnit.MINUTES))
            .addInterceptor(this::addDefaultHeaders)
            .retryOnConnectionFailure(false) // We handle retries ourselves
            .build();
    }
    
    /**
     * OkHttp interceptor to add default headers
     */
    private Response addDefaultHeaders(Interceptor.Chain chain) throws IOException {
        Request original = chain.request();
        
        Request.Builder builder = original.newBuilder()
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("DeviceModelName", config.getDeviceModelName())
            .header("DeviceModelVersionNo", config.getDeviceModelVersion());
        
        return chain.proceed(builder.build());
    }
    
    /**
     * Generate unique request ID for traceability
     */
    private String generateRequestId() {
        String timestamp = Long.toHexString(System.currentTimeMillis());
        String random = UUID.randomUUID().toString().substring(0, 8);
        return String.format("fdms-%s-%s", timestamp, random);
    }
    
    /**
     * Check circuit breaker state
     */
    private void checkCircuitBreaker() throws NetworkException {
        if (circuitState == CircuitState.OPEN) {
            long timeSinceOpen = System.currentTimeMillis() - circuitOpenTime.get();
            
            if (timeSinceOpen >= circuitConfig.getRecoveryTimeout()) {
                // Transition to half-open state
                circuitState = CircuitState.HALF_OPEN;
                circuitSuccessCount.set(0);
                logger.info("Circuit breaker transitioning to HALF_OPEN state");
            } else {
                int retryAfter = (int) Math.ceil((circuitConfig.getRecoveryTimeout() - timeSinceOpen) / 1000.0);
                throw new NetworkException(
                    String.format("Circuit breaker is open. Retry after %d seconds", retryAfter),
                    503,
                    "NET05",
                    false
                );
            }
        }
    }
    
    /**
     * Record circuit breaker success
     */
    private void recordCircuitSuccess() {
        if (circuitState == CircuitState.HALF_OPEN) {
            int count = circuitSuccessCount.incrementAndGet();
            
            if (count >= circuitConfig.getSuccessThreshold()) {
                circuitState = CircuitState.CLOSED;
                circuitFailureCount.set(0);
                circuitSuccessCount.set(0);
                logger.info("Circuit breaker CLOSED after successful recovery");
            }
        } else if (circuitState == CircuitState.CLOSED) {
            circuitFailureCount.set(0);
        }
    }
    
    /**
     * Record circuit breaker failure
     */
    private void recordCircuitFailure() {
        if (circuitState == CircuitState.HALF_OPEN) {
            circuitState = CircuitState.OPEN;
            circuitOpenTime.set(System.currentTimeMillis());
            logger.warn("Circuit breaker REOPENED after failure in half-open state");
        } else if (circuitState == CircuitState.CLOSED) {
            int count = circuitFailureCount.incrementAndGet();
            
            if (count >= circuitConfig.getFailureThreshold()) {
                circuitState = CircuitState.OPEN;
                circuitOpenTime.set(System.currentTimeMillis());
                logger.warn("Circuit breaker OPENED after {} failures", count);
            }
        }
    }
    
    /**
     * Calculate retry delay with exponential backoff
     * 
     * @param attempt Current attempt number (0-based)
     * @return Delay in milliseconds
     */
    private long calculateRetryDelay(int attempt) {
        // Exponential backoff: baseDelay * 2^attempt
        // Max delay capped at 16 seconds
        long delay = (long) (config.getRetryDelay() * Math.pow(2, attempt));
        return Math.min(delay, 16000);
    }
    
    /**
     * Determine if error is retryable
     */
    private boolean isRetryableError(Exception e) {
        if (e instanceof NetworkException) {
            return ((NetworkException) e).isRetryable();
        }
        
        if (e instanceof FdmsException) {
            Integer statusCode = ((FdmsException) e).getStatusCode();
            if (statusCode != null) {
                return Set.of(408, 429, 500, 502, 503, 504).contains(statusCode);
            }
        }
        
        return e instanceof SocketTimeoutException || e instanceof IOException;
    }
    
    /**
     * Normalize error from various sources into FdmsException
     */
    private FdmsException normalizeError(Exception e, Response response) {
        if (e instanceof SocketTimeoutException) {
            return new NetworkException("Request timed out", 408, "NET01", true);
        }
        
        if (e instanceof IOException) {
            return new NetworkException("Network error: " + e.getMessage(), null, "NET10", true);
        }
        
        if (e instanceof FdmsException) {
            return (FdmsException) e;
        }
        
        if (response != null && !response.isSuccessful()) {
            try {
                String body = response.body() != null ? response.body().string() : "";
                JsonNode json = objectMapper.readTree(body);
                
                String code = null;
                String message = e.getMessage();
                
                if (json.has("code")) {
                    code = json.get("code").asText();
                } else if (json.has("errors") && json.get("errors").isArray() && json.get("errors").size() > 0) {
                    JsonNode firstError = json.get("errors").get(0);
                    code = firstError.has("code") ? firstError.get("code").asText() : null;
                    message = firstError.has("message") ? firstError.get("message").asText() : message;
                }
                
                if (json.has("message")) {
                    message = json.get("message").asText();
                }
                
                return new FdmsException(message, code, response.code());
            } catch (Exception ignored) {
                return new FdmsException(e.getMessage(), null, response.code());
            }
        }
        
        return new FdmsException("Request error: " + e.getMessage());
    }
    
    /**
     * Redact sensitive data from object for logging
     */
    @SuppressWarnings("unchecked")
    private Object redactSensitiveData(Object obj) {
        if (obj == null) {
            return null;
        }
        
        if (obj instanceof Map) {
            Map<String, Object> result = new HashMap<>();
            ((Map<String, Object>) obj).forEach((key, value) -> {
                String lowerKey = key.toLowerCase();
                boolean isSensitive = SENSITIVE_FIELDS.stream()
                    .anyMatch(lowerKey::contains);
                
                if (isSensitive) {
                    result.put(key, "[REDACTED]");
                } else if (value instanceof Map || value instanceof List) {
                    result.put(key, redactSensitiveData(value));
                } else {
                    result.put(key, value);
                }
            });
            return result;
        }
        
        if (obj instanceof List) {
            List<Object> result = new ArrayList<>();
            ((List<Object>) obj).forEach(item -> result.add(redactSensitiveData(item)));
            return result;
        }
        
        return obj;
    }
    
    /**
     * Create audit log entry
     */
    private HttpAuditEntry createAuditEntry(
            String method,
            String url,
            Map<String, String> headers,
            Object body,
            String requestId,
            long startTime,
            Response response,
            Exception error,
            Integer retryAttempt
    ) {
        long duration = System.currentTimeMillis() - startTime;
        
        Map<String, Object> responseData = null;
        if (response != null) {
            responseData = new HashMap<>();
            responseData.put("statusCode", response.code());
            try {
                if (response.body() != null) {
                    String responseBody = response.peekBody(Long.MAX_VALUE).string();
                    if (!responseBody.isEmpty()) {
                        responseData.put("body", redactSensitiveData(objectMapper.readValue(responseBody, Object.class)));
                    }
                }
            } catch (Exception ignored) {}
        }
        
        @SuppressWarnings("unchecked")
        Map<String, String> redactedHeaders = (Map<String, String>) redactSensitiveData(headers);
        
        return HttpAuditEntry.builder()
            .timestamp(Instant.now().toString())
            .requestId(requestId)
            .method(method)
            .url(url)
            .headers(redactedHeaders)
            .body(redactSensitiveData(body))
            .response(responseData)
            .duration(duration)
            .success(error == null)
            .error(error != null ? error.getMessage() : null)
            .retryAttempt(retryAttempt)
            .build();
    }
    
    /**
     * Log audit entry
     */
    private void logAudit(HttpAuditEntry entry) {
        if (config.isEnableAuditLog() && auditLogCallback != null) {
            auditLogCallback.accept(entry);
        }
    }
    
    /**
     * Add a custom request interceptor
     */
    public void addRequestInterceptor(Function<Request, Request> interceptor) {
        requestInterceptors.add(interceptor);
    }
    
    /**
     * Add a custom response interceptor
     */
    public void addResponseInterceptor(Function<Response, Response> interceptor) {
        responseInterceptors.add(interceptor);
    }
    
    /**
     * Set audit log callback
     */
    public void setAuditLogCallback(Consumer<HttpAuditEntry> callback) {
        this.auditLogCallback = callback;
    }
    
    /**
     * Apply custom request interceptors
     */
    private Request applyRequestInterceptors(Request request) {
        Request result = request;
        for (Function<Request, Request> interceptor : requestInterceptors) {
            result = interceptor.apply(result);
        }
        return result;
    }
    
    /**
     * Execute HTTP request with retry logic
     */
    private <T> HttpResponse<T> executeWithRetry(
            String method,
            String url,
            Object body,
            HttpRequestOptions options,
            Class<T> responseType
    ) throws FdmsException {
        if (options == null) {
            options = new HttpRequestOptions();
        }
        
        // Check circuit breaker
        checkCircuitBreaker();
        
        int maxAttempts = options.isSkipRetry() ? 1 : config.getRetryAttempts() + 1;
        Exception lastError = null;
        
        // Build full URL
        String fullUrl = config.getBaseUrl() + url;
        
        // Add query parameters
        if (options.getParams() != null && !options.getParams().isEmpty()) {
            HttpUrl.Builder urlBuilder = HttpUrl.parse(fullUrl).newBuilder();
            options.getParams().forEach(urlBuilder::addQueryParameter);
            fullUrl = urlBuilder.build().toString();
        }
        
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            long startTime = System.currentTimeMillis();
            String requestId = generateRequestId();
            
            Response response = null;
            
            try {
                // Build request
                Request.Builder requestBuilder = new Request.Builder()
                    .url(fullUrl)
                    .header("X-Request-ID", requestId);
                
                // Add custom headers
                if (options.getHeaders() != null) {
                    options.getHeaders().forEach(requestBuilder::header);
                }
                
                // Set body
                RequestBody requestBody = null;
                if (body != null) {
                    requestBody = RequestBody.create(objectMapper.writeValueAsString(body), JSON);
                }
                
                switch (method.toUpperCase()) {
                    case "GET":
                        requestBuilder.get();
                        break;
                    case "POST":
                        requestBuilder.post(requestBody != null ? requestBody : RequestBody.create("", JSON));
                        break;
                    case "PUT":
                        requestBuilder.put(requestBody != null ? requestBody : RequestBody.create("", JSON));
                        break;
                    case "DELETE":
                        requestBuilder.delete(requestBody);
                        break;
                    case "PATCH":
                        requestBuilder.patch(requestBody != null ? requestBody : RequestBody.create("", JSON));
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported HTTP method: " + method);
                }
                
                Request request = requestBuilder.build();
                
                // Apply request interceptors
                request = applyRequestInterceptors(request);
                
                // Create client with custom timeout if specified
                OkHttpClient client = this.okHttpClient;
                if (options.getTimeout() != null) {
                    client = okHttpClient.newBuilder()
                        .readTimeout(Duration.ofMillis(options.getTimeout()))
                        .build();
                }
                
                // Execute request
                Response httpResponse = client.newCall(request).execute();
                response = httpResponse;
                
                // Check for HTTP errors
                if (!httpResponse.isSuccessful()) {
                    throw new FdmsException(
                        "HTTP error: " + httpResponse.code(),
                        null,
                        httpResponse.code()
                    );
                }
                
                // Record success for circuit breaker
                recordCircuitSuccess();
                
                // Get headers
                Map<String, String> responseHeaders = new HashMap<>();
                final Response finalResponse = httpResponse;
                httpResponse.headers().names().forEach(name -> 
                    responseHeaders.put(name, finalResponse.header(name))
                );
                
                // Parse response body
                T responseData = null;
                if (httpResponse.body() != null) {
                    String responseBody = httpResponse.body().string();
                    if (!responseBody.isEmpty()) {
                        if (responseType == String.class) {
                            responseData = responseType.cast(responseBody);
                        } else if (responseType == JsonNode.class) {
                            responseData = responseType.cast(objectMapper.readTree(responseBody));
                        } else {
                            responseData = objectMapper.readValue(responseBody, responseType);
                        }
                    }
                }
                
                // Create audit entry
                HttpAuditEntry auditEntry = createAuditEntry(
                    method, fullUrl,
                    new HashMap<>(request.headers().toMultimap().entrySet().stream()
                        .collect(HashMap::new, (m, e) -> m.put(e.getKey(), e.getValue().get(0)), HashMap::putAll)),
                    body, requestId, startTime, httpResponse, null,
                    attempt > 0 ? attempt : null
                );
                logAudit(auditEntry);
                
                return new HttpResponse<>(
                    responseData,
                    httpResponse.code(),
                    responseHeaders,
                    System.currentTimeMillis() - startTime,
                    requestId
                );
                
            } catch (Exception e) {
                lastError = e;
                
                // Record failure for circuit breaker
                recordCircuitFailure();
                
                // Log audit entry for failed attempt
                HttpAuditEntry auditEntry = createAuditEntry(
                    method, fullUrl, options.getHeaders(),
                    body, requestId, startTime, response, e, attempt
                );
                logAudit(auditEntry);
                
                // Check if we should retry
                if (attempt < maxAttempts - 1 && isRetryableError(e)) {
                    long delay = calculateRetryDelay(attempt);
                    logger.warn("Request failed (attempt {}/{}), retrying in {}ms: {}",
                        attempt + 1, maxAttempts, delay, e.getMessage());
                    
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw normalizeError(e, response);
                    }
                    continue;
                }
                
                throw normalizeError(e, response);
                
            } finally {
                if (response != null) {
                    response.close();
                }
            }
        }
        
        // Should not reach here
        throw normalizeError(lastError, null);
    }
    
    /**
     * Perform GET request
     * 
     * @param url Request URL (relative to base URL)
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> get(String url) throws FdmsException {
        return get(url, null, JsonNode.class);
    }
    
    /**
     * Perform GET request with options
     * 
     * @param url Request URL (relative to base URL)
     * @param options Request options
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> get(String url, HttpRequestOptions options) throws FdmsException {
        return get(url, options, JsonNode.class);
    }
    
    /**
     * Perform GET request with custom response type
     * 
     * @param url Request URL (relative to base URL)
     * @param options Request options
     * @param responseType Response class type
     * @return HTTP response with typed data
     */
    public <T> HttpResponse<T> get(String url, HttpRequestOptions options, Class<T> responseType) throws FdmsException {
        return executeWithRetry("GET", url, null, options, responseType);
    }
    
    /**
     * Perform POST request
     * 
     * @param url Request URL (relative to base URL)
     * @param body Request body
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> post(String url, Object body) throws FdmsException {
        return post(url, body, null, JsonNode.class);
    }
    
    /**
     * Perform POST request with options
     * 
     * @param url Request URL (relative to base URL)
     * @param body Request body
     * @param options Request options
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> post(String url, Object body, HttpRequestOptions options) throws FdmsException {
        return post(url, body, options, JsonNode.class);
    }
    
    /**
     * Perform POST request with custom response type
     * 
     * @param url Request URL (relative to base URL)
     * @param body Request body
     * @param options Request options
     * @param responseType Response class type
     * @return HTTP response with typed data
     */
    public <T> HttpResponse<T> post(String url, Object body, HttpRequestOptions options, Class<T> responseType) throws FdmsException {
        return executeWithRetry("POST", url, body, options, responseType);
    }
    
    /**
     * Perform PUT request
     * 
     * @param url Request URL (relative to base URL)
     * @param body Request body
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> put(String url, Object body) throws FdmsException {
        return put(url, body, null, JsonNode.class);
    }
    
    /**
     * Perform PUT request with options
     * 
     * @param url Request URL (relative to base URL)
     * @param body Request body
     * @param options Request options
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> put(String url, Object body, HttpRequestOptions options) throws FdmsException {
        return put(url, body, options, JsonNode.class);
    }
    
    /**
     * Perform PUT request with custom response type
     * 
     * @param url Request URL (relative to base URL)
     * @param body Request body
     * @param options Request options
     * @param responseType Response class type
     * @return HTTP response with typed data
     */
    public <T> HttpResponse<T> put(String url, Object body, HttpRequestOptions options, Class<T> responseType) throws FdmsException {
        return executeWithRetry("PUT", url, body, options, responseType);
    }
    
    /**
     * Perform DELETE request
     * 
     * @param url Request URL (relative to base URL)
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> delete(String url) throws FdmsException {
        return delete(url, null, JsonNode.class);
    }
    
    /**
     * Perform DELETE request with options
     * 
     * @param url Request URL (relative to base URL)
     * @param options Request options
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> delete(String url, HttpRequestOptions options) throws FdmsException {
        return delete(url, options, JsonNode.class);
    }
    
    /**
     * Perform DELETE request with custom response type
     * 
     * @param url Request URL (relative to base URL)
     * @param options Request options
     * @param responseType Response class type
     * @return HTTP response with typed data
     */
    public <T> HttpResponse<T> delete(String url, HttpRequestOptions options, Class<T> responseType) throws FdmsException {
        return executeWithRetry("DELETE", url, null, options, responseType);
    }
    
    /**
     * Perform PATCH request
     * 
     * @param url Request URL (relative to base URL)
     * @param body Request body
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> patch(String url, Object body) throws FdmsException {
        return patch(url, body, null, JsonNode.class);
    }
    
    /**
     * Perform PATCH request with options
     * 
     * @param url Request URL (relative to base URL)
     * @param body Request body
     * @param options Request options
     * @return HTTP response with JsonNode data
     */
    public HttpResponse<JsonNode> patch(String url, Object body, HttpRequestOptions options) throws FdmsException {
        return patch(url, body, options, JsonNode.class);
    }
    
    /**
     * Perform PATCH request with custom response type
     * 
     * @param url Request URL (relative to base URL)
     * @param body Request body
     * @param options Request options
     * @param responseType Response class type
     * @return HTTP response with typed data
     */
    public <T> HttpResponse<T> patch(String url, Object body, HttpRequestOptions options, Class<T> responseType) throws FdmsException {
        return executeWithRetry("PATCH", url, body, options, responseType);
    }
    
    /**
     * Get current circuit breaker state
     */
    public CircuitState getCircuitState() {
        return circuitState;
    }
    
    /**
     * Reset circuit breaker to closed state
     */
    public void resetCircuitBreaker() {
        circuitState = CircuitState.CLOSED;
        circuitFailureCount.set(0);
        circuitSuccessCount.set(0);
        circuitOpenTime.set(0);
        logger.info("Circuit breaker manually reset to CLOSED state");
    }
    
    /**
     * Get base URL
     */
    public String getBaseUrl() {
        return config.getBaseUrl();
    }
    
    /**
     * Get device ID from config
     */
    public String getDeviceId() {
        return config.getDeviceId();
    }
    
    /**
     * Close the HTTP client and release resources
     */
    @Override
    public void close() {
        okHttpClient.dispatcher().executorService().shutdown();
        okHttpClient.connectionPool().evictAll();
    }
}
