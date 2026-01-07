package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Configuration from environment variables
type Config struct {
	RedisHost                   string
	RedisPort                   string
	AlertmanagerWebhookSecret   string
	LogLevel                    string
	ErrorThresholdCount         int
	ErrorThresholdWindowMinutes int
	AutoLogTTLMinutes           int
	Port                        string
}

// AutoLogConfig represents an auto-logging session
type AutoLogConfig struct {
	App          string    `json:"app"`
	Environment  string    `json:"environment"`
	Service      string    `json:"service"`
	Endpoint     *string   `json:"endpoint,omitempty"`
	ErrorType    *string   `json:"error_type,omitempty"`
	TraceID      *string   `json:"trace_id,omitempty"`
	TriggerSource string   `json:"trigger_source"`
	EnabledAt    time.Time `json:"enabled_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	ErrorCount   int       `json:"error_count"`
}

// Prometheus metrics
var (
	webhookRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "autolog_webhook_requests_total",
			Help: "Total webhook requests received",
		},
		[]string{"source", "event_type"},
	)

	autologTriggers = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "autolog_triggers_total",
			Help: "Total auto-logging triggers",
		},
		[]string{"app", "environment", "trigger_source"},
	)

	activeAutologs = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "autolog_active_count",
			Help: "Number of active auto-logging sessions",
		},
		[]string{"app", "environment"},
	)

	errorEvents = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "autolog_error_events_total",
			Help: "Total error events processed",
		},
		[]string{"app", "environment", "error_type"},
	)

	webhookDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "autolog_webhook_duration_seconds",
			Help:    "Webhook processing duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"source"},
	)
)

// AutoLogManager handles auto-logging state
type AutoLogManager struct {
	redisClient             *redis.Client
	config                  *Config
	mu                      sync.RWMutex
	errorCounterPrefix      string
	autoLogStatePrefix      string
}

// NewAutoLogManager creates a new auto-log manager
func NewAutoLogManager(redisClient *redis.Client, config *Config) *AutoLogManager {
	return &AutoLogManager{
		redisClient:        redisClient,
		config:             config,
		errorCounterPrefix: "autolog:errors:",
		autoLogStatePrefix: "autolog:state:",
	}
}

func (m *AutoLogManager) getErrorKey(app, environment string, endpoint *string) string {
	base := fmt.Sprintf("%s:%s", app, environment)
	if endpoint != nil && *endpoint != "" {
		hash := md5.Sum([]byte(*endpoint))
		base = fmt.Sprintf("%s:%x", base, hash[:4])
	}
	return m.errorCounterPrefix + base
}

func (m *AutoLogManager) getStateKey(app, environment string, endpoint *string) string {
	base := fmt.Sprintf("%s:%s", app, environment)
	if endpoint != nil && *endpoint != "" {
		hash := md5.Sum([]byte(*endpoint))
		base = fmt.Sprintf("%s:%x", base, hash[:4])
	}
	return m.autoLogStatePrefix + base
}

// IncrementError increments error counter and returns current count
func (m *AutoLogManager) IncrementError(ctx context.Context, app, environment string, endpoint *string) (int64, error) {
	key := m.getErrorKey(app, environment, endpoint)
	ttl := time.Duration(m.config.ErrorThresholdWindowMinutes) * time.Minute

	pipe := m.redisClient.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}

	return incr.Val(), nil
}

// GetErrorCount returns current error count
func (m *AutoLogManager) GetErrorCount(ctx context.Context, app, environment string, endpoint *string) (int64, error) {
	key := m.getErrorKey(app, environment, endpoint)
	return m.redisClient.Get(ctx, key).Int64()
}

// EnableAutoLog enables auto-logging for a service
func (m *AutoLogManager) EnableAutoLog(ctx context.Context, config *AutoLogConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.getStateKey(config.App, config.Environment, config.Endpoint)
	ttl := time.Duration(m.config.AutoLogTTLMinutes) * time.Minute

	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	if err := m.redisClient.Set(ctx, key, data, ttl).Err(); err != nil {
		return err
	}

	// Update metrics
	activeAutologs.WithLabelValues(config.App, config.Environment).Inc()
	autologTriggers.WithLabelValues(config.App, config.Environment, config.TriggerSource).Inc()

	log.Printf("Auto-logging enabled for %s/%s (endpoint: %v, trigger: %s)",
		config.App, config.Environment, config.Endpoint, config.TriggerSource)

	return nil
}

// IsAutoLogEnabled checks if auto-logging is enabled
func (m *AutoLogManager) IsAutoLogEnabled(ctx context.Context, app, environment string, endpoint *string) (*AutoLogConfig, error) {
	key := m.getStateKey(app, environment, endpoint)

	data, err := m.redisClient.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var config AutoLogConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// DisableAutoLog disables auto-logging
func (m *AutoLogManager) DisableAutoLog(ctx context.Context, app, environment string, endpoint *string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.getStateKey(app, environment, endpoint)
	result, err := m.redisClient.Del(ctx, key).Result()
	if err != nil {
		return false, err
	}

	if result > 0 {
		activeAutologs.WithLabelValues(app, environment).Dec()
		log.Printf("Auto-logging disabled for %s/%s (endpoint: %v)", app, environment, endpoint)
		return true, nil
	}

	return false, nil
}

// GetAllActive returns all active auto-logging sessions
func (m *AutoLogManager) GetAllActive(ctx context.Context) ([]*AutoLogConfig, error) {
	pattern := m.autoLogStatePrefix + "*"
	keys, err := m.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, err
	}

	configs := make([]*AutoLogConfig, 0, len(keys))
	for _, key := range keys {
		data, err := m.redisClient.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var config AutoLogConfig
		if err := json.Unmarshal(data, &config); err != nil {
			continue
		}

		configs = append(configs, &config)
	}

	return configs, nil
}

// Handler for the HTTP server
type Handler struct {
	manager *AutoLogManager
	config  *Config
}

func NewHandler(manager *AutoLogManager, config *Config) *Handler {
	return &Handler{
		manager: manager,
		config:  config,
	}
}

// Health check endpoint
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check Redis connection
	if err := h.manager.redisClient.Ping(ctx).Err(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "unhealthy",
			"error":  err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"redis":  "connected",
	})
}

// Check auto-log status
func (h *Handler) CheckAutoLog(w http.ResponseWriter, r *http.Request) {
	app := r.URL.Query().Get("app")
	environment := r.URL.Query().Get("environment")
	endpoint := r.URL.Query().Get("endpoint")

	if app == "" || environment == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "app and environment are required",
		})
		return
	}

	var endpointPtr *string
	if endpoint != "" {
		endpointPtr = &endpoint
	}

	config, err := h.manager.IsAutoLogEnabled(r.Context(), app, environment, endpointPtr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
		return
	}

	if config != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": true,
			"config":  config,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]bool{
			"enabled": false,
		})
	}
}

// Enable auto-log
func (h *Handler) EnableAutoLog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		App          string  `json:"app"`
		Environment  string  `json:"environment"`
		Service      string  `json:"service"`
		Endpoint     *string `json:"endpoint,omitempty"`
		ErrorType    *string `json:"error_type,omitempty"`
		TriggerSource string  `json:"trigger_source,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if req.App == "" || req.Environment == "" || req.Service == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "app, environment, and service are required",
		})
		return
	}

	if req.TriggerSource == "" {
		req.TriggerSource = "manual"
	}

	now := time.Now()
	config := &AutoLogConfig{
		App:           req.App,
		Environment:   req.Environment,
		Service:       req.Service,
		Endpoint:      req.Endpoint,
		ErrorType:     req.ErrorType,
		TriggerSource: req.TriggerSource,
		EnabledAt:     now,
		ExpiresAt:     now.Add(time.Duration(h.config.AutoLogTTLMinutes) * time.Minute),
		ErrorCount:    0,
	}

	if err := h.manager.EnableAutoLog(r.Context(), config); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "enabled",
		"config": config,
	})
}

// Disable auto-log
func (h *Handler) DisableAutoLog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		App         string  `json:"app"`
		Environment string  `json:"environment"`
		Endpoint    *string `json:"endpoint,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if req.App == "" || req.Environment == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "app and environment are required",
		})
		return
	}

	result, err := h.manager.DisableAutoLog(r.Context(), req.App, req.Environment, req.Endpoint)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
		return
	}

	if result {
		json.NewEncoder(w).Encode(map[string]string{
			"status": "disabled",
		})
	} else {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "not_found",
		})
	}
}

// List all active auto-log sessions
func (h *Handler) ListAutoLogs(w http.ResponseWriter, r *http.Request) {
	configs, err := h.manager.GetAllActive(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":    len(configs),
		"sessions": configs,
	})
}

// AlertManager webhook handler
func (h *Handler) AlertManagerWebhook(w http.ResponseWriter, r *http.Request) {
	webhookType := mux.Vars(r)["type"]
	timer := prometheus.NewTimer(webhookDuration.WithLabelValues("alertmanager"))
	defer timer.ObserveDuration()

	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	webhookRequests.WithLabelValues("alertmanager", webhookType).Inc()

	// Process alerts (both firing and resolved)
	if alerts, ok := data["alerts"].([]interface{}); ok {
		for _, alert := range alerts {
			if alertMap, ok := alert.(map[string]interface{}); ok {
				status, _ := alertMap["status"].(string)
				// Process both firing and resolved alerts
				if status == "firing" || status == "resolved" {
					h.handlePrometheusAlert(r.Context(), alertMap, webhookType, status)
				}
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "processed",
	})
}

func (h *Handler) handlePrometheusAlert(ctx context.Context, alert map[string]interface{}, webhookType string, status string) {
	labels, _ := alert["labels"].(map[string]interface{})

	// Support both OTEL labels (service_name, deployment_environment) and legacy labels (app, environment)
	app, _ := labels["service_name"].(string)
	if app == "" {
		app, _ = labels["app"].(string)
	}
	if app == "" {
		app = "unknown"
	}

	environment, _ := labels["deployment_environment"].(string)
	if environment == "" {
		environment, _ = labels["environment"].(string)
	}
	if environment == "" {
		environment = "production"
	}

	var endpoint *string
	// Support both http_route (OTEL) and endpoint (legacy)
	if ep, ok := labels["http_route"].(string); ok && ep != "" {
		endpoint = &ep
	} else if ep, ok := labels["endpoint"].(string); ok && ep != "" {
		endpoint = &ep
	}

	alertName, _ := labels["alertname"].(string)

	// Handle resolved alerts - disable auto-logging
	if status == "resolved" {
		if webhookType == "autolog" || labels["autolog"] == "true" {
			log.Printf("Auto-log alert resolved: %s for %s/%s - disabling auto-logging", alertName, app, environment)
			if _, err := h.manager.DisableAutoLog(ctx, app, environment, endpoint); err != nil {
				log.Printf("Error disabling auto-log on resolve: %v", err)
			}
		}
		return
	}

	// Check if this is an auto-log trigger alert (firing)
	if webhookType == "autolog" || labels["autolog"] == "true" {
		log.Printf("Auto-log alert triggered: %s for %s/%s", alertName, app, environment)

		now := time.Now()
		config := &AutoLogConfig{
			App:           app,
			Environment:   environment,
			Service:       app,
			Endpoint:      endpoint,
			TriggerSource: "prometheus",
			EnabledAt:     now,
			ExpiresAt:     now.Add(time.Duration(h.config.AutoLogTTLMinutes) * time.Minute),
			ErrorCount:    0,
		}

		if err := h.manager.EnableAutoLog(ctx, config); err != nil {
			log.Printf("Error enabling auto-log: %v", err)
		}
	} else {
		log.Printf("Alert received: %s for %s/%s (type: %s)", alertName, app, environment, webhookType)
	}
}

func loadConfig() *Config {
	errorThreshold, _ := strconv.Atoi(getEnv("ERROR_THRESHOLD_COUNT", "10"))
	errorWindow, _ := strconv.Atoi(getEnv("ERROR_THRESHOLD_WINDOW_MINUTES", "5"))
	autoLogTTL, _ := strconv.Atoi(getEnv("AUTOLOG_TTL_MINUTES", "30"))

	return &Config{
		RedisHost:                   getEnv("REDIS_HOST", "redis-autolog"),
		RedisPort:                   getEnv("REDIS_PORT", "6379"),
		AlertmanagerWebhookSecret:   getEnv("ALERTMANAGER_WEBHOOK_SECRET", ""),
		LogLevel:                    getEnv("LOG_LEVEL", "INFO"),
		ErrorThresholdCount:         errorThreshold,
		ErrorThresholdWindowMinutes: errorWindow,
		AutoLogTTLMinutes:           autoLogTTL,
		Port:                        getEnv("PORT", "5000"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	config := loadConfig()

	// Setup Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", config.RedisHost, config.RedisPort),
		DB:   0,
	})

	ctx := context.Background()

	// Wait for Redis
	log.Println("Waiting for Redis connection...")
	for i := 0; i < 30; i++ {
		if err := redisClient.Ping(ctx).Err(); err == nil {
			log.Println("Connected to Redis")
			break
		}
		time.Sleep(2 * time.Second)
	}

	manager := NewAutoLogManager(redisClient, config)
	handler := NewHandler(manager, config)

	// Setup router
	r := mux.NewRouter()
	r.Use(loggingMiddleware)
	r.Use(corsMiddleware)

	// Health and metrics
	r.HandleFunc("/health", handler.Health).Methods("GET")
	r.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// Webhooks
	r.HandleFunc("/webhook/{type}", handler.AlertManagerWebhook).Methods("POST")

	// API endpoints
	r.HandleFunc("/api/autolog/check", handler.CheckAutoLog).Methods("GET")
	r.HandleFunc("/api/autolog/enable", handler.EnableAutoLog).Methods("POST")
	r.HandleFunc("/api/autolog/disable", handler.DisableAutoLog).Methods("POST")
	r.HandleFunc("/api/autolog/list", handler.ListAutoLogs).Methods("GET")

	// Start server
	srv := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}

		redisClient.Close()
	}()

	log.Printf("Auto-logging service starting on port %s", config.Port)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.RequestURI, time.Since(start))
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
