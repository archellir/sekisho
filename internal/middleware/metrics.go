package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Metrics struct {
	namespace string
	counters  map[string]*Counter
	gauges    map[string]*Gauge
	histograms map[string]*Histogram
	mutex     sync.RWMutex
}

type Counter struct {
	name   string
	help   string
	value  int64
	labels map[string]string
	mutex  sync.Mutex
}

type Gauge struct {
	name   string
	help   string
	value  float64
	labels map[string]string
	mutex  sync.Mutex
}

type Histogram struct {
	name    string
	help    string
	buckets []float64
	counts  []int64
	sum     float64
	count   int64
	labels  map[string]string
	mutex   sync.Mutex
}

func NewMetrics(namespace string) *Metrics {
	return &Metrics{
		namespace:  namespace,
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
	}
}

func (m *Metrics) Counter(name, help string, labels map[string]string) *Counter {
	key := m.makeKey(name, labels)
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if counter, exists := m.counters[key]; exists {
		return counter
	}
	
	counter := &Counter{
		name:   name,
		help:   help,
		labels: labels,
	}
	m.counters[key] = counter
	return counter
}

func (m *Metrics) Gauge(name, help string, labels map[string]string) *Gauge {
	key := m.makeKey(name, labels)
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if gauge, exists := m.gauges[key]; exists {
		return gauge
	}
	
	gauge := &Gauge{
		name:   name,
		help:   help,
		labels: labels,
	}
	m.gauges[key] = gauge
	return gauge
}

func (m *Metrics) Histogram(name, help string, buckets []float64, labels map[string]string) *Histogram {
	key := m.makeKey(name, labels)
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if histogram, exists := m.histograms[key]; exists {
		return histogram
	}
	
	if buckets == nil {
		buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	}
	
	histogram := &Histogram{
		name:    name,
		help:    help,
		buckets: buckets,
		counts:  make([]int64, len(buckets)+1),
		labels:  labels,
	}
	m.histograms[key] = histogram
	return histogram
}

func (m *Metrics) makeKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	
	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return fmt.Sprintf("%s{%s}", name, strings.Join(parts, ","))
}

func (c *Counter) Inc() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.value++
}

func (c *Counter) Add(delta int64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.value += delta
}

func (c *Counter) Value() int64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.value
}

func (g *Gauge) Set(value float64) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.value = value
}

func (g *Gauge) Inc() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.value++
}

func (g *Gauge) Dec() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.value--
}

func (g *Gauge) Add(delta float64) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.value += delta
}

func (g *Gauge) Value() float64 {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return g.value
}

func (h *Histogram) Observe(value float64) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	
	h.sum += value
	h.count++
	
	for i, bucket := range h.buckets {
		if value <= bucket {
			h.counts[i]++
		}
	}
	h.counts[len(h.buckets)]++
}

func (h *Histogram) Count() int64 {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.count
}

func (h *Histogram) Sum() float64 {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.sum
}

type ProxyMetrics struct {
	metrics           *Metrics
	requestsTotal     *Counter
	requestDuration   *Histogram
	requestSize       *Histogram
	responseSize      *Histogram
	activeConnections *Gauge
	authAttempts      *Counter
	authSuccess       *Counter
	authFailures      *Counter
	policyDecisions   *Counter
}

func NewProxyMetrics(namespace string) *ProxyMetrics {
	metrics := NewMetrics(namespace)
	
	return &ProxyMetrics{
		metrics: metrics,
		requestsTotal: metrics.Counter(
			"requests_total",
			"Total number of HTTP requests",
			nil,
		),
		requestDuration: metrics.Histogram(
			"request_duration_seconds",
			"Request duration in seconds",
			nil,
			nil,
		),
		requestSize: metrics.Histogram(
			"request_size_bytes",
			"Request size in bytes",
			[]float64{1, 10, 100, 1000, 10000, 100000, 1000000},
			nil,
		),
		responseSize: metrics.Histogram(
			"response_size_bytes",
			"Response size in bytes",
			[]float64{1, 10, 100, 1000, 10000, 100000, 1000000},
			nil,
		),
		activeConnections: metrics.Gauge(
			"active_connections",
			"Number of active connections",
			nil,
		),
		authAttempts: metrics.Counter(
			"auth_attempts_total",
			"Total authentication attempts",
			nil,
		),
		authSuccess: metrics.Counter(
			"auth_success_total",
			"Successful authentication attempts",
			nil,
		),
		authFailures: metrics.Counter(
			"auth_failures_total",
			"Failed authentication attempts",
			nil,
		),
		policyDecisions: metrics.Counter(
			"policy_decisions_total",
			"Policy decisions by outcome",
			nil,
		),
	}
}

func (pm *ProxyMetrics) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		pm.activeConnections.Inc()
		defer pm.activeConnections.Dec()
		
		pm.requestsTotal.Inc()
		
		if r.ContentLength > 0 {
			pm.requestSize.Observe(float64(r.ContentLength))
		}
		
		wrapper := &metricsResponseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}
		
		next.ServeHTTP(wrapper, r)
		
		duration := time.Since(start).Seconds()
		pm.requestDuration.Observe(duration)
		
		if wrapper.size > 0 {
			pm.responseSize.Observe(float64(wrapper.size))
		}
	})
}

func (pm *ProxyMetrics) RecordAuth(success bool) {
	pm.authAttempts.Inc()
	if success {
		pm.authSuccess.Inc()
	} else {
		pm.authFailures.Inc()
	}
}

func (pm *ProxyMetrics) RecordPolicyDecision(allowed bool) {
	pm.policyDecisions.Inc()
}

func (pm *ProxyMetrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	
	pm.metrics.mutex.RLock()
	defer pm.metrics.mutex.RUnlock()
	
	for _, counter := range pm.metrics.counters {
		pm.writeCounter(w, counter)
	}
	
	for _, gauge := range pm.metrics.gauges {
		pm.writeGauge(w, gauge)
	}
	
	for _, histogram := range pm.metrics.histograms {
		pm.writeHistogram(w, histogram)
	}
}

func (pm *ProxyMetrics) writeCounter(w http.ResponseWriter, counter *Counter) {
	name := pm.formatName(counter.name)
	if counter.help != "" {
		fmt.Fprintf(w, "# HELP %s %s\n", name, counter.help)
	}
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	
	labels := pm.formatLabels(counter.labels)
	fmt.Fprintf(w, "%s%s %d\n", name, labels, counter.Value())
}

func (pm *ProxyMetrics) writeGauge(w http.ResponseWriter, gauge *Gauge) {
	name := pm.formatName(gauge.name)
	if gauge.help != "" {
		fmt.Fprintf(w, "# HELP %s %s\n", name, gauge.help)
	}
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
	
	labels := pm.formatLabels(gauge.labels)
	fmt.Fprintf(w, "%s%s %g\n", name, labels, gauge.Value())
}

func (pm *ProxyMetrics) writeHistogram(w http.ResponseWriter, histogram *Histogram) {
	name := pm.formatName(histogram.name)
	if histogram.help != "" {
		fmt.Fprintf(w, "# HELP %s %s\n", name, histogram.help)
	}
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	
	labels := pm.formatLabels(histogram.labels)
	
	histogram.mutex.Lock()
	defer histogram.mutex.Unlock()
	
	cumulativeCount := int64(0)
	for i, bucket := range histogram.buckets {
		cumulativeCount += histogram.counts[i]
		bucketLabels := pm.addLabel(histogram.labels, "le", fmt.Sprintf("%g", bucket))
		fmt.Fprintf(w, "%s_bucket%s %d\n", name, pm.formatLabels(bucketLabels), cumulativeCount)
	}
	
	infLabels := pm.addLabel(histogram.labels, "le", "+Inf")
	fmt.Fprintf(w, "%s_bucket%s %d\n", name, pm.formatLabels(infLabels), histogram.count)
	fmt.Fprintf(w, "%s_sum%s %g\n", name, labels, histogram.sum)
	fmt.Fprintf(w, "%s_count%s %d\n", name, labels, histogram.count)
}

func (pm *ProxyMetrics) formatName(name string) string {
	if pm.metrics.namespace != "" {
		return pm.metrics.namespace + "_" + name
	}
	return name
}

func (pm *ProxyMetrics) formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	
	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, v))
	}
	return fmt.Sprintf("{%s}", strings.Join(parts, ","))
}

func (pm *ProxyMetrics) addLabel(labels map[string]string, key, value string) map[string]string {
	result := make(map[string]string)
	for k, v := range labels {
		result[k] = v
	}
	result[key] = value
	return result
}

type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

func (mrw *metricsResponseWriter) WriteHeader(statusCode int) {
	mrw.statusCode = statusCode
	mrw.ResponseWriter.WriteHeader(statusCode)
}

func (mrw *metricsResponseWriter) Write(data []byte) (int, error) {
	n, err := mrw.ResponseWriter.Write(data)
	mrw.size += int64(n)
	return n, err
}

type HealthCheck struct {
	name    string
	check   func() error
	timeout time.Duration
}

func NewHealthCheck(name string, check func() error, timeout time.Duration) *HealthCheck {
	return &HealthCheck{
		name:    name,
		check:   check,
		timeout: timeout,
	}
}

type HealthChecker struct {
	checks []HealthCheck
}

func NewHealthChecker() *HealthChecker {
	return &HealthChecker{}
}

func (hc *HealthChecker) AddCheck(check HealthCheck) {
	hc.checks = append(hc.checks, check)
}

func (hc *HealthChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	status := "healthy"
	results := make(map[string]string)
	httpStatus := http.StatusOK
	
	for _, check := range hc.checks {
		if err := check.check(); err != nil {
			status = "unhealthy"
			results[check.name] = err.Error()
			httpStatus = http.StatusServiceUnavailable
		} else {
			results[check.name] = "ok"
		}
	}
	
	response := map[string]interface{}{
		"status":  status,
		"service": "sekisho",
		"checks":  results,
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	
	if data, err := jsonMarshal(response); err == nil {
		w.Write(data)
	} else {
		w.Write([]byte(`{"status":"error","message":"failed to marshal response"}`))
	}
}

func jsonMarshal(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		return marshalMap(val), nil
	default:
		return nil, fmt.Errorf("unsupported type")
	}
}

func marshalMap(m map[string]interface{}) []byte {
	var parts []string
	for k, v := range m {
		switch val := v.(type) {
		case string:
			parts = append(parts, fmt.Sprintf(`"%s":"%s"`, k, val))
		case map[string]string:
			subParts := make([]string, 0, len(val))
			for sk, sv := range val {
				subParts = append(subParts, fmt.Sprintf(`"%s":"%s"`, sk, sv))
			}
			parts = append(parts, fmt.Sprintf(`"%s":{%s}`, k, strings.Join(subParts, ",")))
		}
	}
	return []byte(fmt.Sprintf("{%s}", strings.Join(parts, ",")))
}