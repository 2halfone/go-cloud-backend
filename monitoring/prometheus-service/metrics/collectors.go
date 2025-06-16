package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
)

// Il prometheus-service raccoglie solo metriche, non le definisce
// Tutte le metriche sono definite in shared/metrics per evitare duplicazioni

func InitPrometheusMetrics() {
    // Prometheus-service ora raccoglie solo metriche, non le definisce
    // Le metriche sono tutte centralizzate in shared/metrics
}
