package cover

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aurora-protocol/aurora-core/failure"
)

type ClassifierSurface struct {
	TLSFingerprintFamily           string
	H2SettingsID                   string
	H2PseudoHeaderOrderID          string
	H3SettingsID                   string
	QPACKBehaviorID                string
	DatagramWebTransportProfileID  string
	WebSocketUpgradeShapeID        string
	RequestGraphID                 string
	RequestBodySizeDistributionID  string
	ResponseBodySizeDistributionID string
	CacheCookieRedirectClass       string
	TimeoutCloseClass              string
	PacketCountBeforeCloseBucket   string
	ProbeSurface                   failure.ProbeSurface
	PublicLabels                   []string
}

type ClassifierSample struct {
	Name      string
	Ordinary  ClassifierSurface
	Candidate ClassifierSurface
}

type ClassifierReport struct {
	Passed           bool
	FeatureCount     int
	Samples          []ClassifierSampleReport
	Distinguishers   []ClassifierDistinguisher
	ForbiddenMarkers []ForbiddenPublicMarker
}

type ClassifierSampleReport struct {
	Name             string
	Passed           bool
	Distinguishers   []ClassifierDistinguisher
	ForbiddenMarkers []ForbiddenPublicMarker
}

type ClassifierDistinguisher struct {
	Sample    string
	Feature   string
	Ordinary  string
	Candidate string
}

type ForbiddenPublicMarker struct {
	Sample string
	Label  string
	Marker string
}

func DefaultClassifierBaseline() ([]ClassifierSample, error) {
	surface, err := failure.PublicProbeSurface(failure.BadAccessHint)
	if err != nil {
		return nil, err
	}
	names := []string{"web.h2.stream", "web.h1.ws", "web.shadow-origin", "web.h3.stream", "web.h3.ext-dgram"}
	samples := make([]ClassifierSample, 0, len(names))
	for _, name := range names {
		ordinary := classifierSurfaceForCarrier(name, surface)
		candidate := classifierSurfaceForCarrier(name, surface)
		samples = append(samples, ClassifierSample{Name: name, Ordinary: ordinary, Candidate: candidate})
	}
	return samples, nil
}

func EvaluateClassifierBaseline(samples []ClassifierSample) (ClassifierReport, error) {
	if len(samples) == 0 {
		return ClassifierReport{}, fmt.Errorf("cover: no classifier samples")
	}
	report := ClassifierReport{
		Passed:       true,
		FeatureCount: len(classifierFeatureNames),
		Samples:      make([]ClassifierSampleReport, 0, len(samples)),
	}
	for _, sample := range samples {
		if sample.Name == "" {
			return ClassifierReport{}, fmt.Errorf("cover: classifier sample name is empty")
		}
		sampleReport := ClassifierSampleReport{Name: sample.Name, Passed: true}
		ordinaryFeatures := sample.Ordinary.classifierFeatures()
		candidateFeatures := sample.Candidate.classifierFeatures()
		for _, feature := range classifierFeatureNames {
			ordinary := ordinaryFeatures[feature]
			candidate := candidateFeatures[feature]
			if ordinary == candidate {
				continue
			}
			finding := ClassifierDistinguisher{
				Sample:    sample.Name,
				Feature:   feature,
				Ordinary:  ordinary,
				Candidate: candidate,
			}
			sampleReport.Passed = false
			sampleReport.Distinguishers = append(sampleReport.Distinguishers, finding)
			report.Distinguishers = append(report.Distinguishers, finding)
		}
		for _, finding := range scanPublicLabels(sample.Name, sample.Ordinary.PublicLabels) {
			sampleReport.Passed = false
			sampleReport.ForbiddenMarkers = append(sampleReport.ForbiddenMarkers, finding)
			report.ForbiddenMarkers = append(report.ForbiddenMarkers, finding)
		}
		for _, finding := range scanPublicLabels(sample.Name, sample.Candidate.PublicLabels) {
			sampleReport.Passed = false
			sampleReport.ForbiddenMarkers = append(sampleReport.ForbiddenMarkers, finding)
			report.ForbiddenMarkers = append(report.ForbiddenMarkers, finding)
		}
		report.Passed = report.Passed && sampleReport.Passed
		report.Samples = append(report.Samples, sampleReport)
	}
	return report, nil
}

// ProductionCandidateDecision is the Milestone P9 production-candidate gate: a
// CoverTemplate may be marked production-candidate only if the measured
// Aurora-vs-ordinary classifier advantage does not exceed the operator-chosen
// deployment threshold.
type ProductionCandidateDecision struct {
	Threshold           float64
	ClassifierAdvantage float64
	DistinguisherCount  int
	ComparisonCount     int
	ProductionCandidate bool
}

// EvaluateProductionCandidate computes the measured classifier advantage from a
// baseline report (the fraction of Aurora/ordinary feature comparisons a
// classifier can separate) and decides whether the template clears the
// operator's deployment threshold.
func EvaluateProductionCandidate(report ClassifierReport, threshold float64) ProductionCandidateDecision {
	comparisons := len(report.Samples) * report.FeatureCount
	advantage := 0.0
	if comparisons > 0 {
		advantage = float64(len(report.Distinguishers)) / float64(comparisons)
	}
	return ProductionCandidateDecision{
		Threshold:           threshold,
		ClassifierAdvantage: advantage,
		DistinguisherCount:  len(report.Distinguishers),
		ComparisonCount:     comparisons,
		ProductionCandidate: comparisons > 0 && advantage <= threshold && len(report.ForbiddenMarkers) == 0,
	}
}

func classifierSurfaceForCarrier(name string, probe failure.ProbeSurface) ClassifierSurface {
	surface := ClassifierSurface{
		TLSFingerprintFamily:           "cover-origin-tls-family",
		H2SettingsID:                   "not-applicable",
		H2PseudoHeaderOrderID:          "not-applicable",
		H3SettingsID:                   "not-applicable",
		QPACKBehaviorID:                "not-applicable",
		DatagramWebTransportProfileID:  "not-applicable",
		WebSocketUpgradeShapeID:        "not-applicable",
		RequestGraphID:                 "cover-template-request-graph",
		RequestBodySizeDistributionID:  "cover-request-body-distribution",
		ResponseBodySizeDistributionID: "cover-response-body-distribution",
		CacheCookieRedirectClass:       "cover-cache-cookie-redirect",
		TimeoutCloseClass:              "cover-timeout-close",
		PacketCountBeforeCloseBucket:   "cover-packet-count-before-close",
		ProbeSurface:                   probe,
		PublicLabels:                   []string{"https", "content-type", "user-agent", "accept"},
	}
	switch name {
	case "web.h2.stream":
		surface.H2SettingsID = "browser-h2-settings-family"
		surface.H2PseudoHeaderOrderID = "browser-h2-pseudo-header-order"
	case "web.h1.ws":
		surface.WebSocketUpgradeShapeID = "browser-websocket-upgrade"
		surface.PublicLabels = []string{"https", "upgrade", "websocket", "sec-websocket-key"}
	case "web.shadow-origin":
		surface.RequestGraphID = "shadow-origin-request-graph"
	case "web.h3.stream":
		surface.H3SettingsID = "browser-h3-settings-family"
		surface.QPACKBehaviorID = "browser-qpack-family"
		surface.DatagramWebTransportProfileID = "standards-webtransport-profile"
		surface.PublicLabels = []string{"https", "h3", "webtransport"}
	case "web.h3.ext-dgram":
		surface.H3SettingsID = "browser-h3-settings-family"
		surface.QPACKBehaviorID = "browser-qpack-family"
		surface.DatagramWebTransportProfileID = "standards-webtransport-datagram-profile"
		surface.PublicLabels = []string{"https", "h3", "webtransport", "datagram"}
	}
	return surface
}

func (s ClassifierSurface) classifierFeatures() map[string]string {
	return map[string]string{
		"tls_fingerprint_family":          s.TLSFingerprintFamily,
		"h2_settings":                     s.H2SettingsID,
		"h2_pseudo_header_order":          s.H2PseudoHeaderOrderID,
		"h3_settings":                     s.H3SettingsID,
		"qpack_behavior":                  s.QPACKBehaviorID,
		"datagram_webtransport_profile":   s.DatagramWebTransportProfileID,
		"websocket_upgrade_shape":         s.WebSocketUpgradeShapeID,
		"request_graph":                   s.RequestGraphID,
		"request_body_size_distribution":  s.RequestBodySizeDistributionID,
		"response_body_size_distribution": s.ResponseBodySizeDistributionID,
		"cache_cookie_redirect":           s.CacheCookieRedirectClass,
		"timeout_close":                   s.TimeoutCloseClass,
		"packet_count_before_close":       s.PacketCountBeforeCloseBucket,
		"probe_http_status":               strconv.Itoa(s.ProbeSurface.HTTPStatus),
		"probe_body_size":                 strconv.Itoa(len(s.ProbeSurface.Body)),
		"probe_close_code":                strconv.Itoa(int(s.ProbeSurface.CloseCode)),
		"probe_tls_alert":                 strconv.Itoa(int(s.ProbeSurface.TLSAlertClass)),
		"probe_quic_close":                strconv.FormatUint(s.ProbeSurface.QUICCloseCode, 10),
		"probe_websocket_close":           strconv.Itoa(int(s.ProbeSurface.WebSocketCloseCode)),
		"probe_timing_class":              s.ProbeSurface.TimingClass,
		"probe_reflected_log":             s.ProbeSurface.ReflectedLog,
	}
}

func scanPublicLabels(sample string, labels []string) []ForbiddenPublicMarker {
	var findings []ForbiddenPublicMarker
	for _, label := range labels {
		lower := strings.ToLower(label)
		for _, marker := range forbiddenClassifierPublicMarkers {
			if strings.Contains(lower, marker) {
				findings = append(findings, ForbiddenPublicMarker{Sample: sample, Label: label, Marker: marker})
				break
			}
		}
	}
	return findings
}

var classifierFeatureNames = []string{
	"tls_fingerprint_family",
	"h2_settings",
	"h2_pseudo_header_order",
	"h3_settings",
	"qpack_behavior",
	"datagram_webtransport_profile",
	"websocket_upgrade_shape",
	"request_graph",
	"request_body_size_distribution",
	"response_body_size_distribution",
	"cache_cookie_redirect",
	"timeout_close",
	"packet_count_before_close",
	"probe_http_status",
	"probe_body_size",
	"probe_close_code",
	"probe_tls_alert",
	"probe_quic_close",
	"probe_websocket_close",
	"probe_timing_class",
	"probe_reflected_log",
}

var forbiddenClassifierPublicMarkers = []string{
	"aurora",
	"admission",
	"token",
	"hint",
	"capsule",
	"proof",
	"relay",
	"bridge",
	"proxy",
	"vpn",
	"tunnel",
	"dpi",
	"gfw",
}
