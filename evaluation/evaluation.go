package evaluation

import "fmt"

type EvidenceBundle struct {
	BundleID                     string
	VectorPackageHash            []byte
	Interoperability             InteroperabilityEvidence
	ClassifierReports            []ClassifierReport
	ActiveProbeReports           []ActiveProbeReport
	SecurityReviews              []SecurityReview
	ReleaseGates                 ReleaseGateEvidence
	DeploymentSecurityAssessment DeploymentSecurityAssessment
}

type InteroperabilityEvidence struct {
	IndependentImplementations int
	Fast1Interop               bool
	Split2Interop              bool
	RealCryptoOutputs          bool
}

type ClassifierReport struct {
	ReportID            string
	IndependentLab      bool
	SameCoverTemplate   bool
	OrdinarySamples     int
	CandidateSamples    int
	ClassifierAdvantage float64
	AllowedAdvantage    float64
	ForbiddenMarkers    int
	Distinguishers      int
}

type ActiveProbeReport struct {
	ReportID                  string
	IndependentLab            bool
	ProbeCases                int
	OrdinaryOriginControl     bool
	DistinguishableFailures   int
	ForbiddenPublicMarkers    int
	CoverNeutralFailureBodies bool
}

type SecurityReview struct {
	ReviewID     string
	Area         string
	Independent  bool
	Complete     bool
	CriticalOpen int
	HighOpen     int
}

type ReleaseGateEvidence struct {
	ReproducibleBuilds     bool
	SignedUpdatePipeline   bool
	IncidentResponsePlan   bool
	OperationalAbuseReview bool
	PlatformSecurityReview bool
}

type DeploymentSecurityAssessment struct {
	AssessmentID                 string
	DeploymentID                 string
	IndependentAssessor          bool
	RealDeployment               bool
	IssuerScope                  bool
	RelayScope                   bool
	DirectoryScope               bool
	CoverOriginScope             bool
	ClientUpdateScope            bool
	VerifierOutageDrill          bool
	CoverOriginFailoverDrill     bool
	ReplayAbuseDrill             bool
	OperationalTelemetryRedacted bool
	IncidentResponseLinked       bool
	CriticalOpen                 int
	HighOpen                     int
	CompletedUnix                uint64
}

type EvidenceReport struct {
	Passed                               bool
	ClassifierEvidence                   bool
	ActiveProbeEvidence                  bool
	InteroperabilityEvidence             bool
	SecurityReviewEvidence               bool
	ReleaseGateEvidence                  bool
	DeploymentSecurityAssessmentEvidence bool
	Findings                             []string
}

func VerifyExternalEvaluationEvidence(bundle EvidenceBundle) (EvidenceReport, error) {
	if bundle.BundleID == "" {
		return EvidenceReport{}, fmt.Errorf("evaluation: bundle id is empty")
	}
	if len(bundle.VectorPackageHash) != 48 {
		return EvidenceReport{}, fmt.Errorf("evaluation: vector package hash must be 48 bytes")
	}
	report := EvidenceReport{}
	report.InteroperabilityEvidence = verifyInteroperabilityEvidence(bundle.Interoperability, &report)
	report.ClassifierEvidence = verifyClassifierEvidence(bundle.ClassifierReports, &report)
	report.ActiveProbeEvidence = verifyActiveProbeEvidence(bundle.ActiveProbeReports, &report)
	report.SecurityReviewEvidence = verifySecurityReviewEvidence(bundle.SecurityReviews, &report)
	report.ReleaseGateEvidence = verifyReleaseGateEvidence(bundle.ReleaseGates, &report)
	report.DeploymentSecurityAssessmentEvidence = verifyDeploymentSecurityAssessment(bundle.DeploymentSecurityAssessment, &report)
	report.Passed = report.InteroperabilityEvidence &&
		report.ClassifierEvidence &&
		report.ActiveProbeEvidence &&
		report.SecurityReviewEvidence &&
		report.ReleaseGateEvidence &&
		report.DeploymentSecurityAssessmentEvidence
	return report, nil
}

func ExternalEvaluationHarnessBundle() EvidenceBundle {
	return EvidenceBundle{
		BundleID:          "external-evaluation-harness",
		VectorPackageHash: repeatedByte(0x40, 48),
		Interoperability: InteroperabilityEvidence{
			IndependentImplementations: 2,
			Fast1Interop:               true,
			Split2Interop:              true,
			RealCryptoOutputs:          true,
		},
		ClassifierReports: []ClassifierReport{{
			ReportID:            "classifier-report",
			IndependentLab:      true,
			SameCoverTemplate:   true,
			OrdinarySamples:     5000,
			CandidateSamples:    5000,
			ClassifierAdvantage: 0.01,
			AllowedAdvantage:    0.02,
			ForbiddenMarkers:    0,
			Distinguishers:      0,
		}},
		ActiveProbeReports: []ActiveProbeReport{{
			ReportID:                  "active-probe-report",
			IndependentLab:            true,
			ProbeCases:                14,
			OrdinaryOriginControl:     true,
			DistinguishableFailures:   0,
			ForbiddenPublicMarkers:    0,
			CoverNeutralFailureBodies: true,
		}},
		SecurityReviews: []SecurityReview{{
			ReviewID:    "crypto-review",
			Area:        "cryptography",
			Independent: true,
			Complete:    true,
		}, {
			ReviewID:    "abuse-review",
			Area:        "operational-abuse",
			Independent: true,
			Complete:    true,
		}, {
			ReviewID:    "platform-review",
			Area:        "platform-security",
			Independent: true,
			Complete:    true,
		}},
		ReleaseGates: ReleaseGateEvidence{
			ReproducibleBuilds:     true,
			SignedUpdatePipeline:   true,
			IncidentResponsePlan:   true,
			OperationalAbuseReview: true,
			PlatformSecurityReview: true,
		},
		DeploymentSecurityAssessment: DeploymentSecurityAssessment{
			AssessmentID:                 "deployment-security-assessment",
			DeploymentID:                 "production-candidate-deployment",
			IndependentAssessor:          true,
			RealDeployment:               true,
			IssuerScope:                  true,
			RelayScope:                   true,
			DirectoryScope:               true,
			CoverOriginScope:             true,
			ClientUpdateScope:            true,
			VerifierOutageDrill:          true,
			CoverOriginFailoverDrill:     true,
			ReplayAbuseDrill:             true,
			OperationalTelemetryRedacted: true,
			IncidentResponseLinked:       true,
			CompletedUnix:                1,
		},
	}
}

func verifyInteroperabilityEvidence(evidence InteroperabilityEvidence, report *EvidenceReport) bool {
	passed := true
	if evidence.IndependentImplementations < 2 {
		report.addFinding("fewer than two independent implementations passed vectors")
		passed = false
	}
	if !evidence.Fast1Interop {
		report.addFinding("fast-1 interoperability evidence is missing")
		passed = false
	}
	if !evidence.Split2Interop {
		report.addFinding("split-2 interoperability evidence is missing")
		passed = false
	}
	if !evidence.RealCryptoOutputs {
		report.addFinding("real cryptographic output interoperability is missing")
		passed = false
	}
	return passed
}

func verifyClassifierEvidence(reports []ClassifierReport, out *EvidenceReport) bool {
	if len(reports) == 0 {
		out.addFinding("classifier report is missing")
		return false
	}
	passed := true
	for _, report := range reports {
		if report.ReportID == "" {
			out.addFinding("classifier report id is missing")
			passed = false
		}
		if !report.IndependentLab {
			out.addFinding("classifier report is not independent")
			passed = false
		}
		if !report.SameCoverTemplate {
			out.addFinding("classifier report does not compare against the same cover template")
			passed = false
		}
		if report.OrdinarySamples <= 0 || report.CandidateSamples <= 0 {
			out.addFinding("classifier report lacks ordinary or candidate samples")
			passed = false
		}
		allowed := report.AllowedAdvantage
		if allowed <= 0 {
			allowed = 0.02
		}
		if report.ClassifierAdvantage > allowed {
			out.addFinding("classifier advantage exceeds deployment threshold")
			passed = false
		}
		if report.ForbiddenMarkers != 0 || report.Distinguishers != 0 {
			out.addFinding("classifier report found distinguishers or forbidden markers")
			passed = false
		}
	}
	return passed
}

func verifyActiveProbeEvidence(reports []ActiveProbeReport, out *EvidenceReport) bool {
	if len(reports) == 0 {
		out.addFinding("active-probe report is missing")
		return false
	}
	passed := true
	for _, report := range reports {
		if report.ReportID == "" {
			out.addFinding("active-probe report id is missing")
			passed = false
		}
		if !report.IndependentLab {
			out.addFinding("active-probe report is not independent")
			passed = false
		}
		if report.ProbeCases < 14 {
			out.addFinding("active-probe report has incomplete probe coverage")
			passed = false
		}
		if !report.OrdinaryOriginControl {
			out.addFinding("active-probe report lacks ordinary-origin control")
			passed = false
		}
		if report.DistinguishableFailures != 0 {
			out.addFinding("active-probe report found distinguishable failures")
			passed = false
		}
		if report.ForbiddenPublicMarkers != 0 {
			out.addFinding("active-probe report found forbidden public markers")
			passed = false
		}
		if !report.CoverNeutralFailureBodies {
			out.addFinding("active-probe failures were not cover-neutral")
			passed = false
		}
	}
	return passed
}

func verifySecurityReviewEvidence(reviews []SecurityReview, report *EvidenceReport) bool {
	required := map[string]bool{
		"cryptography":      false,
		"operational-abuse": false,
		"platform-security": false,
	}
	passed := true
	for _, review := range reviews {
		if review.ReviewID == "" {
			report.addFinding("security review id is missing")
			passed = false
		}
		if !review.Independent {
			report.addFinding("security review is not independent")
			passed = false
		}
		if !review.Complete {
			report.addFinding("security review is incomplete")
			passed = false
		}
		if review.CriticalOpen != 0 || review.HighOpen != 0 {
			report.addFinding("security review has open high-severity findings")
			passed = false
		}
		if _, ok := required[review.Area]; ok && review.Independent && review.Complete && review.CriticalOpen == 0 && review.HighOpen == 0 {
			required[review.Area] = true
		}
	}
	for area, present := range required {
		if !present {
			report.addFinding("required security review missing: " + area)
			passed = false
		}
	}
	return passed
}

func verifyReleaseGateEvidence(gates ReleaseGateEvidence, report *EvidenceReport) bool {
	passed := true
	if !gates.ReproducibleBuilds {
		report.addFinding("reproducible build evidence is missing")
		passed = false
	}
	if !gates.SignedUpdatePipeline {
		report.addFinding("signed update pipeline evidence is missing")
		passed = false
	}
	if !gates.IncidentResponsePlan {
		report.addFinding("incident-response plan evidence is missing")
		passed = false
	}
	if !gates.OperationalAbuseReview {
		report.addFinding("operational abuse review gate is missing")
		passed = false
	}
	if !gates.PlatformSecurityReview {
		report.addFinding("platform security review gate is missing")
		passed = false
	}
	return passed
}

func verifyDeploymentSecurityAssessment(assessment DeploymentSecurityAssessment, report *EvidenceReport) bool {
	passed := true
	if assessment.AssessmentID == "" {
		report.addFinding("deployment security assessment id is missing")
		passed = false
	}
	if assessment.DeploymentID == "" {
		report.addFinding("deployment security assessment deployment id is missing")
		passed = false
	}
	if !assessment.IndependentAssessor {
		report.addFinding("deployment security assessment is not independent")
		passed = false
	}
	if !assessment.RealDeployment {
		report.addFinding("deployment security assessment must cover a real deployment")
		passed = false
	}
	if !assessment.IssuerScope {
		report.addFinding("deployment security assessment missing issuer scope")
		passed = false
	}
	if !assessment.RelayScope {
		report.addFinding("deployment security assessment missing relay scope")
		passed = false
	}
	if !assessment.DirectoryScope {
		report.addFinding("deployment security assessment missing directory scope")
		passed = false
	}
	if !assessment.CoverOriginScope {
		report.addFinding("deployment security assessment missing cover-origin scope")
		passed = false
	}
	if !assessment.ClientUpdateScope {
		report.addFinding("deployment security assessment missing client update scope")
		passed = false
	}
	if !assessment.VerifierOutageDrill || !assessment.CoverOriginFailoverDrill || !assessment.ReplayAbuseDrill {
		report.addFinding("deployment security assessment missing outage or replay drills")
		passed = false
	}
	if !assessment.OperationalTelemetryRedacted {
		report.addFinding("deployment security assessment missing telemetry redaction review")
		passed = false
	}
	if !assessment.IncidentResponseLinked {
		report.addFinding("deployment security assessment missing incident-response linkage")
		passed = false
	}
	if assessment.CriticalOpen != 0 {
		report.addFinding("deployment security assessment has open critical findings")
		passed = false
	}
	if assessment.HighOpen != 0 {
		report.addFinding("deployment security assessment has open high-severity findings")
		passed = false
	}
	if assessment.CompletedUnix == 0 {
		report.addFinding("deployment security assessment completion timestamp is missing")
		passed = false
	}
	return passed
}

func (r *EvidenceReport) addFinding(finding string) {
	r.Findings = append(r.Findings, finding)
}

func repeatedByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
