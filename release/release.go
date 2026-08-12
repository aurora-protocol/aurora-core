package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/platform"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	PredicateSLSAProvenance = "https://slsa.dev/provenance/v1"

	RoleRoot      = "root"
	RoleTargets   = "targets"
	RoleSnapshot  = "snapshot"
	RoleTimestamp = "timestamp"
)

type Bundle struct {
	BundleID           string
	NowUnix            uint64
	Artifacts          []Artifact
	UpdatePipeline     SignedUpdatePipeline
	DeviceProvisioning []DeviceProvisioningEvidence
	IncidentResponse   IncidentResponsePlan
}

type Artifact struct {
	Name          string
	Platform      platform.Kind
	Version       string
	SizeBytes     uint64
	Digest        []byte
	RebuildDigest []byte
	Provenance    Provenance
	Signatures    []SignatureRecord
}

type Provenance struct {
	PredicateType        string
	BuildType            string
	BuilderID            string
	SourceRepository     string
	SourceCommit         string
	SubjectName          string
	SubjectDigest        []byte
	SLSALevel            uint8
	ResolvedDependencies []Dependency
}

type Dependency struct {
	URI    string
	Digest []byte
}

type SignedUpdatePipeline struct {
	Roles   []UpdateRole
	Targets []UpdateTarget
}

type UpdateRole struct {
	Name          string
	Version       uint64
	ExpiresUnix   uint64
	Threshold     int
	PayloadDigest []byte
	Signatures    []SignatureRecord
}

type UpdateTarget struct {
	ArtifactName string
	Digest       []byte
	SizeBytes    uint64
}

type DeviceProvisioningEvidence struct {
	TargetName             string
	Platform               platform.Kind
	Entitlements           []string
	ProvisioningProfile    []byte
	SigningIdentity        string
	ReleaseChannel         string
	DevicePolicyValidated  bool
	RevocationPathVerified bool
}

type IncidentResponsePlan struct {
	PlanID                   string
	SecurityContact          string
	KeyRevocationRunbookID   string
	UpdateRollbackRunbookID  string
	AbuseEscalationRunbookID string
	LastExerciseUnix         uint64
	MaxExerciseAgeSeconds    uint64
	CompromisedKeyTested     bool
	UpdateRollbackTested     bool
	DisclosureWorkflowTested bool
}

type SignatureRecord struct {
	KeyID     []byte
	PublicKey protocol.PublicKeyRecord
	Signature []byte
}

type ReadinessReport struct {
	Passed               bool
	ArtifactSignatures   bool
	Provenance           bool
	ReproducibleBuilds   bool
	SignedUpdatePipeline bool
	DeviceProvisioning   bool
	IncidentResponsePlan bool
	ReleaseArtifacts     int
	UpdateRoles          int
	Findings             []string
}

func RunReleaseReadinessHarness(nowUnix uint64) (ReadinessReport, error) {
	bundle, err := ReleaseReadinessHarnessBundle(nowUnix)
	if err != nil {
		return ReadinessReport{}, err
	}
	return VerifyReleaseReadinessBundle(bundle)
}

func VerifyReleaseReadinessBundle(bundle Bundle) (ReadinessReport, error) {
	if bundle.BundleID == "" {
		return ReadinessReport{}, fmt.Errorf("release: bundle id is empty")
	}
	if bundle.NowUnix == 0 {
		return ReadinessReport{}, fmt.Errorf("release: verification time is empty")
	}
	report := ReadinessReport{}
	targets := releasePackagingTargets()
	artifactsByName := map[string]Artifact{}
	for _, artifact := range bundle.Artifacts {
		artifactsByName[artifact.Name] = artifact
	}
	report.ReleaseArtifacts = len(bundle.Artifacts)
	report.UpdateRoles = len(bundle.UpdatePipeline.Roles)

	report.ArtifactSignatures = verifyArtifactSignatures(bundle.Artifacts, &report)
	report.Provenance = verifyArtifactProvenance(bundle.Artifacts, &report)
	report.ReproducibleBuilds = verifyReproducibleBuilds(bundle.Artifacts, &report)
	if !verifyRequiredReleaseArtifacts(targets, artifactsByName, &report) {
		report.ArtifactSignatures = false
		report.Provenance = false
		report.ReproducibleBuilds = false
	}
	report.SignedUpdatePipeline = verifySignedUpdatePipeline(bundle.UpdatePipeline, artifactsByName, bundle.NowUnix, &report)
	report.DeviceProvisioning = verifyDeviceProvisioning(targets, bundle.DeviceProvisioning, &report)
	report.IncidentResponsePlan = verifyIncidentResponsePlan(bundle.IncidentResponse, bundle.NowUnix, &report)
	report.Passed = report.ArtifactSignatures &&
		report.Provenance &&
		report.ReproducibleBuilds &&
		report.SignedUpdatePipeline &&
		report.DeviceProvisioning &&
		report.IncidentResponsePlan
	return report, nil
}

func ReleaseReadinessHarnessBundle(nowUnix uint64) (Bundle, error) {
	releaseSigner, err := newSigner()
	if err != nil {
		return Bundle{}, err
	}
	targets := releasePackagingTargets()
	artifacts := make([]Artifact, 0, len(targets))
	for i, target := range targets {
		digest := artifactDigest(target.Name, target.Kind, byte(i+1))
		artifact := Artifact{
			Name:          target.Name,
			Platform:      target.Kind,
			Version:       "1.0.0",
			SizeBytes:     uint64(1_000_000 + i),
			Digest:        digest,
			RebuildDigest: append([]byte(nil), digest...),
			Provenance: Provenance{
				PredicateType:    PredicateSLSAProvenance,
				BuildType:        "https://build.aurora.example/release",
				BuilderID:        "https://builder.aurora.example/github-actions",
				SourceRepository: "https://github.com/aurora-protocol/aurora-core",
				SourceCommit:     "0123456789abcdef0123456789abcdef01234567",
				SubjectName:      target.Name,
				SubjectDigest:    append([]byte(nil), digest...),
				SLSALevel:        3,
				ResolvedDependencies: []Dependency{{
					URI:    "git+https://github.com/aurora-protocol/aurora-core",
					Digest: repeatedByte(0x60+byte(i), 48),
				}},
			},
		}
		input, err := artifactSignatureInput(artifact)
		if err != nil {
			return Bundle{}, err
		}
		signature, err := releaseSigner.sign(input)
		if err != nil {
			return Bundle{}, err
		}
		artifact.Signatures = []SignatureRecord{signature}
		artifacts = append(artifacts, artifact)
	}
	update, err := signedUpdatePipeline(artifacts, nowUnix)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		BundleID:           "release-readiness-harness",
		NowUnix:            nowUnix,
		Artifacts:          artifacts,
		UpdatePipeline:     update,
		DeviceProvisioning: deviceProvisioningEvidence(targets),
		IncidentResponse: IncidentResponsePlan{
			PlanID:                   "incident-response-plan",
			SecurityContact:          "security@example.invalid",
			KeyRevocationRunbookID:   "key-revocation-runbook",
			UpdateRollbackRunbookID:  "update-rollback-runbook",
			AbuseEscalationRunbookID: "abuse-escalation-runbook",
			LastExerciseUnix:         nowUnix - 50,
			MaxExerciseAgeSeconds:    180 * 24 * 60 * 60,
			CompromisedKeyTested:     true,
			UpdateRollbackTested:     true,
			DisclosureWorkflowTested: true,
		},
	}, nil
}

func verifyArtifactSignatures(artifacts []Artifact, report *ReadinessReport) bool {
	passed := true
	for _, artifact := range artifacts {
		input, err := artifactSignatureInput(artifact)
		if err != nil {
			report.addFinding("release artifact signature input failed: " + err.Error())
			passed = false
			continue
		}
		if !verifyThreshold(input, artifact.Signatures, 1) {
			report.addFinding("release artifact missing valid signature")
			passed = false
		}
	}
	return passed
}

func verifyArtifactProvenance(artifacts []Artifact, report *ReadinessReport) bool {
	passed := true
	for _, artifact := range artifacts {
		provenance := artifact.Provenance
		if provenance.PredicateType != PredicateSLSAProvenance {
			report.addFinding("release artifact provenance predicate is unsupported")
			passed = false
		}
		if provenance.BuildType == "" || provenance.BuilderID == "" {
			report.addFinding("release artifact provenance lacks build type or builder")
			passed = false
		}
		if provenance.SourceRepository == "" || !isHexCommit(provenance.SourceCommit) {
			report.addFinding("release artifact provenance lacks source repository or commit")
			passed = false
		}
		if provenance.SubjectName != artifact.Name || !bytes.Equal(provenance.SubjectDigest, artifact.Digest) {
			report.addFinding("release artifact provenance subject mismatch")
			passed = false
		}
		if provenance.SLSALevel < 3 {
			report.addFinding("release artifact provenance below required build level")
			passed = false
		}
		if len(provenance.ResolvedDependencies) == 0 {
			report.addFinding("release artifact provenance lacks resolved dependencies")
			passed = false
		}
		for _, dependency := range provenance.ResolvedDependencies {
			if dependency.URI == "" || len(dependency.Digest) != 48 {
				report.addFinding("release artifact provenance dependency is incomplete")
				passed = false
			}
		}
	}
	return passed
}

func verifyReproducibleBuilds(artifacts []Artifact, report *ReadinessReport) bool {
	passed := true
	for _, artifact := range artifacts {
		if len(artifact.Digest) != 48 || len(artifact.RebuildDigest) != 48 {
			report.addFinding("release artifact digest length is invalid")
			passed = false
			continue
		}
		if !bytes.Equal(artifact.Digest, artifact.RebuildDigest) {
			report.addFinding("release artifact rebuild digest mismatch")
			passed = false
		}
	}
	return passed
}

func verifyRequiredReleaseArtifacts(targets []platform.PackagingTarget, artifactsByName map[string]Artifact, report *ReadinessReport) bool {
	passed := true
	for _, target := range targets {
		artifact, ok := artifactsByName[target.Name]
		if !ok {
			report.addFinding("release artifact missing for " + target.Name)
			passed = false
			continue
		}
		if artifact.Platform != target.Kind {
			report.addFinding("release artifact platform mismatch for " + target.Name)
			passed = false
		}
		if artifact.Version == "" || artifact.SizeBytes == 0 {
			report.addFinding("release artifact lacks version or size for " + target.Name)
			passed = false
		}
	}
	return passed
}

func verifySignedUpdatePipeline(update SignedUpdatePipeline, artifactsByName map[string]Artifact, nowUnix uint64, report *ReadinessReport) bool {
	passed := true
	roles := map[string]UpdateRole{}
	for _, role := range update.Roles {
		roles[role.Name] = role
	}
	for _, name := range []string{RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp} {
		role, ok := roles[name]
		if !ok {
			report.addFinding("signed update role " + name + " missing")
			passed = false
			continue
		}
		input, err := updateRoleSignatureInput(role)
		if err != nil {
			report.addFinding("signed update role " + name + " input failed")
			passed = false
			continue
		}
		if role.ExpiresUnix <= nowUnix {
			report.addFinding("signed update role " + name + " expired")
			passed = false
		}
		if role.Threshold <= 0 || !verifyThreshold(input, role.Signatures, role.Threshold) {
			report.addFinding("signed update role " + name + " lacks threshold signatures")
			passed = false
		}
	}
	targetDigest, err := updateTargetsPayloadDigest(update.Targets)
	if err != nil {
		report.addFinding("signed update targets payload failed: " + err.Error())
		passed = false
	} else {
		if role, ok := roles[RoleRoot]; ok && !bytes.Equal(role.PayloadDigest, roleLinkPayloadDigest(RoleRoot, targetDigest)) {
			report.addFinding("signed update root payload digest mismatch")
			passed = false
		}
		if role, ok := roles[RoleTargets]; ok && !bytes.Equal(role.PayloadDigest, targetDigest) {
			report.addFinding("signed update targets payload digest mismatch")
			passed = false
		}
	}
	if role, ok := roles[RoleSnapshot]; ok {
		want := roleLinkPayloadDigest(RoleSnapshot, roles[RoleTargets].PayloadDigest)
		if !bytes.Equal(role.PayloadDigest, want) {
			report.addFinding("signed update snapshot payload digest mismatch")
			passed = false
		}
	}
	if role, ok := roles[RoleTimestamp]; ok {
		want := roleLinkPayloadDigest(RoleTimestamp, roles[RoleSnapshot].PayloadDigest)
		if !bytes.Equal(role.PayloadDigest, want) {
			report.addFinding("signed update timestamp payload digest mismatch")
			passed = false
		}
	}
	for _, target := range update.Targets {
		artifact, ok := artifactsByName[target.ArtifactName]
		if !ok {
			report.addFinding("signed update target references unknown artifact")
			passed = false
			continue
		}
		if target.SizeBytes != artifact.SizeBytes || !bytes.Equal(target.Digest, artifact.Digest) {
			report.addFinding("signed update target digest or size mismatch")
			passed = false
		}
	}
	for name := range artifactsByName {
		if !updateTargetsContain(update.Targets, name) {
			report.addFinding("signed update target missing for " + name)
			passed = false
		}
	}
	return passed
}

func verifyDeviceProvisioning(targets []platform.PackagingTarget, evidence []DeviceProvisioningEvidence, report *ReadinessReport) bool {
	passed := true
	byName := map[string]DeviceProvisioningEvidence{}
	for _, item := range evidence {
		byName[item.TargetName] = item
	}
	for _, target := range targets {
		item, ok := byName[target.Name]
		if !ok {
			report.addFinding("device provisioning evidence missing for " + target.Name)
			passed = false
			continue
		}
		if item.Platform != target.Kind {
			report.addFinding("device provisioning platform mismatch for " + target.Name)
			passed = false
		}
		for _, entitlement := range target.RequiredEntitlements {
			if !hasString(item.Entitlements, entitlement) {
				report.addFinding("device provisioning entitlement missing for " + target.Name)
				passed = false
			}
		}
		if len(item.ProvisioningProfile) != 48 || item.SigningIdentity == "" || item.ReleaseChannel != "production" {
			report.addFinding("device provisioning identity/profile incomplete for " + target.Name)
			passed = false
		}
		if !item.DevicePolicyValidated || !item.RevocationPathVerified {
			report.addFinding("device provisioning policy checks incomplete for " + target.Name)
			passed = false
		}
	}
	return passed
}

func verifyIncidentResponsePlan(plan IncidentResponsePlan, nowUnix uint64, report *ReadinessReport) bool {
	passed := true
	if plan.PlanID == "" || plan.SecurityContact == "" || plan.KeyRevocationRunbookID == "" ||
		plan.UpdateRollbackRunbookID == "" || plan.AbuseEscalationRunbookID == "" {
		report.addFinding("incident-response plan metadata is incomplete")
		passed = false
	}
	if plan.LastExerciseUnix == 0 || plan.LastExerciseUnix > nowUnix {
		report.addFinding("incident-response plan exercise timestamp is invalid")
		passed = false
	} else {
		maxAge := plan.MaxExerciseAgeSeconds
		if maxAge == 0 {
			maxAge = 180 * 24 * 60 * 60
		}
		if nowUnix-plan.LastExerciseUnix > maxAge {
			report.addFinding("incident-response plan exercise is stale")
			passed = false
		}
	}
	if !plan.CompromisedKeyTested || !plan.UpdateRollbackTested || !plan.DisclosureWorkflowTested {
		report.addFinding("incident-response plan drills are incomplete")
		passed = false
	}
	return passed
}

func signedUpdatePipeline(artifacts []Artifact, nowUnix uint64) (SignedUpdatePipeline, error) {
	targets := make([]UpdateTarget, 0, len(artifacts))
	for _, artifact := range artifacts {
		targets = append(targets, UpdateTarget{
			ArtifactName: artifact.Name,
			Digest:       append([]byte(nil), artifact.Digest...),
			SizeBytes:    artifact.SizeBytes,
		})
	}
	targetDigest, err := updateTargetsPayloadDigest(targets)
	if err != nil {
		return SignedUpdatePipeline{}, err
	}
	rootPayload := roleLinkPayloadDigest(RoleRoot, targetDigest)
	snapshotPayload := roleLinkPayloadDigest(RoleSnapshot, targetDigest)
	timestampPayload := roleLinkPayloadDigest(RoleTimestamp, snapshotPayload)
	roles := []UpdateRole{
		{Name: RoleRoot, Version: 1, ExpiresUnix: nowUnix + 90*24*60*60, Threshold: 1, PayloadDigest: rootPayload},
		{Name: RoleTargets, Version: 1, ExpiresUnix: nowUnix + 30*24*60*60, Threshold: 1, PayloadDigest: targetDigest},
		{Name: RoleSnapshot, Version: 1, ExpiresUnix: nowUnix + 7*24*60*60, Threshold: 1, PayloadDigest: snapshotPayload},
		{Name: RoleTimestamp, Version: 1, ExpiresUnix: nowUnix + 24*60*60, Threshold: 1, PayloadDigest: timestampPayload},
	}
	for i := range roles {
		signer, err := newSigner()
		if err != nil {
			return SignedUpdatePipeline{}, err
		}
		input, err := updateRoleSignatureInput(roles[i])
		if err != nil {
			return SignedUpdatePipeline{}, err
		}
		signature, err := signer.sign(input)
		if err != nil {
			return SignedUpdatePipeline{}, err
		}
		roles[i].Signatures = []SignatureRecord{signature}
	}
	return SignedUpdatePipeline{Roles: roles, Targets: targets}, nil
}

func deviceProvisioningEvidence(targets []platform.PackagingTarget) []DeviceProvisioningEvidence {
	out := make([]DeviceProvisioningEvidence, 0, len(targets))
	for i, target := range targets {
		out = append(out, DeviceProvisioningEvidence{
			TargetName:             target.Name,
			Platform:               target.Kind,
			Entitlements:           append([]string(nil), target.RequiredEntitlements...),
			ProvisioningProfile:    auroracrypto.PreHashLabel("aurora release provisioning", []byte(target.Name), []byte{byte(i)}),
			SigningIdentity:        "aurora-release-signing",
			ReleaseChannel:         "production",
			DevicePolicyValidated:  true,
			RevocationPathVerified: true,
		})
	}
	return out
}

func artifactSignatureInput(artifact Artifact) ([]byte, error) {
	provenanceDigest, err := provenancePayloadDigest(artifact.Provenance)
	if err != nil {
		return nil, err
	}
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora release artifact signature"))
	e.WriteOpaque16([]byte(artifact.Name))
	e.WriteOpaque16([]byte(artifact.Platform))
	e.WriteOpaque16([]byte(artifact.Version))
	e.WriteUint64(artifact.SizeBytes)
	e.WritePreHash(artifact.Digest)
	e.WritePreHash(provenanceDigest)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func provenancePayloadDigest(provenance Provenance) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora release provenance"))
	e.WriteOpaque16([]byte(provenance.PredicateType))
	e.WriteOpaque16([]byte(provenance.BuildType))
	e.WriteOpaque16([]byte(provenance.BuilderID))
	e.WriteOpaque16([]byte(provenance.SourceRepository))
	e.WriteOpaque16([]byte(provenance.SourceCommit))
	e.WriteOpaque16([]byte(provenance.SubjectName))
	e.WritePreHash(provenance.SubjectDigest)
	e.WriteUint8(provenance.SLSALevel)
	e.WriteVarint(uint64(len(provenance.ResolvedDependencies)))
	for _, dependency := range provenance.ResolvedDependencies {
		e.WriteOpaque16([]byte(dependency.URI))
		e.WritePreHash(dependency.Digest)
	}
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func updateRoleSignatureInput(role UpdateRole) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora release update role"))
	e.WriteOpaque16([]byte(role.Name))
	e.WriteUint64(role.Version)
	e.WriteUint64(role.ExpiresUnix)
	e.WriteVarint(uint64(role.Threshold))
	e.WritePreHash(role.PayloadDigest)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func updateTargetsPayloadDigest(targets []UpdateTarget) ([]byte, error) {
	ordered := append([]UpdateTarget(nil), targets...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ArtifactName < ordered[j].ArtifactName })
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora release update targets"))
	e.WriteVarint(uint64(len(ordered)))
	for _, target := range ordered {
		e.WriteOpaque16([]byte(target.ArtifactName))
		e.WritePreHash(target.Digest)
		e.WriteUint64(target.SizeBytes)
	}
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func roleLinkPayloadDigest(role string, digest []byte) []byte {
	return auroracrypto.PreHashLabel("aurora release update "+role, digest)
}

func verifyThreshold(input []byte, signatures []SignatureRecord, threshold int) bool {
	valid := 0
	seen := map[string]struct{}{}
	for _, signature := range signatures {
		if len(signature.KeyID) != 16 {
			continue
		}
		key := string(signature.KeyID)
		if _, ok := seen[key]; ok {
			continue
		}
		if signature.PublicKey.ValidateCompatibility() != nil {
			continue
		}
		expectedKeyID, err := releaseSigningKeyID(signature.PublicKey)
		if err != nil || !bytes.Equal(signature.KeyID, expectedKeyID) {
			continue
		}
		if err := auroracrypto.VerifySignature(
			signature.PublicKey.SignatureScheme,
			signature.PublicKey.KeyEncoding,
			signature.PublicKey.PublicKey,
			input,
			signature.Signature,
		); err != nil {
			continue
		}
		seen[key] = struct{}{}
		valid++
	}
	return valid >= threshold
}

type signer struct {
	privateKey *ecdsa.PrivateKey
	keyID      []byte
	publicKey  protocol.PublicKeyRecord
}

func newSigner() (signer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return signer{}, err
	}
	encodedPublicKey, err := privateKey.PublicKey.Bytes()
	if err != nil {
		return signer{}, err
	}
	publicKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       encodedPublicKey,
	}
	keyID, err := releaseSigningKeyID(publicKey)
	if err != nil {
		return signer{}, err
	}
	return signer{
		privateKey: privateKey,
		keyID:      keyID,
		publicKey:  publicKey,
	}, nil
}

func (s signer) sign(input []byte) (SignatureRecord, error) {
	signature, err := ecdsa.SignASN1(rand.Reader, s.privateKey, input)
	if err != nil {
		return SignatureRecord{}, err
	}
	return SignatureRecord{
		KeyID:     append([]byte(nil), s.keyID...),
		PublicKey: s.publicKey,
		Signature: signature,
	}, nil
}

func releaseSigningKeyID(publicKey protocol.PublicKeyRecord) ([]byte, error) {
	encoded, err := protocol.Encode(publicKey)
	if err != nil {
		return nil, err
	}
	return auroracrypto.Truncate128(auroracrypto.PreHashLabel("aurora release signing key", encoded)), nil
}

func releasePackagingTargets() []platform.PackagingTarget {
	var out []platform.PackagingTarget
	for _, target := range platform.PackagingBlueprints() {
		if target.Release {
			out = append(out, target)
		}
	}
	return out
}

func artifactDigest(name string, kind platform.Kind, seed byte) []byte {
	return auroracrypto.PreHashLabel("aurora release artifact", []byte(name), []byte(kind), repeatedByte(seed, 32))
}

func updateTargetsContain(targets []UpdateTarget, name string) bool {
	for _, target := range targets {
		if target.ArtifactName == name {
			return true
		}
	}
	return false
}

func isHexCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (r *ReadinessReport) addFinding(finding string) {
	r.Findings = append(r.Findings, finding)
}

func repeatedByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
