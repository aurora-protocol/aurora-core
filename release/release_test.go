package release

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/platform"
)

func TestReleaseReadinessHarnessCoversProductionGates(t *testing.T) {
	report, err := RunReleaseReadinessHarness(200)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("release readiness failed: %+v", report)
	}
	for name, passed := range map[string]bool{
		"artifact_signatures":    report.ArtifactSignatures,
		"provenance":             report.Provenance,
		"reproducible_builds":    report.ReproducibleBuilds,
		"signed_update_pipeline": report.SignedUpdatePipeline,
		"device_provisioning":    report.DeviceProvisioning,
		"incident_response_plan": report.IncidentResponsePlan,
	} {
		if !passed {
			t.Fatalf("%s gate was not covered: %+v", name, report)
		}
	}
	if report.ReleaseArtifacts != 6 || report.UpdateRoles != 4 || len(report.Findings) != 0 {
		t.Fatalf("unexpected release readiness counts/findings: %+v", report)
	}
}

func TestVerifyReleaseReadinessRejectsUnsignedArtifact(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Artifacts[0].Signatures = nil
	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("unsigned release artifact passed: %+v", report)
	}
	if !hasFinding(report, "release artifact missing valid signature") {
		t.Fatalf("report missing signature finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsSignatureKeyIDMismatch(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Artifacts[0].Signatures[0].KeyID = fill(0xff, 16)
	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("artifact signature with mismatched key id passed: %+v", report)
	}
	if !hasFinding(report, "release artifact missing valid signature") {
		t.Fatalf("report missing signature finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsNonReproducibleArtifact(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Artifacts[0].RebuildDigest[0] ^= 0x80
	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("non-reproducible release artifact passed: %+v", report)
	}
	if !hasFinding(report, "release artifact rebuild digest mismatch") {
		t.Fatalf("report missing reproducibility finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRequiresPlatformProvisioning(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	bundle.DeviceProvisioning = nil
	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("release without device provisioning passed: %+v", report)
	}
	if !hasFinding(report, "device provisioning evidence missing for apple-release") {
		t.Fatalf("report missing device provisioning finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsExpiredUpdateRole(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	for i := range bundle.UpdatePipeline.Roles {
		if bundle.UpdatePipeline.Roles[i].Name == RoleTimestamp {
			bundle.UpdatePipeline.Roles[i].ExpiresUnix = 199
		}
	}
	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("expired update role passed: %+v", report)
	}
	if !hasFinding(report, "signed update role timestamp expired") {
		t.Fatalf("report missing expired role finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsWrongRootUpdatePayload(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newSigner()
	if err != nil {
		t.Fatal(err)
	}
	for i := range bundle.UpdatePipeline.Roles {
		if bundle.UpdatePipeline.Roles[i].Name != RoleRoot {
			continue
		}
		bundle.UpdatePipeline.Roles[i].PayloadDigest = roleLinkPayloadDigest(RoleRoot, fill(0xee, 48))
		input, err := updateRoleSignatureInput(bundle.UpdatePipeline.Roles[i])
		if err != nil {
			t.Fatal(err)
		}
		signature, err := signer.sign(input)
		if err != nil {
			t.Fatal(err)
		}
		bundle.UpdatePipeline.Roles[i].Signatures = []SignatureRecord{signature}
	}
	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("wrong root update payload passed: %+v", report)
	}
	if !hasFinding(report, "signed update root payload digest mismatch") {
		t.Fatalf("report missing root payload finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsMissingReleaseTarget(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	var artifacts []Artifact
	for _, artifact := range bundle.Artifacts {
		if artifact.Platform == platform.KindOpenWrt {
			continue
		}
		artifacts = append(artifacts, artifact)
	}
	bundle.Artifacts = artifacts
	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("release missing OpenWrt artifact passed: %+v", report)
	}
	if !hasFinding(report, "release artifact missing for openwrt-release") {
		t.Fatalf("report missing release target finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsDuplicateArtifactName(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Artifacts = append(bundle.Artifacts, bundle.Artifacts[0])

	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("release with duplicate artifact name passed: %+v", report)
	}
	if !hasFinding(report, "release artifact names are duplicated") {
		t.Fatalf("report missing duplicate artifact finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsDuplicateUpdateRole(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	bundle.UpdatePipeline.Roles = append(bundle.UpdatePipeline.Roles, bundle.UpdatePipeline.Roles[0])

	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("release with duplicate update role passed: %+v", report)
	}
	if !hasFinding(report, "signed update role names are duplicated") {
		t.Fatalf("report missing duplicate role finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsDuplicateUpdateTarget(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	bundle.UpdatePipeline.Targets = append(bundle.UpdatePipeline.Targets, bundle.UpdatePipeline.Targets[0])
	resignUpdatePipeline(t, &bundle.UpdatePipeline)

	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("release with duplicate update target passed: %+v", report)
	}
	if !hasFinding(report, "signed update target names are duplicated") {
		t.Fatalf("report missing duplicate target finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsDuplicateDeviceProvisioningEvidence(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	bundle.DeviceProvisioning = append(bundle.DeviceProvisioning, bundle.DeviceProvisioning[0])

	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("release with duplicate device provisioning evidence passed: %+v", report)
	}
	if !hasFinding(report, "device provisioning evidence names are duplicated") {
		t.Fatalf("report missing duplicate device provisioning finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsUnknownDeviceProvisioningEvidence(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	bundle.DeviceProvisioning = append(bundle.DeviceProvisioning, DeviceProvisioningEvidence{
		TargetName: "unknown-release",
		Platform:   platform.KindLinux,
	})

	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("release with unknown device provisioning evidence passed: %+v", report)
	}
	if !hasFinding(report, "device provisioning evidence target is unknown") {
		t.Fatalf("report missing unknown device provisioning finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsUnknownArtifact(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	artifact := bundle.Artifacts[0]
	artifact.Name = "unknown-release"
	artifact.Provenance.SubjectName = artifact.Name
	resignArtifact(t, &artifact)
	bundle.Artifacts = append(bundle.Artifacts, artifact)
	bundle.UpdatePipeline, err = signedUpdatePipeline(bundle.Artifacts, bundle.NowUnix)
	if err != nil {
		t.Fatal(err)
	}

	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("release with unknown artifact passed: %+v", report)
	}
	if !hasFinding(report, "release artifact target is unknown") {
		t.Fatalf("report missing unknown artifact finding: %+v", report.Findings)
	}
}

func TestVerifyReleaseReadinessRejectsUnknownUpdateRole(t *testing.T) {
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatal(err)
	}
	role := bundle.UpdatePipeline.Roles[0]
	role.Name = "unknown"
	resignUpdateRole(t, &role)
	bundle.UpdatePipeline.Roles = append(bundle.UpdatePipeline.Roles, role)

	report, err := VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("release with unknown update role passed: %+v", report)
	}
	if !hasFinding(report, "signed update role is unknown") {
		t.Fatalf("report missing unknown update role finding: %+v", report.Findings)
	}
}

func resignArtifact(t *testing.T, artifact *Artifact) {
	t.Helper()
	input, err := artifactSignatureInput(*artifact)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newSigner()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.sign(input)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Signatures = []SignatureRecord{signature}
}

func resignUpdatePipeline(t *testing.T, pipeline *SignedUpdatePipeline) {
	t.Helper()
	targetDigest, err := updateTargetsPayloadDigest(pipeline.Targets)
	if err != nil {
		t.Fatal(err)
	}
	for index := range pipeline.Roles {
		role := &pipeline.Roles[index]
		switch role.Name {
		case RoleRoot:
			role.PayloadDigest = roleLinkPayloadDigest(RoleRoot, targetDigest)
		case RoleTargets:
			role.PayloadDigest = append(role.PayloadDigest[:0], targetDigest...)
		case RoleSnapshot:
			role.PayloadDigest = roleLinkPayloadDigest(RoleSnapshot, targetDigest)
		case RoleTimestamp:
			role.PayloadDigest = roleLinkPayloadDigest(RoleTimestamp, roleLinkPayloadDigest(RoleSnapshot, targetDigest))
		}
		resignUpdateRole(t, role)
	}
}

func resignUpdateRole(t *testing.T, role *UpdateRole) {
	t.Helper()
	signer, err := newSigner()
	if err != nil {
		t.Fatal(err)
	}
	input, err := updateRoleSignatureInput(*role)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.sign(input)
	if err != nil {
		t.Fatal(err)
	}
	role.Signatures = []SignatureRecord{signature}
}

func hasFinding(report ReadinessReport, want string) bool {
	for _, finding := range report.Findings {
		if finding == want {
			return true
		}
	}
	return false
}

func fill(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
