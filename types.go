package tessera

import (
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/coverage"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/model"
	"github.com/DAVANO-INNOVATION-LAB/tessera/internal/verify"
)

// The public vocabulary. These are aliases rather than copies, so a value read
// from the parser is the same value the caller holds — no conversion layer, no
// drift between an internal and an external shape. The implementation packages
// stay internal, which keeps parsers and emitters free to change without
// breaking importers, while this file is the surface that must stay stable.

type (
	// Artifact is the normalized description of one model.
	Artifact = model.Artifact

	// Identity is the model's self-declared name and provenance handles.
	Identity = model.Identity

	// License is one licence claim: the raw string the file carried, and the
	// SPDX identifier it resolved to.
	License = model.License

	// Lineage is the model's claimed ancestry — base models, sources, datasets.
	Lineage = model.Lineage

	// Reference is a named pointer to another artifact or dataset.
	Reference = model.Reference

	// Parameters is the model's shape and training description.
	Parameters = model.Parameters

	// IOSpec is one model input or output tensor's declared type.
	IOSpec = model.IOSpec

	// FileComponent is one physical file the model is made of, with its hash.
	FileComponent = model.FileComponent

	// Tensor is one weight tensor's shape, from the bounded inventory.
	Tensor = model.Tensor

	// Runtime is the load-time contract and its risk surface.
	Runtime = model.Runtime

	// Opset is one ONNX operator-set import.
	Opset = model.Opset

	// Finding is one security observation about the artifact.
	Finding = model.Finding

	// Format names the container a parser recognized.
	Format = model.Format

	// VerifyResult is the outcome of checking a document against an artifact.
	VerifyResult = verify.Result
	// VerifyCheck is one comparison between a documented claim and a measured
	// fact.
	VerifyCheck = verify.Check
	// VerifyOutcome is the result of a single check.
	VerifyOutcome = verify.Outcome

	// CoverageReport is how far an artifact goes toward a published
	// minimum-elements standard.
	CoverageReport = coverage.Report
	// CoverageElement is one row of such a standard.
	CoverageElement = coverage.Element
	// CoverageStatus is whether an element was supplied.
	CoverageStatus = coverage.Status
)

// Coverage statuses.
const (
	// CoveragePopulated means the artifact supplied the element.
	CoveragePopulated = coverage.Populated
	// CoverageAbsent means the element is derivable in principle but this
	// artifact did not disclose it.
	CoverageAbsent = coverage.Absent
	// CoverageOutOfScope means no static parse of a model file can supply it.
	// Kept distinct from absent because the remedy differs: one is a property
	// of the artifact, the other of the method.
	CoverageOutOfScope = coverage.OutOfScope
)

// Verification outcomes.
const (
	// VerifyPass means the document's claim matched the artifact.
	VerifyPass = verify.OutcomePass
	// VerifyFail means it did not.
	VerifyFail = verify.OutcomeFail
	// VerifyUncheckable means the document claimed something that cannot be
	// confirmed from the bytes. Reported rather than passed, because silence
	// would read as confirmation.
	VerifyUncheckable = verify.OutcomeUncheckable
	// VerifyExtra means the artifact has a component the document never
	// mentioned.
	VerifyExtra = verify.OutcomeExtra
)

// Recognized formats.
const (
	FormatGGUF        = model.FormatGGUF
	FormatSafetensors = model.FormatSafetensors
	FormatONNX        = model.FormatONNX
)

// Finding severities, in the vocabulary the findings use.
const (
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
)

// File roles, as set on FileComponent.Role.
const (
	RolePrimary      = model.RolePrimary
	RoleShard        = model.RoleShard
	RoleExternalData = model.RoleExternalData
)
