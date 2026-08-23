package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scan history: the difference between a viewer and a console.
//
// Without this, every question a security engineer actually asks is
// unanswerable. When did this first appear. Was it clean last week. What
// changed in v2. Which of my models have a critical pickle. All of them need
// yesterday's result to still exist, and throwing it away is why the interface
// could only ever answer "what does this file contain, right now".
//
// The storage is deliberately dull: one JSON file per scan under a directory,
// named by artifact digest and time. No database, because an air-gapped
// deployment should not need one and because a directory of JSON can be read,
// diffed and archived with tools the enclave already has when this program is
// unavailable.
//
// What is stored is the *summary*, not the whole artifact description. A
// history that kept every tensor name would grow without bound and answer no
// question the summary cannot. The bill of materials is regenerable from the
// artifact at any time; the fact that a finding was present on a Tuesday is not.

// ScanRecord is one scan, kept.
type ScanRecord struct {
	ID string `json:"id"`
	// Target is the path as the operator gave it, which is what they will
	// recognise in a list.
	Target string `json:"target"`
	// ModelName is what the artifact called itself.
	ModelName string `json:"modelName,omitempty"`
	Format    string `json:"format,omitempty"`
	// Digest pins the bytes. Two scans of the same digest are the same
	// artifact, whatever the path said, and that is what makes "has this
	// changed" answerable.
	Digest string `json:"digest,omitempty"`

	ScannedAt string `json:"scannedAt"`
	Verdict   string `json:"verdict,omitempty"`
	RiskScore int32  `json:"riskScore"`
	Worst     string `json:"worst,omitempty"`

	Findings []FindingRecord `json:"findings"`
	Counts   map[string]int  `json:"counts"`
	// Truncated records that the walk did not finish, because a clean history
	// entry over a partial walk is not a clean artifact and the distinction
	// has to survive into the record.
	Truncated bool `json:"truncated,omitempty"`

	// Hardened marks this artifact as a derivative this server produced.
	//
	// Set only by the hardening endpoint, never from anything read off disk.
	// That is the whole point: a directory can contain a file claiming to be a
	// hardening record, and treating that claim as fact would let anyone launder
	// an untouched model into a trusted one by writing a JSON file next to it.
	// This flag is the server's own memory of having done the work.
	Hardened bool `json:"hardened,omitempty"`
	// DerivedFrom is the digest of the artifact this was hardened from. Digest
	// rather than path, because paths move and the lineage has to survive it.
	DerivedFrom string `json:"derivedFrom,omitempty"`
	// DerivedFromTarget is the source as the operator named it, kept only so a
	// human sees something recognisable; the digest is what is authoritative.
	DerivedFromTarget string `json:"derivedFromTarget,omitempty"`
}

// FindingRecord is a finding as history keeps it: enough to search, group and
// diff, without the full description bloating every record.
type FindingRecord struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Category string `json:"category,omitempty"`
	Location string `json:"location,omitempty"`
	CWE      string `json:"cwe,omitempty"`
	ATLAS    string `json:"atlas,omitempty"`
}

// Key identifies a finding for diffing. Location is included because the same
// weakness in two files is two findings to fix.
func (f FindingRecord) Key() string { return f.ID + "\x00" + f.Location }

// Asset is one artifact as the inventory sees it: its latest state, plus when
// it was first and last seen.
//
// This is the view a security engineer opens the tool expecting, and it exists
// only because history does.
type Asset struct {
	Digest    string `json:"digest"`
	Target    string `json:"target"`
	ModelName string `json:"modelName,omitempty"`
	Format    string `json:"format,omitempty"`
	Verdict   string `json:"verdict,omitempty"`
	RiskScore int32  `json:"riskScore"`
	Worst     string `json:"worst,omitempty"`
	// FirstSeen is when this digest was first scanned — the question every
	// triage conversation starts with.
	FirstSeen string         `json:"firstSeen"`
	LastSeen  string         `json:"lastSeen"`
	ScanCount int            `json:"scanCount"`
	Counts    map[string]int `json:"counts"`

	// Hardened and DerivedFrom carry the derivation into the inventory, which is
	// where the question "what is this and where did it come from" is actually
	// asked.
	Hardened          bool   `json:"hardened,omitempty"`
	DerivedFrom       string `json:"derivedFrom,omitempty"`
	DerivedFromTarget string `json:"derivedFromTarget,omitempty"`
}

// Diff is what changed between two scans of the same artifact.
type Diff struct {
	From      string          `json:"from"`
	To        string          `json:"to"`
	Added     []FindingRecord `json:"added"`
	Removed   []FindingRecord `json:"removed"`
	Unchanged int             `json:"unchanged"`
}

// History stores scan records on disk.
type History struct {
	dir string
	mu  sync.RWMutex
}

// OpenHistory prepares a directory for scan records. A nil History is valid and
// simply keeps nothing, which is what happens without --config.
func OpenHistory(dir string) (*History, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("scan history directory: %w", err)
	}
	return &History{dir: dir}, nil
}

// Dir is where records are kept, so the interface can say what to back up.
func (h *History) Dir() string {
	if h == nil {
		return ""
	}
	return h.dir
}

// Record persists one scan.
func (h *History) Record(rec ScanRecord) (ScanRecord, error) {
	if h == nil {
		return rec, nil
	}
	if rec.ScannedAt == "" {
		rec.ScannedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if rec.ID == "" {
		rec.ID = scanID(rec)
	}
	if rec.Counts == nil {
		rec.Counts = countBySeverity(rec.Findings)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// A second scan of the same target within the same second derives the same
	// id, and the rename below would silently replace the earlier record. That
	// is how a hardening record disappeared: applying a plan and then viewing
	// the copy happen well inside one second, so the ordinary scan overwrote the
	// one carrying the derivation. History that quietly drops entries is worse
	// than none, because it still looks complete.
	//
	// Settled here, before marshalling, so a record's id field and its filename
	// cannot disagree — Compare looks scans up by the id it read out of the
	// file, and a mismatch would make a stored scan unaddressable.
	base := rec.ID
	for i := 1; i < 1000; i++ {
		if _, err := os.Stat(filepath.Join(h.dir, rec.ID+".json")); os.IsNotExist(err) {
			break
		}
		rec.ID = base + "-" + strconv.Itoa(i)
	}

	data, err := json.MarshalIndent(&rec, "", "  ")
	if err != nil {
		return rec, err
	}
	data = append(data, '\n')

	// Written to a temporary file and renamed, so a reader never sees a
	// half-written record. A truncated JSON file in a history directory would
	// break every listing that followed it.
	tmp, err := os.CreateTemp(h.dir, ".scan-*")
	if err != nil {
		return rec, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return rec, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return rec, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return rec, err
	}
	if err := tmp.Close(); err != nil {
		return rec, err
	}
	return rec, os.Rename(tmp.Name(), filepath.Join(h.dir, rec.ID+".json"))
}

// Scans returns every record, newest first.
func (h *History) Scans() []ScanRecord {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()

	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return nil
	}
	out := make([]ScanRecord, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.dir, e.Name()))
		if err != nil {
			continue
		}
		var rec ScanRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			// A corrupt record is skipped rather than fatal: one bad file must
			// not make the whole history unreadable.
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScannedAt > out[j].ScannedAt })
	return out
}

// Assets collapses history into one row per artifact — the inventory.
//
// Keyed by digest *and* location, which took a wrong turn first and is worth
// recording. Keying on digest alone seemed right: the same model moved to a new
// directory is the same artifact. But the scan covers the directory, not only
// the model file, so a byte-identical GGUF with a poisoned pickle beside it is a
// genuinely different risk from the same GGUF sitting alone. Merging them showed
// one row reading "Approved, risk 0" for a location that also held a Critical
// finding — the inventory actively lying about the estate.
//
// So: same bytes in two places are two things to manage, because they are. The
// digest still identifies the artifact for history and diffing; the pair
// identifies the deployment.
func (h *History) Assets() []Asset {
	scans := h.Scans()
	byDigest := map[string]*Asset{}
	for _, s := range scans {
		key := s.Digest + "\x00" + s.Target
		if s.Digest == "" {
			key = "path:" + s.Target
		}
		a, ok := byDigest[key]
		if !ok {
			// Scans arrive newest first, so the first one seen is the latest
			// state and every later one only moves FirstSeen backwards.
			byDigest[key] = &Asset{
				Digest: s.Digest, Target: s.Target, ModelName: s.ModelName,
				Format: s.Format, Verdict: s.Verdict, RiskScore: s.RiskScore,
				Worst: s.Worst, FirstSeen: s.ScannedAt, LastSeen: s.ScannedAt,
				ScanCount: 1, Counts: s.Counts,
				Hardened: s.Hardened, DerivedFrom: s.DerivedFrom,
				DerivedFromTarget: s.DerivedFromTarget,
			}
			continue
		}
		a.ScanCount++
		// The derivation was recorded once, by the scan taken immediately after
		// hardening. Every later scan of that copy is an ordinary scan carrying
		// none, so it is latched rather than overwritten — otherwise a model
		// would stop being hardened the moment somebody looked at it again.
		if s.Hardened && !a.Hardened {
			a.Hardened = true
			a.DerivedFrom = s.DerivedFrom
			a.DerivedFromTarget = s.DerivedFromTarget
		}
		if s.ScannedAt < a.FirstSeen {
			a.FirstSeen = s.ScannedAt
		}
		if s.ScannedAt > a.LastSeen {
			a.LastSeen = s.ScannedAt
		}
	}
	out := make([]Asset, 0, len(byDigest))
	for _, a := range byDigest {
		out = append(out, *a)
	}
	// Worst first: an inventory sorted alphabetically buries the thing that
	// needs attention, which is the only reason anyone opened it.
	sort.Slice(out, func(i, j int) bool {
		if out[i].RiskScore != out[j].RiskScore {
			return out[i].RiskScore > out[j].RiskScore
		}
		return out[i].LastSeen > out[j].LastSeen
	})
	return out
}

// Search returns findings across every scan, which is the query the per-model
// filter cannot answer: "which of my models has a critical pickle".
func (h *History) Search(q, severity string) []map[string]any {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []map[string]any
	for _, s := range h.Scans() {
		for _, f := range s.Findings {
			if severity != "" && !strings.EqualFold(f.Severity, severity) {
				continue
			}
			if q != "" {
				hay := strings.ToLower(f.ID + " " + f.Title + " " + f.Category + " " +
					f.Location + " " + f.CWE + " " + f.ATLAS + " " + s.ModelName + " " + s.Target)
				if !strings.Contains(hay, q) {
					continue
				}
			}
			out = append(out, map[string]any{
				"finding": f, "target": s.Target, "modelName": s.ModelName,
				"digest": s.Digest, "scannedAt": s.ScannedAt, "scanId": s.ID,
			})
		}
	}
	return out
}

// History returns every scan of one artifact, newest first.
func (h *History) For(digest string) []ScanRecord {
	var out []ScanRecord
	for _, s := range h.Scans() {
		if s.Digest == digest {
			out = append(out, s)
		}
	}
	return out
}

// Compare diffs two scans by id.
//
// This answers "what changed", which is the question that decides whether a new
// model version is safe to ship — and it is answerable only because both scans
// were kept.
func (h *History) Compare(fromID, toID string) (*Diff, error) {
	var from, to *ScanRecord
	for _, s := range h.Scans() {
		rec := s
		if s.ID == fromID {
			from = &rec
		}
		if s.ID == toID {
			to = &rec
		}
	}
	if from == nil || to == nil {
		return nil, fmt.Errorf("both scans must exist to compare them")
	}
	inFrom := map[string]FindingRecord{}
	for _, f := range from.Findings {
		inFrom[f.Key()] = f
	}
	d := &Diff{From: fromID, To: toID}
	for _, f := range to.Findings {
		if _, ok := inFrom[f.Key()]; ok {
			d.Unchanged++
			delete(inFrom, f.Key())
			continue
		}
		d.Added = append(d.Added, f)
	}
	for _, f := range inFrom {
		d.Removed = append(d.Removed, f)
	}
	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].ID < d.Added[j].ID })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].ID < d.Removed[j].ID })
	return d, nil
}

func countBySeverity(fs []FindingRecord) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Severity]++
	}
	return out
}

// scanID is derived from the artifact digest and the scan time, so it is stable
// and sorts usefully in a directory listing.
func scanID(rec ScanRecord) string {
	h := sha256.Sum256([]byte(rec.Digest + rec.Target + rec.ScannedAt))
	stamp := strings.NewReplacer("-", "", ":", "").Replace(rec.ScannedAt)
	return stamp + "-" + hex.EncodeToString(h[:4])
}

// Lineage is one artifact's place in a hardening chain.
type Lineage struct {
	Digest string `json:"digest"`
	Target string `json:"target,omitempty"`
	// Ancestors runs from the immediate source outwards, so the first entry is
	// what this was hardened from and the last is the original nobody derived.
	Ancestors []LineageNode `json:"ancestors,omitempty"`
	// Descendants are the copies hardened from this one, newest first.
	Descendants []LineageNode `json:"descendants,omitempty"`
}

// LineageNode is one artifact in a chain.
type LineageNode struct {
	Digest    string `json:"digest,omitempty"`
	Target    string `json:"target"`
	ModelName string `json:"modelName,omitempty"`
	Verdict   string `json:"verdict,omitempty"`
	RiskScore int32  `json:"riskScore"`
	Findings  int    `json:"findings"`
	Hardened  bool   `json:"hardened,omitempty"`
	// Missing marks a link the history knows was there but has no scan for —
	// the source was hardened, then its record was pruned or it was scanned on
	// another machine. Naming the gap beats silently ending the chain, which
	// would present a derivative as an original.
	Missing bool `json:"missing,omitempty"`
}

// LineageFor walks the derivation chain around one artifact.
//
// This is what turns a pile of scans into a picture: which model this came
// from, what it became, and how the risk moved along the way.
//
// Identified by digest **and** location, for a reason that is not obvious and
// that a digest-only version got wrong. Hardening usually removes a file
// *beside* the model — a pickle, a stray symlink — or edits a config, and none
// of that changes the model file's own bytes. The hardened copy therefore
// carries the same primary digest as the original it came from. Keyed on digest
// alone, the two are one artifact: the original inherits its copy's "hardened"
// label, and the chain points at itself.
//
// The digest is still what makes a link durable across a move; the pair is what
// makes the two ends of that link distinguishable.
func (h *History) LineageFor(digest, target string) Lineage {
	out := Lineage{Digest: digest, Target: target}
	if h == nil || digest == "" {
		return out
	}
	assets := h.Assets()

	key := func(digest, target string) string { return digest + "\x00" + target }
	byKey := map[string]Asset{}
	for _, a := range assets {
		if a.Digest == "" {
			continue
		}
		if _, seen := byKey[key(a.Digest, a.Target)]; !seen {
			byKey[key(a.Digest, a.Target)] = a
		}
	}

	node := func(a Asset) LineageNode {
		total := 0
		for _, n := range a.Counts {
			total += n
		}
		return LineageNode{
			Digest: a.Digest, Target: a.Target, ModelName: a.ModelName,
			Verdict: a.Verdict, RiskScore: a.RiskScore, Findings: total,
			Hardened: a.Hardened,
		}
	}

	// Upwards. Bounded by the number of known artifacts and guarded against a
	// cycle: a digest that somehow lists itself as an ancestor would otherwise
	// spin here forever, and this runs inside a request.
	seen := map[string]bool{key(digest, target): true}
	cur, ok := byKey[key(digest, target)]
	for ok && cur.Hardened && cur.DerivedFrom != "" {
		pk := key(cur.DerivedFrom, cur.DerivedFromTarget)
		if seen[pk] {
			break
		}
		seen[pk] = true
		parent, found := byKey[pk]
		if !found {
			out.Ancestors = append(out.Ancestors, LineageNode{
				Digest: cur.DerivedFrom, Target: cur.DerivedFromTarget, Missing: true,
			})
			break
		}
		out.Ancestors = append(out.Ancestors, node(parent))
		cur = parent
	}

	// Downwards, one level: everything hardened directly from this artifact.
	for _, a := range assets {
		if a.Hardened && a.DerivedFrom == digest && a.DerivedFromTarget == target {
			out.Descendants = append(out.Descendants, node(a))
		}
	}
	return out
}
