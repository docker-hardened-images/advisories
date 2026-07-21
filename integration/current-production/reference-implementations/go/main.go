package main

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
)

type attestation struct {
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
}

type scanResult struct {
	ImageRef     string
	IsDHI        bool
	ChainIDLabel string
	ChainIDIndex int
	IsDerived    bool
	SBOMType     string
	VEXType      string
}

func main() {
	var imageRef string
	var timeout time.Duration

	flag.StringVar(&imageRef, "image", "", "OCI image reference (tag@digest recommended)")
	flag.DurationVar(&timeout, "timeout", 45*time.Second, "Registry timeout")
	flag.Parse()

	if imageRef == "" {
		if flag.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "usage: dhi-scanner-go --image <image-ref>")
			os.Exit(1)
		}
		imageRef = flag.Arg(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		fail("parse image reference", err)
	}

	desc, err := remote.Get(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		fail("resolve image descriptor", err)
	}

	subjectRef, err := name.NewDigest(fmt.Sprintf("%s@%s", ref.Context().Name(), desc.Digest.String()))
	if err != nil {
		fail("create digest reference", err)
	}

	img, attestationSubject, err := imageFromDescriptor(ctx, subjectRef, desc.MediaType)
	if err != nil {
		fail("fetch image", err)
	}

	osRelease, err := readFileFromLayers(img, "/etc/os-release")
	isDHI := err == nil && strings.Contains(osRelease, "Docker Hardened Images")

	configFile, err := img.ConfigFile()
	if err != nil {
		fail("read image config", err)
	}

	chainIDLabel := ""
	if configFile.Config.Labels != nil {
		chainIDLabel = configFile.Config.Labels["com.docker.dhi.chain-id"]
	}

	chainIDs := computeChainIDs(configFile.RootFS.DiffIDs)
	chainIndex := findChainIDIndex(chainIDs, chainIDLabel)
	isDerived := chainIndex >= 0 && chainIndex < len(chainIDs)-1

	attestations, err := fetchAttestations(ctx, attestationSubject)
	if err != nil {
		fail("fetch referrer attestations", err)
	}

	sbomType := findPredicateType(attestations, []string{"spdx", "cyclonedx"})
	vexType := findPredicateType(attestations, []string{"openvex", "vex"})

	result := scanResult{
		ImageRef:     imageRef,
		IsDHI:        isDHI,
		ChainIDLabel: chainIDLabel,
		ChainIDIndex: chainIndex,
		IsDerived:    isDerived,
		SBOMType:     sbomType,
		VEXType:      vexType,
	}

	printResult(result)
}

func fail(action string, err error) {
	fmt.Fprintf(os.Stderr, "error: %s: %v\n", action, err)
	os.Exit(1)
}

func printResult(result scanResult) {
	fmt.Printf("Image: %s\n", result.ImageRef)
	fmt.Printf("DHI: %t\n", result.IsDHI)

	if result.ChainIDLabel != "" {
		fmt.Printf("chainID label: %s\n", result.ChainIDLabel)
		if result.ChainIDIndex >= 0 {
			fmt.Printf("chainID layer index: %d\n", result.ChainIDIndex)
		} else {
			fmt.Printf("chainID layer index: not found in layer chain\n")
		}
		fmt.Printf("Derived: %t\n", result.IsDerived)
	} else {
		fmt.Printf("chainID label: not present\n")
	}

	if result.SBOMType != "" {
		fmt.Printf("SBOM attestation: %s\n", result.SBOMType)
	} else {
		fmt.Printf("SBOM attestation: not found\n")
	}

	if result.VEXType != "" {
		fmt.Printf("VEX attestation: %s\n", result.VEXType)
	} else {
		fmt.Printf("VEX attestation: not found\n")
	}
}

func computeChainIDs(diffIDs []v1.Hash) []digest.Digest {
	if len(diffIDs) == 0 {
		return nil
	}

	chainIDs := make([]digest.Digest, len(diffIDs))
	for i, diffID := range diffIDs {
		chainIDs[i] = digest.Digest(diffID.String())
	}

	identity.ChainIDs(chainIDs)
	return chainIDs
}

func findChainIDIndex(chainIDs []digest.Digest, target string) int {
	if target == "" {
		return -1
	}

	for i, chainID := range chainIDs {
		if chainID.String() == target {
			return i
		}
	}

	return -1
}

func readFileFromLayers(img v1.Image, filePath string) (string, error) {
	normalized := strings.TrimPrefix(path.Clean(filePath), "/")
	layers, err := img.Layers()
	if err != nil {
		return "", err
	}

	for i := len(layers) - 1; i >= 0; i-- {
		layer := layers[i]
		rc, err := layer.Uncompressed()
		if err != nil {
			continue
		}

		content, found, err := readFileFromTar(rc, normalized)
		_ = rc.Close()

		if err != nil {
			continue
		}
		if found {
			return content, nil
		}
	}

	return "", errors.New("file not found in layers")
}

func readFileFromTar(reader io.Reader, target string) (string, bool, error) {
	tr := tar.NewReader(reader)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}

		name := strings.TrimPrefix(hdr.Name, "./")
		if path.Clean(name) != target {
			continue
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return "", false, err
		}
		return string(data), true, nil
	}
}

func imageFromDescriptor(ctx context.Context, subject name.Digest, mediaType types.MediaType) (v1.Image, name.Digest, error) {
	if mediaType.IsImage() {
		img, err := remote.Image(subject, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		return img, subject, err
	}
	if mediaType.IsIndex() {
		index, err := remote.Index(subject, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return nil, name.Digest{}, err
		}
		manifest, err := index.IndexManifest()
		if err != nil {
			return nil, name.Digest{}, err
		}
		selected, err := selectManifestForHostPlatform(manifest.Manifests)
		if err != nil {
			return nil, name.Digest{}, err
		}
		childRef, err := name.NewDigest(fmt.Sprintf("%s@%s", subject.Context().Name(), selected.Digest.String()))
		if err != nil {
			return nil, name.Digest{}, err
		}
		img, err := remote.Image(childRef, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		return img, childRef, err
	}

	return nil, name.Digest{}, fmt.Errorf("unsupported media type: %s", mediaType)
}

func fetchAttestations(ctx context.Context, subject name.Digest) ([]attestation, error) {
	index, err := remote.Referrers(subject, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}

	var attestations []attestation
	for _, desc := range manifest.Manifests {
		ref, err := name.NewDigest(fmt.Sprintf("%s@%s", subject.Context().Name(), desc.Digest.String()))
		if err != nil {
			continue
		}

		img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			continue
		}

		layers, err := img.Layers()
		if err != nil || len(layers) == 0 {
			continue
		}

		rc, err := layers[0].Uncompressed()
		if err != nil {
			continue
		}

		payload, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			continue
		}

		att, err := parseAttestation(payload)
		if err != nil {
			continue
		}

		attestations = append(attestations, att)
	}

	return attestations, nil
}

func parseAttestation(payload []byte) (attestation, error) {
	var att attestation
	if err := json.Unmarshal(payload, &att); err == nil && att.PredicateType != "" {
		return att, nil
	}

	var env dsseEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return attestation{}, err
	}
	if env.Payload == "" {
		return attestation{}, errors.New("missing attestation payload")
	}

	decoded, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return attestation{}, err
	}

	if err := json.Unmarshal(decoded, &att); err != nil {
		return attestation{}, err
	}
	if att.PredicateType == "" {
		return attestation{}, errors.New("missing predicateType")
	}

	return att, nil
}

func findPredicateType(attestations []attestation, hints []string) string {
	for _, att := range attestations {
		predicate := strings.ToLower(att.PredicateType)
		for _, hint := range hints {
			if strings.Contains(predicate, hint) {
				return att.PredicateType
			}
		}
	}

	return ""
}

func selectManifestForHostPlatform(manifests []v1.Descriptor) (v1.Descriptor, error) {
	if len(manifests) == 0 {
		return v1.Descriptor{}, errors.New("image index has no manifests")
	}

	target := &v1.Platform{
		OS:           "linux",
		Architecture: runtime.GOARCH,
	}

	for _, manifest := range manifests {
		if manifest.Platform == nil {
			continue
		}
		if matchesPlatform(manifest.Platform, target) {
			return manifest, nil
		}
	}

	return v1.Descriptor{}, fmt.Errorf("no manifest found for host platform %s/%s", target.OS, target.Architecture)
}

func matchesPlatform(candidate, target *v1.Platform) bool {
	if candidate == nil || target == nil {
		return false
	}
	if !strings.EqualFold(candidate.OS, target.OS) {
		return false
	}
	if !strings.EqualFold(candidate.Architecture, target.Architecture) {
		return false
	}
	if target.Variant != "" && !strings.EqualFold(candidate.Variant, target.Variant) {
		return false
	}
	return true
}
