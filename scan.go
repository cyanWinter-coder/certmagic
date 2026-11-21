// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DefaultCertScanPageSize is the default number of site prefixes
// processed per page when scanning certificates in storage.
const DefaultCertScanPageSize = 256

// CertScanOptions configures ScanStoredCertificates.
type CertScanOptions struct {
	// PageSize is the maximum number of site prefixes processed per
	// page while scanning. Larger pages amortize the per-page context
	// checks at the cost of more transient memory. If less than 1,
	// DefaultCertScanPageSize is used.
	PageSize int

	// Logger is used to report entries that are skipped because they
	// are corrupt or otherwise unreadable. If nil, a default logger
	// is used.
	Logger *zap.Logger
}

// ScannedCertificate is a single certificate asset discovered by
// ScanStoredCertificates. The PEM and parsed certificate were read
// from storage as part of the scan's logical view: callers that need
// to re-read the entry should use these fields rather than loading
// the key from storage again, since a later read could observe a
// newer write that is not part of the scan's view.
type ScannedCertificate struct {
	// IssuerKey is the storage prefix of the issuer that produced
	// the certificate.
	IssuerKey string

	// SiteKey is the storage prefix of the site's assets.
	SiteKey string

	// CertKey is the storage key of the certificate (".crt") file.
	CertKey string

	// PEM is the raw content of CertKey as observed by the scan.
	PEM []byte

	// Certificate is the parsed leaf certificate from PEM.
	Certificate *x509.Certificate
}

// AssetKeys returns the storage keys of all assets related to this
// certificate: the certificate, its private key, and its metadata.
func (scanned ScannedCertificate) AssetKeys() []string {
	baseName := strings.TrimSuffix(scanned.CertKey, ".crt")
	return []string{scanned.CertKey, baseName + ".key", baseName + ".json"}
}

// ScanStoredCertificates walks the certificate assets in storage in a
// bounded, consistent manner, invoking yield for each certificate that
// was readable in the scan's logical view. It is intended for
// maintenance tasks that need to inspect every stored certificate
// (for example, cleaning up expired ones) while other instances
// concurrently write and delete assets in the same storage.
//
// The scan provides the following guarantees:
//
//   - Consistent view: the set of issuers is snapshotted when the scan
//     starts, and each entry's content is loaded exactly once and
//     carried in the ScannedCertificate, so every yielded entry can be
//     re-read from the same logical view. Entries created (or
//     recreated) after the scan started are excluded from the view
//     whenever the storage backend reports modification times.
//   - Pagination: site prefixes are visited in sorted order, one page
//     of opts.PageSize at a time, so page boundaries neither repeat
//     nor skip entries. If ctx is canceled, the scan stops promptly
//     and no further storage calls are made.
//   - Fault isolation: an entry that is corrupt (not a PEM-encoded,
//     parseable certificate) is logged with its storage key and
//     skipped; it does not fail the rest of the scan.
//   - Deletion safety: an entry that was concurrently deleted from
//     storage is silently skipped and never yielded, so maintenance
//     cannot act on it as if it were a valid certificate.
//   - Bounded memory: results are streamed to yield one entry at a
//     time and never accumulated; memory use is bounded by one
//     directory listing per issuer plus one page of site prefixes,
//     not by the total number of keys in storage.
//
// If yield returns an error, the scan stops and that error is
// returned. If ctx is canceled, the scan stops and ctx.Err() is
// returned.
func ScanStoredCertificates(ctx context.Context, storage Storage, opts CertScanOptions, yield func(ScannedCertificate) error) error {
	if opts.PageSize < 1 {
		opts.PageSize = DefaultCertScanPageSize
	}
	logger := opts.Logger
	if logger == nil {
		logger = defaultLogger
	}
	logger = logger.Named("cert_scan")

	// anchor the scan's logical view at this point in time; entries
	// created (or recreated) after this are not part of the view
	scanStart := time.Now()

	// snapshot the issuers up front; issuers created after the scan
	// starts are not part of this scan's logical view
	issuerKeys, err := storage.List(ctx, prefixCerts, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // no certificates in storage; nothing to scan
		}
		return fmt.Errorf("listing issuers in storage: %w", err)
	}
	sort.Strings(issuerKeys)

	for _, issuerKey := range issuerKeys {
		if err := ctx.Err(); err != nil {
			return err
		}

		// snapshot this issuer's site prefixes, then process them in
		// pages; sorting makes page boundaries deterministic, so no
		// site is visited twice or skipped (sites created after the
		// scan started are filtered out when each entry is read)
		siteKeys, err := storage.List(ctx, issuerKey, false)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // issuer was deleted concurrently with the scan
			}
			return fmt.Errorf("listing sites for issuer %s: %w", issuerKey, err)
		}
		sort.Strings(siteKeys)

		for pageStart := 0; pageStart < len(siteKeys); pageStart += opts.PageSize {
			if err := ctx.Err(); err != nil {
				return err
			}
			pageEnd := min(pageStart+opts.PageSize, len(siteKeys))
			for _, siteKey := range siteKeys[pageStart:pageEnd] {
				if err := ctx.Err(); err != nil {
					return err
				}
				err := scanSiteAssets(ctx, storage, logger, scanStart, issuerKey, siteKey, yield)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// scanSiteAssets yields each readable certificate asset stored under
// siteKey that belongs to the scan's logical view (i.e. that was not
// created or modified after scanStart). Corrupt or vanished assets
// are skipped without failing the scan.
func scanSiteAssets(ctx context.Context, storage Storage, logger *zap.Logger, scanStart time.Time, issuerKey, siteKey string, yield func(ScannedCertificate) error) error {
	assetKeys, err := storage.List(ctx, siteKey, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // site was deleted concurrently with the scan
		}
		// a broken listing for one site should not fail the whole scan
		logger.Error("unable to list site assets; skipping site",
			zap.String("site_key", siteKey),
			zap.Error(err))
		return nil
	}
	sort.Strings(assetKeys)

	for _, assetKey := range assetKeys {
		if path.Ext(assetKey) != ".crt" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		// exclude entries created (or recreated) after the scan
		// started, so they can't leak into this scan's logical view
		info, err := storage.Stat(ctx, assetKey)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // deleted concurrently with the scan
			}
			// without metadata we can't verify the entry belongs to
			// the scan's view, so conservatively skip it
			logger.Warn("unable to stat certificate asset; skipping entry",
				zap.String("cert_key", assetKey),
				zap.Error(err))
			continue
		}
		if !info.Modified.IsZero() && info.Modified.After(scanStart) {
			continue // created or modified after the scan started
		}

		certPEM, err := storage.Load(ctx, assetKey)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// deleted concurrently with the scan; it must not be
				// treated as a valid certificate by maintenance
				continue
			}
			logger.Error("unable to load certificate asset; skipping entry",
				zap.String("cert_key", assetKey),
				zap.Error(err))
			continue
		}

		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			logger.Warn("certificate file does not contain a PEM-encoded certificate; skipping entry",
				zap.String("cert_key", assetKey))
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Warn("certificate file is malformed; skipping entry",
				zap.String("cert_key", assetKey),
				zap.Error(err))
			continue
		}

		if err := yield(ScannedCertificate{
			IssuerKey:   issuerKey,
			SiteKey:     siteKey,
			CertKey:     assetKey,
			PEM:         certPEM,
			Certificate: cert,
		}); err != nil {
			return err
		}
	}

	return nil
}
