// Copyright 2023 Linka Cloud  All rights reserved.
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

package registry

import (
	"context"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
)

type ManifestStore = registry.ManifestStore

type ManifestProxy interface {
	registry.ReferenceFetcher
	content.Fetcher
}

type manifests struct {
	ManifestStore
	p ManifestProxy
}

func (m *manifests) Fetch(ctx context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
	return m.maybeProxy().Fetch(ctx, target)
}

func (m *manifests) FetchReference(ctx context.Context, reference string) (ocispec.Descriptor, io.ReadCloser, error) {
	return m.maybeProxy().FetchReference(ctx, reference)
}

func (m *manifests) maybeProxy() ManifestProxy {
	if m.p != nil {
		return m.p
	}
	return m.ManifestStore
}
