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

package auth

import (
	"context"
)

type Basic interface {
	BasicAuth() (username, password string, ok bool)
}

type key struct{}

func Context(ctx context.Context, a Basic) context.Context {
	return context.WithValue(ctx, key{}, a)
}

func FromContext(ctx context.Context) Basic {
	a, _ := ctx.Value(key{}).(Basic)
	return a
}
