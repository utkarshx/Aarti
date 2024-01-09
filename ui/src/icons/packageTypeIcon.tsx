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

import { RepositoryType } from '../api/repository'
import { AlpineIcon } from './AlpineIcon'
import { DebianIcon } from './DebianIcon'
import { HelmIcon } from './HelmIcon'
import { RedHatIcon } from './RedHatIcon'

export const packageTypeIcon = (type: RepositoryType) => {
  switch (type) {
    case RepositoryType.DEB:
      return <DebianIcon />
    case RepositoryType.APK:
      return <AlpineIcon />
    case RepositoryType.RPM:
      return <RedHatIcon />
    case RepositoryType.HELM:
      return <HelmIcon />
  }
}
