// Copyright 2022 Linka Cloud  All rights reserved.
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

import { HomeOutlined } from '@mui/icons-material'
import React from 'react'
import HomePage from '../Components/Home/HomePage'
import { MainRoutesRegistry } from '../routes'

MainRoutesRegistry['home'] = {
  path: '/',
  component: <HomePage />,
  icon: <HomeOutlined />,
  priority: 100,
  public: false,
  label: 'Home',
  show: true,
  navigate: () => '/',
}
