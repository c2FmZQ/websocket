// Copyright 2026 Robin Thellend <rthellend@rthellend.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build race

package websocket

func init() { raceEnabled = true }
