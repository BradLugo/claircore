# ClairCore
[![Build Status](https://github.com/quay/claircore/actions/workflows/main.yml/badge.svg)](https://github.com/quay/claircore/actions/workflows/main.yml)
[![GoDoc](https://pkg.go.dev/badge/github.com/quay/claircore?status.svg)](https://pkg.go.dev/github.com/quay/claircore)
[![codecov](https://codecov.io/github/quay/claircore/coverage.svg?branch=main)](https://codecov.io/github/quay/claircore?branch=main)

A container security library from Red Hat's Quay and Advanced Cluster Security teams. 

For a full overview see: [ClairCore Book](https://quay.github.io/claircore)

ClairCore is a library that provides scanning container layers for installed packages
and reporting any discovered vulnerabilities.

## Getting Started

### Requirements

There some things claircore needs:
- Database
- A non-zero amount of disk space for temporarily storing image layers. You don't need much but enough to download the
images you plan to scan

### Basic components

ClairCore's main entire points are through `libindex`, a module that indexes containers and reports all packages for
layer, and `libvuln`, a module that matches packages with vulnerability data.

#### libindex


#### libvuln

```go
package main

import (
	"context"
	"net/http"
	"os"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/pkg/ctxlock"
)

func main() {
	ctx := context.Background()
	pool, _ := postgres.Connect(ctx, "connection string", "libindex-test")
	store, _ := postgres.InitPostgresIndexerStore(ctx, pool, true)

	ctxLocker, _ := ctxlock.New(ctx, pool)

	opts := &libindex.Options{
		Store:      store,
		Locker:     ctxLocker,
		FetchArena: libindex.NewRemoteFetchArena(http.DefaultClient, os.TempDir()),
		// see definition for more configuration options
	}
	
	lib, _ := libindex.New(ctx, opts, http.DefaultClient)
	m := &claircore.Manifest{}

	indexReport, _ := lib.Index(ctx, m)
}

```

## Development

### Local development and testing

The following targets start and stop a local development environment  
```
make local-dev-up
make local-dev-down
```

If you modify libvuln or libindex code the following make targets will restart the services with your changes  
```
make libindexhttp-restart
make libvulnhttp-restart
```

With the local development environment up the following make target runs all tests including integration  
```
make integration
```

The following make target runs unit tests which do not require a database or local development environment  
```
make unit
```
