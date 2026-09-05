package main

import (
	"context"
	"os/exec"
)

// Обёртка над os/exec вынесена отдельно, чтобы переопределять в тестах.
var execCommandContext = exec.CommandContext

var _ = context.Background
