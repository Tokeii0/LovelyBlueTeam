// Lovely UDS Demo is an offline simulator; it has no network or host collector.
package main

import "os"

var logf = func(string, ...any) {} // No persistent argument or host logs.

func main() { os.Exit(runCLI(os.Args[1:])) }
