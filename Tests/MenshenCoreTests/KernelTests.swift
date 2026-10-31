import Testing

/// Every suite that runs sandboxed processes is nested in here, so they run one at a time.
/// A burst of sandbox reports from one test (a learn run reports every operation) makes the
/// kernel or log system drop other processes' reports, with no notice in the stream: under a
/// sustained flood the enforce integration test failed 5 of 5 runs, without it 5 of 5 passed
/// (finding 26). The other suites still run in parallel.
@Suite(.serialized) enum KernelTests {}
