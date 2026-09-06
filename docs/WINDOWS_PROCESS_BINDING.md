# Windows process binding

The assembly runner starts Windows children suspended, assigns the process to
a kill-on-close Job Object, and resumes it only after assignment succeeds.
Resume uses `NtResumeProcess` against the retained process handle because
`subprocess.Popen` closes the primary thread handle. Job setup or resume
failure terminates the child and returns a non-success launch result.

This closes the bind-before-run race and makes cleanup evidence explicit. It is
process-tree hygiene, not a security sandbox: the runner does not claim to
contain a malicious process that escapes operating-system controls.
