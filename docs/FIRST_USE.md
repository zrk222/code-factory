# First Use On An Existing Repository

Code Factory is most useful when it meets code you already own. Start with one
small feature or risky workflow, not a whole migration.

```powershell
cd path\to\your-repository
pip install factoryline-code-factory==0.13.1 code-factory-1-spec==0.5.3 code-factory-2-forge==0.10.4
factory doctor --strict --json
factory init .
forge adopt <feature> --root .
```

`forge adopt` records a reviewable baseline rather than pretending the factory
generated the repository. Then choose the proof that matches your change:

```powershell
forge verify-tests <feature> --root .
factory trace <feature> --root .
factory verify-trace .factory/traces/<feature>.trace.json
```

For a policy that already controls release behavior, add a reviewed evaluator
manifest and prove its rules matter:

```powershell
factory verify-policy --root . --challenge policy.challenge.json
```

The command only certifies an evaluator after its baseline passes and every
deleted or inverted policy rule fails. See [Verify Policy](VERIFY_POLICY.md) for
the manifest format.

## Tell Us What Happened

The most useful contribution is a real first-run report: what command you ran,
where it helped, and where it made you stop. Open the [first external run
template](https://github.com/zrk222/code-factory/issues/new?template=first-external-run.yml).
Remove secrets, customer data, and private paths before posting.
