# FactoryLine 0.8.21 — paste-ready JetBrains forum update

Before an iOS build enters another App Review queue, the question is rarely
“does the app compile?” It is whether the selected build has the evidence that
review will actually need: a real restore path, complete iPad journeys,
authentic screenshots, accessible common tasks, accurate privacy/metadata,
reviewer access, and the user’s design intent still reflected in the result.

FactoryLine 0.8.21 adds an **AppForge Mission Control** tab inside JetBrains.
It reads local, hash-verified AppForge receipts and shows which candidate-bound
lanes exist or are missing: mission and user design input, storyboard, App
Review gate, strict quality audit, SaaS journey, and submission dossier. It is
designed to catch preventable rework before a team spends more days waiting for
the next review cycle.

It does not access credentials, upload a build or screenshots, start
TestFlight, submit to Apple, or promise approval. The developer keeps the
decision and the final authority.

The same release also lets Junie or GitHub Copilot work from a sealed local
FactoryLine mission and binds returned changes to Qodana or SonarQube SARIF and
optional E2E evidence. Use your preferred coding agent and analyzer—FactoryLine
independently decides whether their green result deserves trust.
