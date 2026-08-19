package app.factoryline.intellij

import java.nio.file.Files
import java.nio.file.attribute.FileTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class FactoryLineCoreTest {
    @Test
    fun firstProofIsZeroConfigurationAndMachineReadable() {
        assertEquals(listOf("doctor", "--json"), FactoryLineCommands.firstProof())
    }

    @Test
    fun workspaceAdvisorIsExplicitWorkspaceBoundAndWritesOnlyWhenRequested() {
        val root = Files.createTempDirectory("factoryline-workspace-advisor")
        val outDir = root.resolve(".factory/workspace-advice")

        assertEquals(
            listOf("workspace", "inspect", "--root", root.toString(), "--json"),
            FactoryLineCommands.workspaceAdvisor(root),
        )
        assertEquals(
            listOf("workspace", "inspect", "--root", root.toString(), "--out-dir", outDir.toString(), "--json"),
            FactoryLineCommands.workspaceAdvisor(root, outDir),
        )
    }

    @Test
    fun workspaceAdvisorParserAcceptsOnlyItsFixedSchemaAndKeepsTheDiagnosticBoundary() {
        val summary = WorkspaceAdvisorSummary.fromJson(
            """
                {
                  "schema":"factory.workspace_advisor.v1",
                  "workspace":{"name":"demo","path_classification":"wsl_unc","ecosystems":["node","python"]},
                  "scan":{"files_scanned":150,"bytes_scanned":4096,"scan_limited":false},
                  "recommendations":[{
                    "id":"remote_path_preflight","priority":"high","state":"review",
                    "action":"Verify shared paths.","boundary":"No remote connection."
                  }]
                }
            """.trimIndent(),
        )

        assertNotNull(summary)
        assertEquals("demo", summary.workspaceName)
        assertEquals("wsl_unc", summary.pathClassification)
        assertEquals(listOf("node", "python"), summary.ecosystems)
        assertEquals("false", summary.scanLimited)
        assertTrue(summary.brief().contains("not an IDE heap"))
        assertEquals("WORKSPACE_ADVISOR_CONFIRMATION_REQUIRED", WorkspaceAdvisorMarkers.CONFIRMATION_REQUIRED)
        assertEquals(null, WorkspaceAdvisorSummary.fromJson("{\"schema\":\"untrusted\"}"))
    }

    @Test
    fun proofReviewCommandsAreDirectAndCanFocusOneWorkspacePath() {
        val root = Files.createTempDirectory("factoryline-proof-review")

        assertEquals(
            listOf("change", "review", "--root", root.toString(), "--json"),
            FactoryLineCommands.proofReview(root),
        )
        assertEquals(
            listOf("change", "review", "--root", root.toString(), "--changed", "src/service.py", "--json"),
            FactoryLineCommands.proofReview(root, "src/service.py"),
        )
        val handoff = root.resolve(".factory/change-reviews")
        assertEquals(
            listOf("change", "review", "--root", root.toString(), "--out-dir", handoff.toString(), "--json"),
            FactoryLineCommands.proofReview(root, outDir = handoff),
        )
    }

    @Test
    fun repairSandboxCommandsAreDirectAndBindOnlyExplicitPaths() {
        val root = Files.createTempDirectory("factoryline-repair-sandbox")
        val outDir = root.resolve(".factory/repair-sandboxes")
        val scope = root.resolve(".factory/repair-sandboxes/repair-scope-abc.json")
        val patch = root.resolve("candidate.patch")

        assertEquals(
            listOf(
                "repair", "scope", "--root", root.toString(), "--change-list", "Checkout", "--changed", "src/service.py",
                "--changed", "src/ui.kt", "--out-dir", outDir.toString(), "--json",
            ),
            FactoryLineCommands.repairScope(root, "Checkout", listOf("src/service.py", "src/ui.kt"), outDir),
        )
        assertEquals(
            listOf(
                "repair", "candidate", "--root", root.toString(), "--scope", scope.toString(), "--patch", patch.toString(),
                "--out-dir", outDir.toString(), "--json",
            ),
            FactoryLineCommands.repairCandidate(root, scope, patch, outDir),
        )
    }

    @Test
    fun repairSandboxParsersAcceptOnlyStableScopeAndCandidateSchemas() {
        val scope = RepairScopeSummary.fromJson(
            """
                {
                  "schema":"factory.repair_scope.v1",
                  "scope_sha256":"scope-123",
                  "change_list":"Checkout",
                  "paths":[{"path":"src/service.py","exists":true}],
                  "context_budget":{"measured_bytes":128,"limit_bytes":262144,"decision":"within_budget"},
                  "review":{"review_sha256":"review-123","next_action":{"action":"rerun_stale_proof","reason":"Proof changed."}},
                  "verification":{"required_checks":[{"id":"scope_current"},{"id":"independent_verifier"}]},
                  "artifacts":{"paths":{"json":".factory/repair-sandboxes/scope.json","markdown":".factory/repair-sandboxes/scope.md","mermaid":".factory/repair-sandboxes/scope.mmd"}}
                }
            """.trimIndent(),
        )
        val candidate = RepairCandidateSummary.fromJson(
            """
                {
                  "schema":"factory.repair_candidate.v1",
                  "candidate_sha256":"candidate-123",
                  "scope_sha256":"scope-123",
                  "patch":{"path":"candidate.patch"},
                  "touched_paths":["src/service.py"],
                  "artifacts":{"paths":{"json":".factory/repair-sandboxes/candidate.json","markdown":".factory/repair-sandboxes/candidate.md"}}
                }
            """.trimIndent(),
        )

        assertNotNull(scope)
        assertEquals("Checkout", scope.changeList)
        assertEquals(listOf("src/service.py"), scope.paths)
        assertEquals(listOf("scope_current", "independent_verifier"), scope.requiredChecks)
        assertEquals("128", scope.contextMeasuredBytes)
        assertEquals("262144", scope.contextLimitBytes)
        assertEquals(3, scope.artifactPaths.size)
        assertTrue(scope.brief().contains("no candidate runner"))
        assertNotNull(candidate)
        assertEquals("candidate.patch", candidate.patchPath)
        assertEquals(listOf("src/service.py"), candidate.touchedPaths)
        assertEquals(2, candidate.artifactPaths.size)
        assertTrue(candidate.brief().contains("human IDE apply"))
        assertEquals(null, RepairScopeSummary.fromJson("{\"schema\":\"untrusted\"}"))
        assertEquals(null, RepairCandidateSummary.fromJson("{\"schema\":\"untrusted\"}"))
    }

    @Test
    fun proofReviewParserUsesOnlyKnownSchemaFieldsAndRanksAttentionFirst() {
        val raw = """
            {
              "schema": "factory.change_review.v1",
              "review_sha256": "abc123",
              "input_source": "explicit",
              "changed_paths": ["src/service.py", "src/ui.kt"],
              "next_action": {"action": "bind_changed_path_to_proof", "reason": "A path is unbound."},
              "findings": [
                {"severity": "info", "kind": "ready_for_human_review", "message": "No release claim."},
                {"severity": "blocking", "kind": "unmatched_changed_path", "message": "Bind the path."}
              ],
              "unproven_claims": ["No explicit proof-input edge is declared for src/service.py."],
              "artifacts": {"paths": {"json": ".factory/change-reviews/review.json", "markdown": ".factory/change-reviews/review.md", "mermaid": ".factory/change-reviews/review.mmd"}},
              "authority": {"execution": false}
            }
        """.trimIndent()

        val review = ProofReviewSummary.fromJson(raw)

        assertNotNull(review)
        assertEquals(listOf("src/service.py", "src/ui.kt"), review.changedPaths)
        assertEquals("bind_changed_path_to_proof", review.nextAction)
        assertEquals("blocking", review.orderedFindings.first().severity)
        assertEquals(3, review.handoffArtifactPaths.size)
        assertTrue(ProofReviewMarkers.EXPLICIT_SCOPE in review.markers)
        assertTrue(ProofReviewMarkers.HANDOFF_SAVED in review.markers)
        assertTrue(review.brief().contains("analysis only"))
    }

    @Test
    fun proofReviewRejectsUnknownSchemaAsUnavailable() {
        assertEquals(null, ProofReviewSummary.fromJson("{\"schema\":\"untrusted\"}"))
        val unavailable = ProofReviewUnavailable.from(
            CommandResult("Proof Review", emptyList(), 2, false, "{\"code\":\"DIFF_BASE_UNAVAILABLE\",\"message\":\"base missing\"}"),
        )
        assertTrue(ProofReviewMarkers.UNAVAILABLE in unavailable.markers)
        assertTrue(unavailable.message.contains("DIFF_BASE_UNAVAILABLE"))
    }

    @Test
    fun githubStarPromptRequiresACompletedCommandAndANewPluginVersion() {
        assertTrue(FactoryLineGitHubStarPrompt.shouldOffer(0, false, null, "0.8.2"))
        assertFalse(FactoryLineGitHubStarPrompt.shouldOffer(1, false, null, "0.8.2"))
        assertFalse(FactoryLineGitHubStarPrompt.shouldOffer(0, true, null, "0.8.2"))
        assertFalse(FactoryLineGitHubStarPrompt.shouldOffer(0, false, "0.8.2", "0.8.2"))
        assertTrue(FactoryLineGitHubStarPrompt.shouldOffer(0, false, "0.8.1", "0.8.2"))
    }

    @Test
    fun featureNamesAreBounded() {
        assertTrue(FeatureName.isValid("receipt-integrity_2"))
        assertFalse(FeatureName.isValid("receipt integrity"))
        assertFalse(FeatureName.isValid("../receipt"))
        assertFalse(FeatureName.isValid(""))
    }

    @Test
    fun studioUrlAcceptsOnlyLiteralLoopbackOutput() {
        assertEquals(
            "http://127.0.0.1:43117/",
            StudioUrl.find("marker: STUDIO_STARTED\nFactory Studio: http://127.0.0.1:43117/\n")
        )
        assertEquals(null, StudioUrl.find("Factory Studio: http://0.0.0.0:43117/"))
        assertEquals(null, StudioUrl.find("Factory Studio: https://example.com/"))
    }

    @Test
    fun studioRoutesPreserveTheLiteralLoopbackBoundary() {
        val base = "http://127.0.0.1:43117/"

        assertEquals("http://127.0.0.1:43117/graph-ops", StudioUrl.graphOps(base))
        assertEquals("http://127.0.0.1:43117/?mode=product", StudioUrl.productMissions(base))
        assertEquals(null, StudioUrl.graphOps("https://example.com/"))
        assertEquals(null, StudioUrl.productMissions("http://localhost:43117/"))
    }

    @Test
    fun receiptSummarySelectsKnownFieldsWithoutRenderingHtml() {
        val summary = ReceiptSummary.fromJson(
            Files.createTempFile("factoryline", ".json"),
            """{ "status": "passed", "feature": "<script>alert(1)</script>", "ignored": "value" }"""
        )

        assertEquals("passed", summary.fields["status"])
        assertEquals("<script>alert(1)</script>", summary.fields["feature"])
        assertFalse(summary.display.contains("<html", ignoreCase = true))
    }

    @Test
    fun meterSummarySeparatesMeasuredAndUnavailableValues() {
        val summary = MeterSummary.fromJson(
            """{ "stages_measured": 2, "build_wall_ms": 15, "tokens_reported_by_modules": false, "stages_successful": 2 }"""
        )

        assertEquals("2", summary.fields["stages_measured"])
        assertEquals("false", summary.fields["tokens_reported_by_modules"])
        assertTrue(summary.display.contains("Token totals are measured"))
    }

    @Test
    fun pairedSavingsCommandIsExplicitAndWorkspaceBound() {
        val root = Files.createTempDirectory("factoryline-savings")
        assertEquals(
            listOf("savings", "report", "--root", root.toString(), "--json"),
            FactoryLineCommands.savings(root)
        )
    }

    @Test
    fun receiptLocatorIgnoresDependencyTreesAndReturnsNewestReceipt() {
        val root = Files.createTempDirectory("factoryline-receipts")
        val receipts = Files.createDirectories(root.resolve("receipts"))
        val ignored = Files.createDirectories(receipts.resolve("node_modules"))
        val older = receipts.resolve("older.json")
        val newest = receipts.resolve("newest.json")
        Files.writeString(older, "{\"status\":\"old\"}")
        Files.writeString(ignored.resolve("ignored.json"), "{\"status\":\"ignored\"}")
        Files.writeString(newest, "{\"status\":\"passed\"}")
        Files.setLastModifiedTime(older, FileTime.fromMillis(1_000))
        Files.setLastModifiedTime(newest, FileTime.fromMillis(2_000))

        val found = ReceiptLocator.latest(root)

        assertNotNull(found)
        assertEquals(newest.fileName.toString(), found.fileName.toString())
    }

    @Test
    fun requirementEvidenceIsBoundedAndNavigable() {
        val root = Files.createTempDirectory("factoryline-requirements")
        val evidence = Files.createDirectories(root.resolve(".factory")).resolve("proof.json")
        Files.writeString(evidence, """{"requirement":"FR-101","status":"passed"}""")

        assertEquals(listOf("FR-101", "NFR-A11Y"), RequirementEvidenceLocator.ids("FR-101 and NFR-A11Y and FR-101"))
        val found = RequirementEvidenceLocator.first(root, "FR-101")
        assertNotNull(found)
        assertEquals(evidence, found.path)
        assertEquals(0, found.line)
    }

    @Test
    fun workspacePathsCannotEscapeTheProject() {
        val root = Files.createTempDirectory("factoryline-workspace")
        assertEquals(root.resolve("missions/one.json").normalize(), WorkspacePath.resolve(root, "missions/one.json"))
        assertEquals(null, WorkspacePath.resolve(root, "../outside.json"))
    }

    @Test
    fun commandOutputRedactsCommonCredentialShapes() {
        val redacted = OutputRedactor.redact("api_key=sk-secret123 Bearer abcdefghijk hf_secret123")
        assertFalse(redacted.contains("secret123"))
        assertFalse(redacted.contains("abcdefghijk"))
        assertTrue(redacted.contains("[REDACTED]"))
    }

    @Test
    fun jetbrainsRouterNeverAcceptsCredentialValues() {
        val root = Files.createTempDirectory("factoryline-router")
        val command = FactoryLineCommands.providerRoute(
            root.resolve("policy.json"), root.resolve("mission.json"), root, "high", "openai", "gpt-5"
        )
        assertTrue(command.containsAll(listOf("--ide", "jetbrains", "--risk", "high")))
        assertFalse(command.any { it.contains("api-key", ignoreCase = true) || it.contains("secret", ignoreCase = true) })
    }
}
