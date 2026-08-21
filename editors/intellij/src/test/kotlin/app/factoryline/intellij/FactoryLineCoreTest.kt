package app.factoryline.intellij

import java.nio.file.Files
import java.nio.file.attribute.FileTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FactoryLineCoreTest {
    private fun pluginDescriptor(): String = requireNotNull(
        FactoryLineCoreTest::class.java.classLoader.getResourceAsStream("META-INF/plugin.xml")
    ) { "The packaged plugin descriptor must be available to plugin tests." }
        .bufferedReader()
        .use { it.readText() }

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
    fun indexContinuityCommandsRemainExplicitAndWorkspaceBound() {
        val root = Files.createTempDirectory("factoryline-index-continuity")
        val baseline = root.resolve(".factory/index-continuity/baseline.json")

        assertEquals(
            listOf("workspace", "continuity", "baseline", "--root", root.toString(), "--out", baseline.toString(), "--json"),
            FactoryLineCommands.indexContinuityBaseline(root, baseline),
        )
        assertEquals(
            listOf("workspace", "continuity", "compare", "--root", root.toString(), "--baseline", baseline.toString(), "--json"),
            FactoryLineCommands.indexContinuityCompare(root, baseline),
        )
    }

    @Test
    fun indexContinuityParserAcceptsOnlyVersionedLocalSchemas() {
        val summary = IndexContinuitySummary.fromJson(
            """
                {
                  "schema":"factory.index_continuity.v1",
                  "review_scope":"broad_reanalysis",
                  "recommendation":"Review changed manifests.",
                  "baseline":{"path":".factory/index-continuity/baseline.json"},
                  "changes":[{"kind":"structural_files","files":[{"path":"package.json"}]}]
                }
            """.trimIndent(),
        )

        assertNotNull(summary)
        assertEquals("broad_reanalysis", summary.reviewScope)
        assertEquals(listOf("structural_files"), summary.changes)
        assertTrue(summary.brief().contains("does not inspect or repair an IDE index"))
        assertEquals(null, IndexContinuitySummary.fromJson("{\"schema\":\"untrusted\"}"))
    }

    @Test
    fun ideHealthKeepsUnavailableSignalsHonestAndDoesNotAssignCause() {
        val sample = IdeHealthSample(
            capturedAtMs = 1L,
            heapUsedBytes = 128L * 1024L * 1024L,
            heapMaxBytes = 512L * 1024L * 1024L,
            processCpuPercent = null,
            systemCpuPercent = null,
            indexingActive = false,
            edtDelayMs = 10L,
        )

        assertEquals("unavailable", IdeHealthAssessment.cpu(null))
        assertEquals("128 MB / 512 MB", IdeHealthAssessment.heap(sample.heapUsedBytes, sample.heapMaxBytes))
        assertTrue(IdeHealthAssessment.reviewNote(sample).contains("unavailable"))
        assertTrue(IdeHealthMarkers.CORRELATION_NOT_CAUSATION.startsWith("IDE_HEALTH"))
    }

    @Test
    fun guardianRequiresLocalSamplesBeforeItReportsAnyState() {
        val assessment = FactoryLineGuardian.assess(emptyList())

        assertEquals(GuardianState.NO_DATA, assessment.state)
        assertEquals(0, assessment.sampleCount)
        assertEquals(listOf("no_data"), assessment.signals.map { it.id })
        assertTrue(assessment.overview().contains("does not infer an IDE state"))
    }

    @Test
    fun guardianReportsExactElevatedObservationsWithoutPluginOrCauseClaims() {
        val samples = listOf(
            IdeHealthSample(1L, 100L, 1_000L, 20.0, null, false, 20L),
            IdeHealthSample(2L, 900L, 1_000L, 90.0, null, true, 300L),
        )

        val assessment = FactoryLineGuardian.assess(samples)

        assertEquals(GuardianState.ATTENTION, assessment.state)
        assertEquals(3, assessment.elevatedSignalCount)
        assertEquals(1, assessment.indexingActiveCount)
        assertEquals(listOf("edt_delay", "process_cpu", "heap", "indexing"), assessment.signals.map { it.id })
        assertTrue(assessment.timeline.any { it.detail.contains("EDT dispatch delay reached 300 ms") })
        assertTrue(assessment.timeline.any { it.detail.contains("Indexing became active") })
        assertTrue(assessment.overview().contains("does not identify a root cause"))
        assertFalse(assessment.overview().contains("plugin caused", ignoreCase = true))
    }

    @Test
    fun guardianTreatsIndexingAndUnavailableCpuAsObservationsOnly() {
        val samples = listOf(
            IdeHealthSample(1L, 100L, 1_000L, null, null, false, 10L),
            IdeHealthSample(2L, 100L, 1_000L, null, null, true, 10L),
        )

        val assessment = FactoryLineGuardian.assess(samples)

        assertEquals(GuardianState.OBSERVE, assessment.state)
        assertEquals(0, assessment.elevatedSignalCount)
        assertEquals(1, assessment.indexingActiveCount)
        assertEquals(listOf("indexing"), assessment.signals.map { it.id })
        assertFalse(assessment.signals.any { it.id == "process_cpu" })
        assertTrue(assessment.timelineBrief().contains("Indexing became active"))
    }

    @Test
    fun guardianKeepsOnlyExplicitNavigationRoutes() {
        assertEquals(
            listOf("IDE Health", "Index Continuity", "Proof Review", "Intent Ledger", "Engineering Judgment", "Workspace Advisor"),
            GuardianReviewRoutes.all,
        )
    }

    @Test
    fun pluginDescriptorRegistersGuardianAndCoreCompatibilityWithoutAnUpperBound() {
        val descriptor = pluginDescriptor()

        assertTrue(descriptor.contains("<id>app.factoryline</id>"))
        assertTrue(descriptor.contains("<name>FactoryLine AI Proof</name>"))
        assertTrue(descriptor.contains("<idea-version since-build=\"252\""))
        assertFalse(descriptor.contains("until-build="))
        assertTrue(descriptor.contains("<depends>com.intellij.modules.platform</depends>"))
        assertTrue(descriptor.contains("<depends>com.intellij.modules.vcs</depends>"))
        assertTrue(descriptor.contains("id=\"app.factoryline.intellij.openGuardian\""))
        assertTrue(descriptor.contains("class=\"app.factoryline.intellij.OpenGuardianAction\""))
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
    fun intentLedgerCommandsBindOnlyOneSelectedChangeListAndCarryTheConfirmationPhrase() {
        val root = Files.createTempDirectory("factoryline-intent-ledger")

        assertEquals(
            listOf(
                "intent", "capture", "--root", root.toString(), "--change-list", "Checkout",
                "--changed", "src/service.py", "--changed", "src/ui.kt",
                "--confirmed-by", "Ada", "--promise", "Cancel safely", "--non-goal", "No migration",
                "--failure-case", "Invoice after cancellation", "--confirmation", "CAPTURE Checkout", "--json",
            ),
            FactoryLineCommands.intentCapture(
                root, "Checkout", listOf("src/service.py", "src/ui.kt"), "Ada", "Cancel safely",
                "No migration", "Invoice after cancellation", "CAPTURE Checkout",
            ),
        )
        assertEquals(
            listOf(
                "intent", "inspect", "--root", root.toString(), "--change-list", "Checkout",
                "--changed", "src/service.py", "--changed", "src/ui.kt", "--json",
            ),
            FactoryLineCommands.intentInspect(root, "Checkout", listOf("src/service.py", "src/ui.kt")),
        )
    }

    @Test
    fun judgmentCommandsAreReadOnlyAndBindOnlyExplicitChangedPaths() {
        val root = Files.createTempDirectory("factoryline-judgment")

        assertEquals(
            listOf("judgment", "status", "--root", root.toString(), "--json"),
            FactoryLineCommands.judgmentStatus(root),
        )
        assertEquals(
            listOf(
                "judgment", "safety-case", "--root", root.toString(),
                "--changed", "src/service.py", "--changed", "src/ui.kt", "--json",
            ),
            FactoryLineCommands.judgmentSafetyCase(root, listOf("src/service.py", "src/ui.kt")),
        )
        assertEquals(
            listOf(
                "judgment", "safety-case", "--root", root.toString(),
                "--changed", "src/service.py", "--change-profile", root.resolve(".factory/judgment/change-profile.json").toString(), "--json",
            ),
            FactoryLineCommands.judgmentSafetyCase(
                root,
                listOf("src/service.py"),
                root.resolve(".factory/judgment/change-profile.json"),
            ),
        )
    }

    @Test
    fun judgmentParserAcceptsOnlyBoundedStatusOrSafetyCaseSchemas() {
        val status = JudgmentSummary.fromJson(
            """{"schema":"factory.judgment.status.v1","marker":"JUDGMENT_CAPSULE_STATUS_READ_ONLY","state":"valid","counts":{"active":1,"proposed":2,"review_due":0}}""",
        )
        val safetyCase = JudgmentSummary.fromJson(
            """{"schema":"factory.judgment.safety-case.v1","marker":"JUDGMENT_SAFETY_CASE_READ_ONLY","route":"AMBER","attention":"architecture","profile":{"state":"valid"},"novelty":{"novel_change_kinds":["architecture-boundary"]},"human_questions":[{"id":"confirm-novel-architecture-boundary"}],"changed_paths":["src/service.py"],"required_reviewers":["Ada"],"missing_obligations":[]}""",
        )

        assertNotNull(status)
        assertEquals("1", status.active)
        assertEquals("2", status.proposed)
        assertNotNull(safetyCase)
        assertEquals("AMBER", safetyCase.route)
        assertEquals(listOf("Ada"), safetyCase.requiredReviewers)
        assertEquals("architecture", safetyCase.attention)
        assertEquals("valid", safetyCase.profileState)
        assertEquals(listOf("architecture-boundary"), safetyCase.novelChangeKinds)
        assertEquals(1, safetyCase.humanQuestionCount)
        assertNull(JudgmentSummary.fromJson("""{"schema":"untrusted","state":"valid"}"""))
    }

    @Test
    fun intentLedgerParserRendersOnlyTheSchemaBoundSupervisionFacts() {
        val ledger = IntentLedgerSummary.fromJson(
            """
                {
                  "schema":"factory.intent-ledger-inspection.v1",
                  "change_list":"Checkout",
                  "state":"stale_proof",
                  "current_changed_paths":["src/service.py"],
                  "record_path":".factory/intent-ledgers/intent.json",
                  "record":{"intent":{"promise":"Cancel safely","non_goal":"No migration","failure_case":"Invoice after cancellation"}},
                  "next_action":{"action":"rerun_stale_proof","reason":"A declared proof input changed."},
                  "untrusted":"ignored"
                }
            """.trimIndent(),
        )

        assertNotNull(ledger)
        assertEquals("stale_proof", ledger.state)
        assertEquals("Cancel safely", ledger.promise)
        assertEquals(listOf("src/service.py"), ledger.paths)
        assertEquals("rerun_stale_proof", ledger.nextAction)
        assertTrue(ledger.brief().contains("never edits source"))
        assertEquals(null, IntentLedgerSummary.fromJson("{\"schema\":\"untrusted\"}"))
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
