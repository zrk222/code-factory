package app.factoryline.intellij

import com.intellij.ide.BrowserUtil
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.util.Computable
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.vcs.changes.Change
import com.intellij.openapi.vcs.changes.ChangeListManager
import java.nio.file.Files
import java.nio.file.Path

object FactoryLineExecutionConfirmation {
    fun confirm(project: Project, action: String): Boolean {
        val root = project.basePath ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return false
        }
        return Messages.showYesNoDialog(
            project,
            "FactoryLine will run a local command in:\n$root\n\nContinue only if you trust this workspace and its configured FactoryLine executable.",
            "FactoryLine: $action",
            "Run local command",
            "Cancel",
            Messages.getWarningIcon()
        ) == Messages.YES
    }
}

object FactoryLineController {
    private val graphEvents = arrayOf(
        "approve", "defer", "reject", "candidate_ready", "validation_failed", "validation_passed",
        "retry", "pause", "plan_revised", "resume", "context_refreshed", "usage_recorded",
        "release_requested", "release_decided", "outcome_recorded"
    )

    private fun workspacePath(project: Project, label: String): Path? {
        val root = project.basePath?.let(Path::of) ?: return null
        val value = Messages.showInputDialog(project, "$label (inside this workspace):", "FactoryLine Mission Operations", null)
            ?: return null
        return WorkspacePath.resolve(root, value).also {
            if (it == null) Messages.showErrorDialog(project, "$label must resolve inside the current workspace.", "FactoryLine")
        }
    }

    private fun runBackground(
        project: Project,
        title: String,
        onCompleted: (CommandResult) -> Unit = { FactoryLinePanels.show(project, it) },
        operation: () -> CommandResult,
    ) {
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "FactoryLine: $title", true) {
            private lateinit var result: CommandResult
            override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                indicator.isIndeterminate = true
                result = operation()
            }
            override fun onSuccess() {
                onCompleted(result)
            }
        })
    }

    fun runFirstProof(project: Project) {
        if (!FactoryLineExecutionConfirmation.confirm(project, "Run First Proof")) return
        runBackground(project, "Run First Proof") { FactoryLineRunner.firstProof(project) }
    }

    fun analyzeWorkspaceAdvisor(project: Project) {
        if (!FactoryLineExecutionConfirmation.confirm(project, "Analyze Workspace Load and Remote/WSL Preflight")) return
        runBackground(project, "Workspace Load Advisor", onCompleted = { FactoryLinePanels.showWorkspaceAdvisor(project, it) }) {
            FactoryLineRunner.workspaceAdvisor(project)
        }
    }

    fun inspectSaasReality(project: Project) {
        if (!FactoryLineExecutionConfirmation.confirm(project, "Inspect local SaaS Reality receipts")) return
        runBackground(project, "Inspect SaaS Reality") { FactoryLineRunner.saasStatus(project) }
    }

    fun verifySaasReality(project: Project) {
        val contract = workspacePath(project, "Reviewed SaaS promise contract JSON") ?: return
        val evidence = workspacePath(project, "Observed SaaS journey evidence JSON") ?: return
        if (!FactoryLineExecutionConfirmation.confirm(project, "Verify the selected SaaS journey and write a local receipt")) return
        runBackground(project, "Verify SaaS Journey") { FactoryLineRunner.saasVerify(project, contract, evidence) }
    }

    fun saveWorkspaceAdvisorReport(project: Project) {
        val root = project.basePath?.let(Path::of) ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        if (!FactoryLineExecutionConfirmation.confirm(project, "Save Workspace Advisor Report")) return
        runBackground(project, "Save Workspace Advisor Report", onCompleted = { FactoryLinePanels.showWorkspaceAdvisor(project, it) }) {
            FactoryLineRunner.workspaceAdvisor(project, root.resolve(".factory").resolve("workspace-advice"))
        }
    }

    fun captureIndexContinuityBaseline(project: Project) {
        val root = project.basePath?.let(Path::of) ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        val out = root.resolve(".factory").resolve("index-continuity").resolve("baseline.json")
        if (!FactoryLineExecutionConfirmation.confirm(project, "Capture Index Continuity Baseline")) return
        runBackground(project, "Capture Index Continuity Baseline", onCompleted = { FactoryLinePanels.showIndexContinuity(project, it) }) {
            FactoryLineRunner.indexContinuityBaseline(project, out)
        }
    }

    fun compareIndexContinuityBaseline(project: Project) {
        val root = project.basePath?.let(Path::of) ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        val baseline = root.resolve(".factory").resolve("index-continuity").resolve("baseline.json")
        if (!Files.isRegularFile(baseline)) {
            Messages.showInfoMessage(project, "Capture the local baseline first. FactoryLine will not infer one from an old workspace state.", "FactoryLine Index Continuity Guard")
            return
        }
        if (!FactoryLineExecutionConfirmation.confirm(project, "Compare Index Continuity Baseline")) return
        runBackground(project, "Compare Index Continuity Baseline", onCompleted = { FactoryLinePanels.showIndexContinuity(project, it) }) {
            FactoryLineRunner.indexContinuityCompare(project, baseline)
        }
    }

    fun openIdeHealth(project: Project) {
        val toolWindow = com.intellij.openapi.wm.ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                toolWindow.contentManager.findContent("IDE Health")?.let { toolWindow.contentManager.setSelectedContent(it) }
                project.getUserData(FactoryLinePanels.ideHealthKey)?.showCurrent()
            }
        }
    }

    fun openGuardian(project: Project) = FactoryLinePanels.showGuardian(project)

    fun missionOperations(project: Project) {
        val options = MissionGraphOperation.entries.map { it.label }.toTypedArray()
        val selected = Messages.showDialog(
            project, "Choose a receipt-governed mission operation.", "FactoryLine Mission Operations",
            options, 0, Messages.getQuestionIcon()
        )
        if (selected < 0) return
        val operation = MissionGraphOperation.entries[selected]
        when (operation) {
            MissionGraphOperation.EVENT -> recordMissionEvent(project)
            MissionGraphOperation.ROUTE -> routeMissionProvider(project)
            else -> {
                val mission = workspacePath(project, "Mission JSON path") ?: return
                if (!FactoryLineExecutionConfirmation.confirm(project, operation.label)) return
                runBackground(project, operation.label) { FactoryLineRunner.runMissionGraph(project, operation, mission) }
            }
        }
    }

    private fun recordMissionEvent(project: Project) {
        val mission = workspacePath(project, "Mission JSON path") ?: return
        val eventIndex = Messages.showDialog(
            project, "Event to record:", "FactoryLine Guarded Event", graphEvents, 0, Messages.getQuestionIcon()
        )
        if (eventIndex < 0) return
        val actor = Messages.showInputDialog(project, "Actor identity:", "FactoryLine Guarded Event", null)?.trim().orEmpty()
        if (actor.isBlank()) return
        val roles = arrayOf("owner", "worker", "validator", "operator")
        val roleIndex = Messages.showDialog(project, "Actor role:", "FactoryLine Guarded Event", roles, 0, Messages.getQuestionIcon())
        if (roleIndex < 0) return
        val key = Messages.showInputDialog(project, "Unique idempotency key:", "FactoryLine Guarded Event", null)?.trim().orEmpty()
        if (key.isBlank()) return
        val receipt = workspacePath(project, "Receipt JSON path") ?: return
        val payloadValue = Messages.showInputDialog(
            project, "Optional payload JSON path (leave blank for none):", "FactoryLine Guarded Event", null
        ) ?: return
        val root = project.basePath?.let(Path::of) ?: return
        val payload = payloadValue.takeIf { it.isNotBlank() }?.let {
            WorkspacePath.resolve(root, it) ?: run {
                Messages.showErrorDialog(project, "Payload must resolve inside the current workspace.", "FactoryLine")
                return
            }
        }
        if (!FactoryLineExecutionConfirmation.confirm(project, "Record ${graphEvents[eventIndex]} event")) return
        runBackground(project, "Record guarded event") {
            FactoryLineRunner.runMissionEvent(project, mission, graphEvents[eventIndex], actor, roles[roleIndex], key, receipt, payload)
        }
    }

    private fun routeMissionProvider(project: Project) {
        val policy = workspacePath(project, "Provider policy JSON path") ?: return
        val mission = workspacePath(project, "Mission JSON path") ?: return
        val risks = arrayOf("low", "medium", "high")
        val riskIndex = Messages.showDialog(project, "Mission risk:", "FactoryLine BYOK Router", risks, 1, Messages.getQuestionIcon())
        if (riskIndex < 0) return
        val provider = Messages.showInputDialog(project, "Preferred provider ID (optional):", "FactoryLine BYOK Router", null) ?: return
        val model = Messages.showInputDialog(project, "Preferred model ID (optional):", "FactoryLine BYOK Router", null) ?: return
        if (!FactoryLineExecutionConfirmation.confirm(project, "Route BYOK provider")) return
        runBackground(project, "Route BYOK provider") {
            FactoryLineRunner.routeProvider(project, policy, mission, risks[riskIndex], provider.trim(), model.trim())
        }
    }

    fun requestFeature(project: Project, operation: FactoryLineOperation) {
        val feature = Messages.showInputDialog(
            project,
            "Feature name (letters, digits, hyphens, underscores):",
            "FactoryLine: ${operation.title}",
            null
        )?.trim() ?: return
        if (!FeatureName.isValid(feature)) {
            Messages.showErrorDialog(project, "Feature names use letters, digits, hyphens, and underscores only.", "FactoryLine")
            return
        }
        if (!FactoryLineExecutionConfirmation.confirm(project, operation.title)) return
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "FactoryLine: ${operation.title}", true) {
            private lateinit var result: CommandResult

            override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                indicator.isIndeterminate = true
                result = FactoryLineRunner.run(project, operation, feature)
            }

            override fun onSuccess() {
                FactoryLinePanels.show(project, result)
            }
        })
    }

    fun openLatestReceipt(project: Project) {
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "FactoryLine: Open Latest Receipt", true) {
            private var receipt: ReceiptSummary? = null
            private var error: String? = null

            override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                indicator.isIndeterminate = true
                try {
                    val root = project.basePath?.let(Path::of) ?: error("The project has no local workspace path.")
                    val path = ReceiptLocator.latest(root) ?: error("No JSON receipt found under .factory or receipts.")
                    receipt = ReceiptLocator.read(path)
                } catch (failure: Exception) {
                    error = failure.message ?: "Unable to open the latest receipt."
                }
            }

            override fun onSuccess() {
                receipt?.let { FactoryLinePanels.show(project, it) }
                    ?: Messages.showErrorDialog(project, error ?: "Unable to open the latest receipt.", "FactoryLine")
            }
        })
    }

    fun analyzeChangedProof(project: Project) {
        if (!FactoryLineExecutionConfirmation.confirm(project, "Analyze Changed Proof")) return
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "FactoryLine: Analyze Changed Proof", true) {
            private lateinit var result: CommandResult

            override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                indicator.isIndeterminate = true
                result = FactoryLineRunner.analyzeChangedProof(project)
            }

            override fun onSuccess() {
                FactoryLinePanels.show(project, result)
            }
        })
    }

    fun reviewCurrentDiff(project: Project) {
        if (!FactoryLineExecutionConfirmation.confirm(project, "Review Current Diff")) return
        runBackground(project, "Proof Review", onCompleted = { FactoryLinePanels.showProofReview(project, it) }) {
            FactoryLineRunner.proofReview(project)
        }
    }

    fun reviewCurrentFile(project: Project, requestedFile: VirtualFile? = null) {
        val root = project.basePath?.let(Path::of) ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        val file = requestedFile ?: FileEditorManager.getInstance(project).selectedFiles.firstOrNull()
        val resolved = file?.let { WorkspacePath.resolve(root, it.path) }
        if (file == null || resolved == null || resolved == root || file.isDirectory) {
            Messages.showErrorDialog(project, "Open a project file before starting a focused Proof Review.", "FactoryLine")
            return
        }
        val relative = root.toAbsolutePath().normalize().relativize(resolved).toString().replace('\\', '/')
        if (!FactoryLineExecutionConfirmation.confirm(project, "Review This File")) return
        runBackground(project, "Proof Review This File", onCompleted = { FactoryLinePanels.showProofReview(project, it) }) {
            FactoryLineRunner.proofReview(project, relative)
        }
    }

    fun saveProofReviewHandoff(project: Project) {
        val root = project.basePath?.let(Path::of) ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        val outDir = root.resolve(".factory").resolve("change-reviews")
        if (!FactoryLineExecutionConfirmation.confirm(project, "Save Review Handoff")) return
        runBackground(project, "Save Proof Review Handoff", onCompleted = { FactoryLinePanels.showProofReview(project, it) }) {
            FactoryLineRunner.proofReview(project, outDir = outDir)
        }
    }

    fun prepareRepairScope(project: Project) {
        val root = project.basePath?.let(Path::of) ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        val scopes = runCatching { NativeChangeListScopes.collect(project, root) }.getOrElse { failure ->
            Messages.showErrorDialog(project, "Could not read local Change Lists: ${failure.message}", "FactoryLine")
            return
        }.filter { it.paths.isNotEmpty() || it.unavailableChanges > 0 }
        if (scopes.isEmpty()) {
            Messages.showInfoMessage(project, "No local Change List contains a project change. Make or select a local change first.", "FactoryLine Repair Sandbox")
            return
        }
        val selectedIndex = Messages.showDialog(
            project,
            "Select one Change List to seal. FactoryLine will send only its explicit project paths to the local CLI.",
            "FactoryLine: Prepare Repair Scope",
            scopes.map { it.displayName() }.toTypedArray(),
            0,
            Messages.getQuestionIcon(),
        )
        if (selectedIndex < 0) return
        val selected = scopes[selectedIndex]
        if (selected.unavailableChanges > 0) {
            Messages.showErrorDialog(
                project,
                "'${selected.name}' includes ${selected.unavailableChanges} change(s) outside the project or without a resolvable file path. FactoryLine will not silently drop them; use a fully project-contained Change List.",
                "FactoryLine Repair Sandbox",
            )
            return
        }
        if (selected.paths.isEmpty()) {
            Messages.showErrorDialog(project, "The selected Change List contains no project files to seal.", "FactoryLine Repair Sandbox")
            return
        }
        if (!FactoryLineExecutionConfirmation.confirm(project, "Prepare Repair Scope")) return
        val outDir = root.resolve(".factory").resolve("repair-sandboxes")
        runBackground(project, "Prepare Repair Scope", onCompleted = { FactoryLinePanels.showRepairSandbox(project, it) }) {
            FactoryLineRunner.repairScope(project, selected.name, selected.paths, outDir)
        }
    }

    fun installProofAdapter(project: Project, client: String) {
        val label = if (client == "junie") "Junie MCP" else "Copilot Proof Agent"
        if (!FactoryLineExecutionConfirmation.confirm(project, "Install $label")) return
        runBackground(project, "Install $label") { FactoryLineRunner.mcpInstall(project, client) }
    }

    fun verifyAgentAndAnalyzer(project: Project, scope: RepairScopeSummary?) {
        val selectedScope = scope ?: run {
            Messages.showInfoMessage(project, "Prepare a trusted Change List scope before verifying an agent result.", "FactoryLine Proof Handshake")
            return
        }
        val root = project.basePath?.let(Path::of) ?: return
        val scopePath = selectedScope.artifactPaths.firstOrNull { it.endsWith(".json", ignoreCase = true) }
            ?.let { WorkspacePath.resolve(root, it) } ?: run {
                Messages.showErrorDialog(project, "The selected scope has no project-contained JSON packet.", "FactoryLine Proof Handshake")
                return
            }
        val sarifValue = Messages.showInputDialog(project, "Qodana or SonarQube SARIF 2.1.0 path (inside this workspace):", "FactoryLine: Verify Agent + Analyzer", null)
            ?.trim() ?: return
        val sarif = WorkspacePath.resolve(root, sarifValue)
        if (sarif == null || !Files.isRegularFile(sarif)) {
            Messages.showErrorDialog(project, "The SARIF report must be an existing regular file inside the workspace.", "FactoryLine Proof Handshake")
            return
        }
        val providerIndex = Messages.showDialog(project, "Choose the report source. Auto accepts a uniquely recognized Qodana or SonarQube driver.", "FactoryLine: Analysis Evidence", arrayOf("Auto detect", "Qodana", "SonarQube"), 0, Messages.getQuestionIcon())
        if (providerIndex < 0) return
        val provider = listOf("auto", "qodana", "sonarqube")[providerIndex]
        val e2eValue = Messages.showInputDialog(project, "Optional E2E receipt path (leave blank to report it as unknown):", "FactoryLine: Optional E2E Evidence", null)?.trim().orEmpty()
        val e2e = if (e2eValue.isBlank()) null else WorkspacePath.resolve(root, e2eValue)
        if (e2eValue.isNotBlank() && (e2e == null || !Files.isRegularFile(e2e))) {
            Messages.showErrorDialog(project, "The E2E receipt must be an existing regular file inside the workspace.", "FactoryLine Proof Handshake")
            return
        }
        if (!FactoryLineExecutionConfirmation.confirm(project, "Verify Agent + Analyzer")) return
        runBackground(project, "Verify Agent + Analyzer") {
            FactoryLineRunner.jetbrainsHandshake(project, scopePath, selectedScope.paths, sarif, provider, e2e)
        }
    }

    fun inspectIntentLedger(project: Project) {
        val selected = selectIntentScope(project) ?: return
        if (!FactoryLineExecutionConfirmation.confirm(project, "Inspect Intent Ledger")) return
        runBackground(project, "Inspect Intent Ledger", onCompleted = { FactoryLinePanels.showIntentLedger(project, it) }) {
            FactoryLineRunner.inspectIntentLedger(project, selected.name, selected.paths)
        }
    }

    fun inspectJudgment(project: Project) {
        if (!FactoryLineExecutionConfirmation.confirm(project, "Inspect Engineering Judgment")) return
        runBackground(project, "Inspect Engineering Judgment", onCompleted = { FactoryLinePanels.showJudgment(project, it) }) {
            FactoryLineRunner.judgmentStatus(project)
        }
    }

    fun inspectJudgmentSafetyCase(project: Project) {
        val selected = selectIntentScope(project, "FactoryLine Engineering Judgment") ?: return
        if (!FactoryLineExecutionConfirmation.confirm(project, "Inspect Judgment Safety Case")) return
        runBackground(project, "Inspect Judgment Safety Case", onCompleted = { FactoryLinePanels.showJudgment(project, it) }) {
            FactoryLineRunner.judgmentSafetyCase(project, selected.paths)
        }
    }

    fun captureIntentLedger(project: Project) {
        val selected = selectIntentScope(project) ?: return
        val confirmedBy = Messages.showInputDialog(project, "Named human confirming this behavioral contract:", "FactoryLine: Capture Intent Ledger", null)
            ?.trim().orEmpty()
        if (confirmedBy.isBlank()) return
        val promise = Messages.showInputDialog(project, "Observable promise for this Change List:", "FactoryLine: Capture Intent Ledger", null)
            ?.trim().orEmpty()
        if (promise.isBlank()) return
        val nonGoal = Messages.showInputDialog(project, "Explicit non-goal for this Change List:", "FactoryLine: Capture Intent Ledger", null)
            ?.trim().orEmpty()
        if (nonGoal.isBlank()) return
        val failureCase = Messages.showInputDialog(project, "Negative behavior the later proof must be able to catch:", "FactoryLine: Capture Intent Ledger", null)
            ?.trim().orEmpty()
        if (failureCase.isBlank()) return
        val phrase = "CAPTURE ${selected.name}"
        val confirmation = Messages.showInputDialog(
            project,
            "FactoryLine will save only a local intent record for ${selected.paths.size} selected Change List path(s).\n\nIt will not edit source, modify the Change List, run a test, or start an agent.\n\nType exactly: $phrase",
            "FactoryLine: Confirm Intent Ledger Capture",
            null,
        )?.trim().orEmpty()
        if (confirmation != phrase) {
            Messages.showErrorDialog(project, "Capture was not confirmed. The required phrase is: $phrase", "FactoryLine Intent Ledger")
            return
        }
        if (!FactoryLineExecutionConfirmation.confirm(project, "Capture Intent Ledger")) return
        runBackground(project, "Capture Intent Ledger", onCompleted = { FactoryLinePanels.showIntentLedger(project, it) }) {
            FactoryLineRunner.captureIntentLedger(project, selected.name, selected.paths, confirmedBy, promise, nonGoal, failureCase, confirmation)
        }
    }

    private fun selectIntentScope(project: Project, title: String = "FactoryLine Intent Ledger"): NativeChangeListScope? {
        val root = project.basePath?.let(Path::of) ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return null
        }
        val scopes = runCatching { NativeChangeListScopes.collect(project, root) }.getOrElse { failure ->
            Messages.showErrorDialog(project, "Could not read local Change Lists: ${failure.message}", "FactoryLine")
            return null
        }.filter { it.paths.isNotEmpty() || it.unavailableChanges > 0 }
        if (scopes.isEmpty()) {
            Messages.showInfoMessage(project, "No local Change List contains a project change. Make or select a local change first.", title)
            return null
        }
        val selectedIndex = Messages.showDialog(
            project,
            "Select one native Change List. FactoryLine will use only its explicit project paths; it will not change VCS state.",
            title,
            scopes.map { it.displayName() }.toTypedArray(),
            0,
            Messages.getQuestionIcon(),
        )
        if (selectedIndex < 0) return null
        val selected = scopes[selectedIndex]
        if (selected.unavailableChanges > 0) {
            Messages.showErrorDialog(
                project,
                "'${selected.name}' includes ${selected.unavailableChanges} change(s) outside the project or without a resolvable file path. FactoryLine will not silently drop them.",
                title,
            )
            return null
        }
        if (selected.paths.isEmpty()) {
            Messages.showErrorDialog(project, "The selected Change List contains no project files to inspect.", title)
            return null
        }
        return selected
    }

    fun validateRepairCandidate(project: Project, scope: RepairScopeSummary?) {
        val selectedScope = scope ?: run {
            Messages.showInfoMessage(project, "Prepare a trusted Change List scope before validating a candidate patch.", "FactoryLine Repair Sandbox")
            return
        }
        val root = project.basePath?.let(Path::of) ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        val scopePath = selectedScope.artifactPaths.firstOrNull { it.endsWith(".json", ignoreCase = true) }?.let {
            WorkspacePath.resolve(root, it)
        } ?: run {
            Messages.showErrorDialog(project, "The selected scope has no project-contained JSON packet. Prepare the Change List again.", "FactoryLine Repair Sandbox")
            return
        }
        val patchValue = Messages.showInputDialog(
            project,
            "Candidate patch path (inside this workspace; textual Git diff only):",
            "FactoryLine: Validate Repair Candidate",
            null,
        )?.trim() ?: return
        val patchPath = WorkspacePath.resolve(root, patchValue)
        if (patchPath == null || !Files.isRegularFile(patchPath)) {
            Messages.showErrorDialog(project, "Candidate patch must be an existing regular file inside the current workspace.", "FactoryLine Repair Sandbox")
            return
        }
        if (!FactoryLineExecutionConfirmation.confirm(project, "Validate Repair Candidate")) return
        val outDir = root.resolve(".factory").resolve("repair-sandboxes")
        runBackground(project, "Validate Repair Candidate", onCompleted = { FactoryLinePanels.showRepairSandbox(project, it) }) {
            FactoryLineRunner.repairCandidate(project, scopePath, patchPath, outDir)
        }
    }

    fun checkLatestReceiptSignature(project: Project) {
        if (!FactoryLineExecutionConfirmation.confirm(project, "Check Receipt Signature State")) return
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "FactoryLine: Check Receipt Signature State", true) {
            private lateinit var result: CommandResult

            override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                indicator.isIndeterminate = true
                result = try {
                    val root = project.basePath?.let(Path::of) ?: error("The project has no local workspace path.")
                    val receipt = ReceiptLocator.latest(root) ?: error("No JSON receipt found under .factory or receipts.")
                    FactoryLineRunner.receiptStatus(project, receipt)
                } catch (failure: Exception) {
                    CommandResult("Check Receipt Signature State", emptyList(), null, false, failure.message ?: "Unable to inspect receipt signature state.")
                }
            }

            override fun onSuccess() {
                FactoryLinePanels.show(project, result)
            }
        })
    }

    fun openMeter(project: Project) {
        if (!FactoryLineExecutionConfirmation.confirm(project, "Open Local Meter")) return
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "FactoryLine: Open Local Meter", true) {
            private lateinit var result: CommandResult

            override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                indicator.isIndeterminate = true
                result = FactoryLineRunner.meter(project)
            }

            override fun onSuccess() {
                if (result.exitCode == 0 && !result.timedOut) {
                    FactoryLinePanels.show(project, MeterSummary.fromJson(result.output))
                } else {
                    FactoryLinePanels.show(project, result)
                }
            }
        })
    }

    fun openSavings(project: Project) {
        if (!FactoryLineExecutionConfirmation.confirm(project, "Open Paired Savings Report")) return
        runBackground(project, "Open Paired Savings Report") { FactoryLineRunner.savings(project) }
    }

    fun openStudio(project: Project, productMode: Boolean = false, graphMode: Boolean = false) {
        require(!(productMode && graphMode))
        val root = project.basePath ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        fun targetUrl(base: String): String = when {
            graphMode -> StudioUrl.graphOps(base) ?: base
            productMode -> StudioUrl.productMissions(base) ?: base
            else -> base
        }
        FactoryLineStudioSession.connectedUrl(project)?.let { connected ->
            val target = targetUrl(connected)
            BrowserUtil.browse(target)
            FactoryLinePanels.showStudioConnection(project, target, reused = true)
            return
        }
        val confirmed = Messages.showYesNoDialog(
            project,
            "Open ${if (graphMode) "Unified Graph Ops" else if (productMode) "Product Missions" else "Factory Studio"} on loopback for:\n$root\n\nGraph Ops only inspects local artifacts. Studio grants no execute, merge, deploy, publish, credential, connector, or external-message authority.",
            "FactoryLine: ${if (graphMode) "Open Unified Graph Ops" else if (productMode) "Open Product Missions" else "Open Local Factory Studio"}",
            "Start local Studio",
            "Cancel",
            Messages.getWarningIcon()
        ) == Messages.YES
        if (!confirmed) return
        FactoryLineRunner.startStudio(
            project,
            onStarted = { url ->
                FactoryLineStudioSession.remember(project, url)
                val target = targetUrl(url)
                BrowserUtil.browse(target)
                val marker = if (graphMode) "EDITOR_GRAPH_OPS_CONFIRMED" else if (productMode) "EDITOR_PRODUCT_MISSION_CONFIRMED" else "EDITOR_TRUST_CONFIRMED"
                FactoryLinePanels.showStudioConnection(project, target, reused = false)
                Messages.showInfoMessage(project, "Factory Studio is running at $target\n\nmarker: $marker", "FactoryLine")
            },
            onFailure = { message -> Messages.showErrorDialog(project, message, "FactoryLine") },
            onStopped = { FactoryLineStudioSession.clear(project) },
        )
    }
}

abstract class FactoryLineAction : AnAction() {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(event: AnActionEvent) {
        event.presentation.isEnabledAndVisible = event.project != null
    }
}

class RunFirstProofAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.runFirstProof(it) }
    }
}

class RunAssemblyAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.requestFeature(it, FactoryLineOperation.ASSEMBLE) }
    }
}

class ContinueAssemblyAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.requestFeature(it, FactoryLineOperation.CONTINUE) }
    }
}

class VerifyReceiptsAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.requestFeature(it, FactoryLineOperation.VERIFY) }
    }
}

class OpenLatestReceiptAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.openLatestReceipt(it) }
    }
}

class AnalyzeChangedProofAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.analyzeChangedProof(it) }
    }
}

class AnalyzeWorkspaceAdvisorAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.analyzeWorkspaceAdvisor(it) }
    }
}

class CaptureIndexContinuityBaselineAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.captureIndexContinuityBaseline(it) }
    }
}

class CompareIndexContinuityBaselineAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.compareIndexContinuityBaseline(it) }
    }
}

class OpenIdeHealthAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.openIdeHealth(it) }
    }
}

class OpenGuardianAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.openGuardian(it) }
    }
}

data class NativeChangeListScope(
    val name: String,
    val paths: List<String>,
    val unavailableChanges: Int,
) {
    fun displayName(): String = buildString {
        append("$name â€” ${paths.size} project file(s)")
        if (unavailableChanges > 0) append("; $unavailableChanges unavailable")
    }
}

/** Reads only native local Change Lists; it neither modifies VCS state nor runs Git. */
object NativeChangeListScopes {
    fun collect(project: Project, root: Path): List<NativeChangeListScope> =
        ApplicationManager.getApplication().runReadAction(Computable {
            ChangeListManager.getInstance(project).changeLists.map { changeList ->
                val paths = linkedSetOf<String>()
                var unavailable = 0
                changeList.changes.forEach { change ->
                    val rawPaths = revisionPaths(change)
                    val resolved = rawPaths.mapNotNull { raw ->
                        WorkspacePath.resolve(root, raw)?.let { path ->
                            root.toAbsolutePath().normalize().relativize(path).toString().replace('\\', '/')
                        }
                    }
                    if (rawPaths.isEmpty() || resolved.size != rawPaths.size) unavailable += 1 else paths.addAll(resolved)
                }
                NativeChangeListScope(changeList.name, paths.toList().sorted(), unavailable)
            }.sortedBy { it.name.lowercase() }
        })

    private fun revisionPaths(change: Change): List<String> = listOfNotNull(
        change.beforeRevision?.file?.path,
        change.afterRevision?.file?.path,
    ).distinct()
}

class ReviewCurrentDiffAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.reviewCurrentDiff(it) }
    }
}

class PrepareRepairScopeAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.prepareRepairScope(it) }
    }
}

class InspectIntentLedgerAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.inspectIntentLedger(it) }
    }
}

class CaptureIntentLedgerAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.captureIntentLedger(it) }
    }
}

class ReviewCurrentFileAction : FactoryLineAction() {
    override fun update(event: AnActionEvent) {
        super.update(event)
        event.presentation.isEnabledAndVisible = event.project != null && event.getData(CommonDataKeys.VIRTUAL_FILE)?.isDirectory == false
    }

    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.reviewCurrentFile(it, event.getData(CommonDataKeys.VIRTUAL_FILE)) }
    }
}

class CheckLatestReceiptSignatureAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.checkLatestReceiptSignature(it) }
    }
}

class OpenMeterAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.openMeter(it) }
    }
}

class OpenSavingsAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.openSavings(it) }
    }
}

class OpenStudioAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.openStudio(it) }
    }
}

class OpenProductMissionsAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.openStudio(it, productMode = true) }
    }
}

class OpenGraphOpsAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.openStudio(it, graphMode = true) }
    }
}

class MissionOperationsAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.missionOperations(it) }
    }
}
