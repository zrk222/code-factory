package app.factoryline.intellij

import com.intellij.ide.BrowserUtil
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
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

    private fun runBackground(project: Project, title: String, operation: () -> CommandResult) {
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "FactoryLine: $title", true) {
            private lateinit var result: CommandResult
            override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                indicator.isIndeterminate = true
                result = operation()
            }
            override fun onSuccess() = FactoryLinePanels.show(project, result)
        })
    }

    fun missionOperations(project: Project) {
        val options = MissionGraphOperation.entries.map { it.label }.toTypedArray()
        val selected = Messages.showChooseDialog(
            project, "Choose a receipt-governed mission operation.", "FactoryLine Mission Operations",
            Messages.getQuestionIcon(), options, options.first()
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
        val eventIndex = Messages.showChooseDialog(
            project, "Event to record:", "FactoryLine Guarded Event", Messages.getQuestionIcon(), graphEvents, graphEvents.first()
        )
        if (eventIndex < 0) return
        val actor = Messages.showInputDialog(project, "Actor identity:", "FactoryLine Guarded Event", null)?.trim().orEmpty()
        if (actor.isBlank()) return
        val roles = arrayOf("owner", "worker", "validator", "operator")
        val roleIndex = Messages.showChooseDialog(project, "Actor role:", "FactoryLine Guarded Event", Messages.getQuestionIcon(), roles, roles.first())
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
        val riskIndex = Messages.showChooseDialog(project, "Mission risk:", "FactoryLine BYOK Router", Messages.getQuestionIcon(), risks, "medium")
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

    fun openStudio(project: Project, productMode: Boolean = false) {
        val root = project.basePath ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        val confirmed = Messages.showYesNoDialog(
            project,
            "Open ${if (productMode) "Product Missions" else "Factory Studio"} on loopback for:\n$root\n\nLocal artifacts may be created. This grants no execute, merge, deploy, publish, credential, connector, or external-message authority.",
            "FactoryLine: ${if (productMode) "Open Product Missions" else "Open Local Factory Studio"}",
            "Start local Studio",
            "Cancel",
            Messages.getWarningIcon()
        ) == Messages.YES
        if (!confirmed) return
        FactoryLineRunner.startStudio(
            project,
            onStarted = { url ->
                val targetUrl = if (productMode) "$url?mode=product" else url
                BrowserUtil.browse(targetUrl)
                val marker = if (productMode) "EDITOR_PRODUCT_MISSION_CONFIRMED" else "EDITOR_TRUST_CONFIRMED"
                Messages.showInfoMessage(project, "Factory Studio is running at $targetUrl\n\nmarker: $marker", "FactoryLine")
            },
            onFailure = { message -> Messages.showErrorDialog(project, message, "FactoryLine") }
        )
    }
}

abstract class FactoryLineAction : AnAction() {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(event: AnActionEvent) {
        event.presentation.isEnabledAndVisible = event.project != null
    }
}

class RunAssemblyAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.requestFeature(it, FactoryLineOperation.ASSEMBLE) }
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

class MissionOperationsAction : FactoryLineAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.let { FactoryLineController.missionOperations(it) }
    }
}
