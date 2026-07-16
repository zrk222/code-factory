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

    fun openStudio(project: Project) {
        val root = project.basePath ?: run {
            Messages.showErrorDialog(project, "FactoryLine needs a local project workspace path.", "FactoryLine")
            return
        }
        val confirmed = Messages.showYesNoDialog(
            project,
            "Start Factory Studio on loopback for:\n$root\n\nStudio may create new child directories. It cannot deploy, publish, sign, inject credentials, grant connectors, or send external messages.",
            "FactoryLine: Open Local Factory Studio",
            "Start local Studio",
            "Cancel",
            Messages.getWarningIcon()
        ) == Messages.YES
        if (!confirmed) return
        FactoryLineRunner.startStudio(
            project,
            onStarted = { url ->
                BrowserUtil.browse(url)
                Messages.showInfoMessage(project, "Factory Studio is running at $url\n\nmarker: EDITOR_TRUST_CONFIRMED", "FactoryLine")
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
