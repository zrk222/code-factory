package app.factoryline.intellij

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.Key
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.openapi.wm.ToolWindowManager
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.ui.content.ContentFactory
import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel

class FactoryLineToolWindowFactory : ToolWindowFactory {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val guardian = FactoryLineGuardianPanel(project)
        val panel = FactoryLinePanel(project)
        val proofReview = FactoryLineProofReviewPanel(project)
        val repairSandbox = FactoryLineRepairSandboxPanel(project)
        val workspaceAdvisor = FactoryLineWorkspaceAdvisorPanel(project)
        val ideHealth = FactoryLineIdeHealthPanel(project)
        val indexContinuity = FactoryLineIndexContinuityPanel(project)
        val intentLedger = FactoryLineIntentLedgerPanel(project)
        val judgment = FactoryLineJudgmentPanel(project)
        project.putUserData(FactoryLinePanels.guardianKey, guardian)
        project.putUserData(FactoryLinePanels.key, panel)
        project.putUserData(FactoryLinePanels.proofReviewKey, proofReview)
        project.putUserData(FactoryLinePanels.repairSandboxKey, repairSandbox)
        project.putUserData(FactoryLinePanels.workspaceAdvisorKey, workspaceAdvisor)
        project.putUserData(FactoryLinePanels.ideHealthKey, ideHealth)
        project.putUserData(FactoryLinePanels.indexContinuityKey, indexContinuity)
        project.putUserData(FactoryLinePanels.intentLedgerKey, intentLedger)
        project.putUserData(FactoryLinePanels.judgmentKey, judgment)
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(guardian, "Guardian", false)
        )
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(panel, "Receipts", false)
        )
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(proofReview, "Proof Review", false)
        )
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(repairSandbox, "Repair Sandbox", false)
        )
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(workspaceAdvisor, "Workspace Advisor", false)
        )
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(ideHealth, "IDE Health", false)
        )
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(indexContinuity, "Index Continuity", false)
        )
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(intentLedger, "Intent Ledger", false)
        )
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(judgment, "Engineering Judgment", false)
        )
    }
}

class FactoryLinePanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Local Studio: not connected. Start with a local proof; code and receipts stay on this machine.")
    private val output = JBTextArea().apply {
        isEditable = false
        lineWrap = false
        text = "Run first proof to check the local Code Factory setup. Every command requires workspace confirmation."
    }

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Run first proof").apply { addActionListener { FactoryLineController.runFirstProof(project) } })
            add(JButton("Run assembly").apply { addActionListener { FactoryLineController.requestFeature(project, FactoryLineOperation.ASSEMBLE) } })
            add(JButton("Continue assembly").apply { addActionListener { FactoryLineController.requestFeature(project, FactoryLineOperation.CONTINUE) } })
            add(JButton("Verify receipts").apply { addActionListener { FactoryLineController.requestFeature(project, FactoryLineOperation.VERIFY) } })
            add(JButton("Analyze changed proof").apply { addActionListener { FactoryLineController.analyzeChangedProof(project) } })
            add(JButton("Analyze workspace").apply { addActionListener { FactoryLineController.analyzeWorkspaceAdvisor(project) } })
            add(JButton("Open local meter").apply { addActionListener { FactoryLineController.openMeter(project) } })
            add(JButton("Factory Studio").apply { addActionListener { FactoryLineController.openStudio(project) } })
            add(JButton("Unified Graph Ops").apply { addActionListener { FactoryLineController.openStudio(project, graphMode = true) } })
            add(JButton("Verify SaaS journey").apply { addActionListener { FactoryLineController.verifySaasReality(project) } })
            add(JButton("View SaaS status").apply { addActionListener { FactoryLineController.inspectSaasReality(project) } })
            add(JButton("Product missions").apply { addActionListener { FactoryLineController.openStudio(project, productMode = true) } })
            add(JButton("Mission operations").apply { addActionListener { FactoryLineController.missionOperations(project) } })
            add(JButton("Open latest receipt").apply { addActionListener { FactoryLineController.openLatestReceipt(project) } })
            add(JButton("Check signature state").apply { addActionListener { FactoryLineController.checkLatestReceiptSignature(project) } })
        }
        add(controls, BorderLayout.NORTH)
        add(JBScrollPane(output), BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        status.text = when {
            result.timedOut -> "${result.title}: timed out after five minutes."
            result.exitCode == 0 -> "${result.title}: completed successfully."
            result.exitCode != null -> "${result.title}: exited ${result.exitCode}."
            else -> "${result.title}: blocked or could not start."
        }
        output.text = buildString {
            appendLine("Command: ${result.command.joinToString(" ")}")
            appendLine()
            append(result.output.ifBlank { "No output." })
        }
        output.caretPosition = 0
    }

    fun show(receipt: ReceiptSummary) {
        status.text = "Opened local receipt: ${receipt.source.fileName}"
        output.text = receipt.display + "\n" + receipt.rawJson
        output.caretPosition = 0
    }

    fun show(meter: MeterSummary) {
        status.text = "Opened local FactoryLine meter."
        output.text = meter.display + "\n" + meter.rawJson
        output.caretPosition = 0
    }

    fun showStudioConnection(target: String, reused: Boolean) {
        status.text = if (reused) {
            "Local Studio connected — opened $target"
        } else {
            "Local Studio started on loopback — opened $target"
        }
    }
}

object FactoryLinePanels {
    val guardianKey: Key<FactoryLineGuardianPanel> = Key.create("app.factoryline.intellij.guardian")
    val key: Key<FactoryLinePanel> = Key.create("app.factoryline.intellij.panel")
    val proofReviewKey: Key<FactoryLineProofReviewPanel> = Key.create("app.factoryline.intellij.proofReview")
    val repairSandboxKey: Key<FactoryLineRepairSandboxPanel> = Key.create("app.factoryline.intellij.repairSandbox")
    val workspaceAdvisorKey: Key<FactoryLineWorkspaceAdvisorPanel> = Key.create("app.factoryline.intellij.workspaceAdvisor")
    val ideHealthKey: Key<FactoryLineIdeHealthPanel> = Key.create("app.factoryline.intellij.ideHealth")
    val indexContinuityKey: Key<FactoryLineIndexContinuityPanel> = Key.create("app.factoryline.intellij.indexContinuity")
    val intentLedgerKey: Key<FactoryLineIntentLedgerPanel> = Key.create("app.factoryline.intellij.intentLedger")
    val judgmentKey: Key<FactoryLineJudgmentPanel> = Key.create("app.factoryline.intellij.judgment")

    fun show(project: Project, result: CommandResult) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater { project.getUserData(key)?.show(result) }
        }
    }

    fun show(project: Project, receipt: ReceiptSummary) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater { project.getUserData(key)?.show(receipt) }
        }
    }

    fun show(project: Project, meter: MeterSummary) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater { project.getUserData(key)?.show(meter) }
        }
    }

    fun showStudioConnection(project: Project, target: String, reused: Boolean) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                project.getUserData(key)?.showStudioConnection(target, reused)
            }
        }
    }

    fun showProofReview(project: Project, result: CommandResult) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                project.getUserData(proofReviewKey)?.show(result)
            }
        }
    }

    fun showRepairSandbox(project: Project, result: CommandResult) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                project.getUserData(repairSandboxKey)?.show(result)
            }
        }
    }

    fun showWorkspaceAdvisor(project: Project, result: CommandResult) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                toolWindow.contentManager.findContent("Workspace Advisor")?.let { toolWindow.contentManager.setSelectedContent(it) }
                project.getUserData(workspaceAdvisorKey)?.show(result)
            }
        }
    }

    fun showIndexContinuity(project: Project, result: CommandResult) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                toolWindow.contentManager.findContent("Index Continuity")?.let { toolWindow.contentManager.setSelectedContent(it) }
                project.getUserData(indexContinuityKey)?.show(result)
            }
        }
    }

    fun showGuardian(project: Project) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                toolWindow.contentManager.findContent("Guardian")?.let { toolWindow.contentManager.setSelectedContent(it) }
                project.getUserData(guardianKey)?.showCurrent()
            }
        }
    }

    fun selectTab(project: Project, title: String) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                toolWindow.contentManager.findContent(title)?.let { toolWindow.contentManager.setSelectedContent(it) }
            }
        }
    }

    fun showIntentLedger(project: Project, result: CommandResult) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                toolWindow.contentManager.findContent("Intent Ledger")?.let { toolWindow.contentManager.setSelectedContent(it) }
                project.getUserData(intentLedgerKey)?.show(result)
            }
        }
    }

    fun showJudgment(project: Project, result: CommandResult) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow(FactoryLineIds.TOOL_WINDOW)
        toolWindow?.show {
            ApplicationManager.getApplication().invokeLater {
                toolWindow.contentManager.findContent("Engineering Judgment")?.let { toolWindow.contentManager.setSelectedContent(it) }
                project.getUserData(judgmentKey)?.show(result)
            }
        }
    }
}
