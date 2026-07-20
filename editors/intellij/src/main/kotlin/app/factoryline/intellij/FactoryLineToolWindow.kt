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
        val panel = FactoryLinePanel(project)
        project.putUserData(FactoryLinePanels.key, panel)
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(panel, "Receipts", false)
        )
    }
}

class FactoryLinePanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Run a FactoryLine action to inspect local output and receipts.")
    private val output = JBTextArea().apply {
        isEditable = false
        lineWrap = false
        text = "FactoryLine keeps the proof loop local. Command actions require explicit workspace confirmation."
    }

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Run assembly").apply { addActionListener { FactoryLineController.requestFeature(project, FactoryLineOperation.ASSEMBLE) } })
            add(JButton("Verify receipts").apply { addActionListener { FactoryLineController.requestFeature(project, FactoryLineOperation.VERIFY) } })
            add(JButton("Analyze changed proof").apply { addActionListener { FactoryLineController.analyzeChangedProof(project) } })
            add(JButton("Open local meter").apply { addActionListener { FactoryLineController.openMeter(project) } })
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
}

object FactoryLinePanels {
    val key: Key<FactoryLinePanel> = Key.create("app.factoryline.intellij.panel")

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
}
