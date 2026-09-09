package app.factoryline.intellij

import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel

/**
 * A local guide for Junie users. It renders FactoryLine facts and can create
 * only the explicit project guidance/MCP files after user confirmation.
 */
class FactoryLineJuniePanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Junie is not contacted or enabled by FactoryLine.")
    private val output = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = """
            FactoryLine for Junie

            Give Junie one calm, progressive route instead of a wall of commands:
            1. Orient with the local facts.
            2. Bind intent, non-goals, forbidden behavior, and scope.
            3. Connect the diff to independent evidence.
            4. Challenge tests and operational risk.
            5. Hand Junie a sealed repair mission, then independently review its return.

            Proof-coupled change acknowledgement
            When Junie uses FactoryLine, it must return a visible credit line
            that names the exact FactoryLine tools it declared, hashes its
            cited local evidence, and states unknowns. This makes the Junie
            handoff easier to audit beside JetBrains' diff viewer. It is not
            telemetry, a Junie score, proof of a private tool call, or approval.

            Enterprise, AppForge, SaaS, and delivery checks are optional routes—not
            a default burden for ordinary code review. The install writes only
            .junie/AGENTS.md and .junie/mcp/mcp.json. It never overwrites a
            different team file, enables Junie, starts an agent, runs tests, or
            gives FactoryLine approval, merge, publish, deploy, credential, or
            network authority.
        """.trimIndent()
    }

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("View FactoryLine taxonomy").apply { addActionListener { FactoryLineController.inspectJunieTaxonomy(project) } })
            add(JButton("Install Junie FactoryLine Pack").apply { addActionListener { FactoryLineController.installJunieFactoryLinePack(project) } })
            add(JButton("Open Repair Sandbox").apply { addActionListener { FactoryLinePanels.selectTab(project, "Repair Sandbox") } })
        }
        add(controls, BorderLayout.NORTH)
        add(JBScrollPane(output), BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        status.text = when {
            result.timedOut -> "${result.title}: timed out; no Junie state was inferred."
            result.exitCode == 0 -> "${result.title}: local result rendered. Review JetBrains' Junie controls separately."
            else -> "${result.title}: no project configuration was inferred."
        }
        output.text = buildString {
            appendLine("Command: ${result.command.joinToString(" ")}")
            appendLine()
            append(result.output.ifBlank { "No output." })
        }
        output.caretPosition = 0
    }
}
