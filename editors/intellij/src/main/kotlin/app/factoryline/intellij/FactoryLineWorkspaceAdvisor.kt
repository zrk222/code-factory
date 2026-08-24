package app.factoryline.intellij

import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.datatransfer.StringSelection
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTabbedPane

object WorkspaceAdvisorMarkers {
    const val TAB_AVAILABLE = "WORKSPACE_ADVISOR_TAB_AVAILABLE"
    const val LOCAL_ONLY = "WORKSPACE_ADVISOR_LOCAL_ONLY"
    const val IDE_MUTATION_DENIED = "WORKSPACE_ADVISOR_IDE_MUTATION_DENIED"
    const val REMOTE_CONNECTION_DENIED = "WORKSPACE_ADVISOR_REMOTE_CONNECTION_DENIED"
    const val CONFIRMATION_REQUIRED = "WORKSPACE_ADVISOR_CONFIRMATION_REQUIRED"
    const val UNAVAILABLE = "WORKSPACE_ADVISOR_UNAVAILABLE"
}

data class WorkspaceAdvisorRecommendation(
    val id: String,
    val priority: String,
    val state: String,
    val action: String,
    val boundary: String,
)

data class WorkspaceAdvisorSummary(
    val workspaceName: String,
    val pathClassification: String,
    val ecosystems: List<String>,
    val filesScanned: String,
    val bytesScanned: String,
    val scanLimited: String,
    val recommendations: List<WorkspaceAdvisorRecommendation>,
    val rawJson: String,
) {
    fun brief(): String = buildString {
        appendLine("FactoryLine Workspace Load Advisor")
        appendLine("Workspace: $workspaceName ($pathClassification)")
        appendLine("Measured local shape: $filesScanned files, $bytesScanned bytes; scan limited: $scanLimited")
        appendLine("Detected ecosystems: ${ecosystems.ifEmpty { listOf("none") }.joinToString()}")
        appendLine()
        appendLine("Manual review paths")
        recommendations.forEach { recommendation ->
            appendLine("- [${recommendation.priority}] ${recommendation.action}")
            appendLine("  Boundary: ${recommendation.boundary}")
        }
        append("Boundary: this is a local filesystem measurement, not an IDE heap, GC, freeze, indexing, or remote-connectivity diagnosis. It changes no IDE settings, caches, indexes, inspections, plugins, files, or credentials.")
    }

    companion object {
        private const val SCHEMA = "factory.workspace_advisor.v1"

        fun fromJson(rawJson: String): WorkspaceAdvisorSummary? {
            if (JsonFields.string(rawJson, "schema") != SCHEMA) return null
            val workspace = JsonFields.container(rawJson, "workspace", '{', '}') ?: return null
            val scan = JsonFields.container(rawJson, "scan", '{', '}') ?: return null
            val recommendations = JsonFields.objects(rawJson, "recommendations").mapNotNull { value ->
                WorkspaceAdvisorRecommendation(
                    id = JsonFields.string(value, "id") ?: return@mapNotNull null,
                    priority = JsonFields.string(value, "priority") ?: return@mapNotNull null,
                    state = JsonFields.string(value, "state") ?: return@mapNotNull null,
                    action = JsonFields.string(value, "action") ?: return@mapNotNull null,
                    boundary = JsonFields.string(value, "boundary") ?: return@mapNotNull null,
                )
            }
            return WorkspaceAdvisorSummary(
                workspaceName = JsonFields.string(workspace, "name") ?: return null,
                pathClassification = JsonFields.string(workspace, "path_classification") ?: return null,
                ecosystems = JsonFields.strings(workspace, "ecosystems"),
                filesScanned = JsonFields.number(scan, "files_scanned") ?: return null,
                bytesScanned = JsonFields.number(scan, "bytes_scanned") ?: return null,
                scanLimited = JsonFields.boolean(scan, "scan_limited") ?: "unavailable",
                recommendations = recommendations,
                rawJson = rawJson,
            )
        }
    }
}

data class WorkspaceAdvisorUnavailable(val message: String, val rawOutput: String) {
    companion object {
        fun from(result: CommandResult): WorkspaceAdvisorUnavailable {
            val detail = listOfNotNull(JsonFields.string(result.output, "code"), JsonFields.string(result.output, "message"))
                .joinToString(": ")
                .ifBlank {
                    when {
                        result.timedOut -> "Workspace Advisor reached the 300 second command boundary."
                        result.exitCode != null -> "Workspace Advisor exited ${result.exitCode}."
                        else -> "Workspace Advisor could not start."
                    }
                }
            return WorkspaceAdvisorUnavailable(detail, result.output)
        }
    }
}

class FactoryLineWorkspaceAdvisorPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Measure workspace shape before manually changing indexing, remote, or performance settings.")
    private val summary = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = """
            Workspace Load Advisor + Remote/WSL Preflight

            Measure the local workspace shape, generated/dependency directory signals, and path-only Remote/WSL context. Use the result to decide what to review in your JetBrains IDE.

            FactoryLine never changes heap settings, caches, indexing, inspections, plugins, project files, remote paths, credentials, or network state. It also does not claim to diagnose an IDE freeze or performance issue.
        """.trimIndent()
    }
    private val raw = JBTextArea().apply { isEditable = false; lineWrap = false }
    private var latest: WorkspaceAdvisorSummary? = null

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Analyze workspace").apply { addActionListener { FactoryLineController.analyzeWorkspaceAdvisor(project) } })
            add(JButton("Save local report").apply { addActionListener { FactoryLineController.saveWorkspaceAdvisorReport(project) } })
            add(JButton("Copy diagnostic brief").apply { addActionListener { copyBrief() } })
        }
        add(controls, BorderLayout.NORTH)
        add(JTabbedPane().apply {
            addTab("Advisor", JBScrollPane(summary))
            addTab("Details", JBScrollPane(raw))
        }, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        val parsed = if (result.exitCode == 0 && !result.timedOut) WorkspaceAdvisorSummary.fromJson(result.output) else null
        if (parsed == null) show(WorkspaceAdvisorUnavailable.from(result)) else show(parsed)
    }

    fun show(value: WorkspaceAdvisorSummary) {
        latest = value
        status.text = "${WorkspaceAdvisorMarkers.CONFIRMATION_REQUIRED}: observed ${value.filesScanned} files / ${value.bytesScanned} bytes (${value.pathClassification}). Manual review only."
        summary.text = value.brief()
        raw.text = value.rawJson
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    fun show(value: WorkspaceAdvisorUnavailable) {
        latest = null
        status.text = "Workspace Advisor unavailable: ${value.message}"
        summary.text = "Workspace Advisor could not produce a trusted structured result.\n\n${value.message}\n\nNo performance conclusion or configuration recommendation was inferred."
        raw.text = value.rawOutput
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    private fun copyBrief() {
        val value = latest ?: run {
            status.text = "Analyze the workspace before copying a local diagnostic brief."
            return
        }
        CopyPasteManager.getInstance().setContents(StringSelection(value.brief()))
        status.text = "Copied a local measurement brief. No AI service or remote host was contacted."
    }
}
