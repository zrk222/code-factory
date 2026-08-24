package app.factoryline.intellij

import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.ui.components.JBList
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.datatransfer.StringSelection
import java.nio.file.Files
import java.nio.file.Path
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSplitPane
import javax.swing.JTabbedPane

object RepairSandboxMarkers {
    const val TAB_AVAILABLE = "REPAIR_SANDBOX_TAB_AVAILABLE"
    const val SCOPE_CONFIRMATION_REQUIRED = "REPAIR_SCOPE_CONFIRMATION_REQUIRED"
    const val SCOPE_HASH_BOUND = "REPAIR_SCOPE_HASH_BOUND"
    const val SCOPE_ARTIFACTS_WRITTEN = "REPAIR_SCOPE_ARTIFACTS_WRITTEN"
    const val CANDIDATE_CONFIRMATION_REQUIRED = "REPAIR_CANDIDATE_CONFIRMATION_REQUIRED"
    const val CANDIDATE_PATCH_SCOPED = "REPAIR_CANDIDATE_PATCH_SCOPED"
    const val UNAVAILABLE = "REPAIR_SANDBOX_UNAVAILABLE"
    const val HUMAN_APPLY_REQUIRED = "REPAIR_SANDBOX_HUMAN_APPLY_REQUIRED"
}

data class RepairScopeSummary(
    val scopeSha256: String,
    val changeList: String,
    val paths: List<String>,
    val reviewSha256: String,
    val nextAction: String,
    val nextReason: String,
    val contextMeasuredBytes: String,
    val contextLimitBytes: String,
    val contextDecision: String,
    val requiredChecks: List<String>,
    val artifactPaths: List<String>,
    val rawJson: String,
) {
    fun brief(): String = buildString {
        appendLine("FactoryLine Verified Repair Sandbox")
        appendLine("Scope: $scopeSha256")
        appendLine("Change List: $changeList")
        appendLine("Sealed paths: ${paths.size}")
        appendLine("Proof review: $reviewSha256")
        appendLine("Context Budget: $contextMeasuredBytes / $contextLimitBytes bytes ($contextDecision; no token or credit estimate)")
        appendLine("Fact-derived next action: $nextAction")
        appendLine("Reason: $nextReason")
        appendLine("Required before human apply: ${requiredChecks.joinToString()}")
        append("Boundary: no candidate runner, patch application, test, commit, merge, publication, deployment, credential, or network action was performed.")
    }

    companion object {
        private const val SCHEMA = "factory.repair_scope.v1"

        fun fromJson(rawJson: String): RepairScopeSummary? {
            if (JsonFields.string(rawJson, "schema") != SCHEMA) return null
            val review = JsonFields.container(rawJson, "review", '{', '}') ?: return null
            val next = JsonFields.container(review, "next_action", '{', '}') ?: return null
            val budget = JsonFields.container(rawJson, "context_budget", '{', '}') ?: return null
            val checks = JsonFields.objects(rawJson, "required_checks").mapNotNull { JsonFields.string(it, "id") }
            val artifacts = artifactPaths(rawJson, listOf("json", "markdown", "mermaid"))
            return RepairScopeSummary(
                scopeSha256 = JsonFields.string(rawJson, "scope_sha256") ?: return null,
                changeList = JsonFields.string(rawJson, "change_list") ?: return null,
                paths = JsonFields.objects(rawJson, "paths").mapNotNull { JsonFields.string(it, "path") },
                reviewSha256 = JsonFields.string(review, "review_sha256") ?: return null,
                nextAction = JsonFields.string(next, "action") ?: return null,
                nextReason = JsonFields.string(next, "reason") ?: return null,
                contextMeasuredBytes = JsonFields.number(budget, "measured_bytes") ?: return null,
                contextLimitBytes = JsonFields.number(budget, "limit_bytes") ?: return null,
                contextDecision = JsonFields.string(budget, "decision") ?: return null,
                requiredChecks = checks,
                artifactPaths = artifacts,
                rawJson = rawJson,
            )
        }
    }
}

data class RepairCandidateSummary(
    val candidateSha256: String,
    val scopeSha256: String,
    val patchPath: String,
    val touchedPaths: List<String>,
    val artifactPaths: List<String>,
    val rawJson: String,
) {
    fun brief(): String = buildString {
        appendLine("FactoryLine Scoped Repair Candidate")
        appendLine("Candidate: $candidateSha256")
        appendLine("Scope: $scopeSha256")
        appendLine("Patch: $patchPath")
        appendLine("Touched paths: ${touchedPaths.joinToString()}")
        append("Boundary: patch paths are scoped only. Independent verifier evidence and a human IDE apply decision are still required.")
    }

    companion object {
        private const val SCHEMA = "factory.repair_candidate.v1"

        fun fromJson(rawJson: String): RepairCandidateSummary? {
            if (JsonFields.string(rawJson, "schema") != SCHEMA) return null
            val patch = JsonFields.container(rawJson, "patch", '{', '}') ?: return null
            return RepairCandidateSummary(
                candidateSha256 = JsonFields.string(rawJson, "candidate_sha256") ?: return null,
                scopeSha256 = JsonFields.string(rawJson, "scope_sha256") ?: return null,
                patchPath = JsonFields.string(patch, "path") ?: return null,
                touchedPaths = JsonFields.strings(rawJson, "touched_paths"),
                artifactPaths = artifactPaths(rawJson, listOf("json", "markdown")),
                rawJson = rawJson,
            )
        }
    }
}

private fun artifactPaths(rawJson: String, names: List<String>): List<String> {
    val artifacts = JsonFields.container(rawJson, "artifacts", '{', '}') ?: return emptyList()
    val paths = JsonFields.container(artifacts, "paths", '{', '}') ?: return emptyList()
    return names.mapNotNull { JsonFields.string(paths, it) }
}

data class RepairSandboxUnavailable(val message: String, val rawOutput: String) {
    companion object {
        fun from(result: CommandResult): RepairSandboxUnavailable {
            val detail = listOfNotNull(JsonFields.string(result.output, "code"), JsonFields.string(result.output, "message"))
                .joinToString(": ")
                .ifBlank {
                    when {
                        result.timedOut -> "Repair Sandbox reached the 300 second command boundary."
                        result.exitCode != null -> "Repair Sandbox exited ${result.exitCode}."
                        else -> "Repair Sandbox could not start."
                    }
                }
            return RepairSandboxUnavailable(detail, result.output)
        }
    }
}

class FactoryLineRepairSandboxPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Seal one Change List before a supervised repair candidate enters review.")
    private val summary = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = """
            Verified Repair Sandbox

            Select one native Change List to create a hash-bound Scope Passport. Then validate a textual candidate patch from a supervised external runner. FactoryLine verifies only that its paths remain in scope and makes the independent verifier and human apply steps explicit.

            This is designed for professional teams: unrelated work stays out of the repair context, scope drift is blocked, and applying a patch remains an IDE-owned human decision.
        """.trimIndent()
    }
    private val raw = JBTextArea().apply { isEditable = false; lineWrap = false }
    private val pathsModel = DefaultListModel<String>()
    private val paths = JBList(pathsModel)
    private var latestScope: RepairScopeSummary? = null
    private var latestCandidate: RepairCandidateSummary? = null

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Prepare Change List").apply { addActionListener { FactoryLineController.prepareRepairScope(project) } })
            add(JButton("Validate candidate patch").apply { addActionListener { FactoryLineController.validateRepairCandidate(project, latestScope) } })
            add(JButton("Open selected scope file").apply { addActionListener { openSelectedScopePath() } })
            add(JButton("Open candidate patch").apply { addActionListener { openCandidatePatch() } })
            add(JButton("Copy team brief").apply { addActionListener { copyBrief() } })
            add(JButton("Copy proof context for AI Chat").apply { addActionListener { copyAiContext() } })
            add(JButton("Copy local MCP config").apply { addActionListener { copyMcpConfig() } })
        }
        val pathsPanel = JPanel(BorderLayout(0, 4)).apply {
            add(JLabel("Sealed Change List paths"), BorderLayout.NORTH)
            add(JBScrollPane(paths), BorderLayout.CENTER)
        }
        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JBScrollPane(summary), pathsPanel).apply { resizeWeight = 0.72 }
        add(controls, BorderLayout.NORTH)
        add(JTabbedPane().apply {
            addTab("Scope", split)
            addTab("Details", JBScrollPane(raw))
        }, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        val scope = if (result.exitCode == 0 && !result.timedOut) RepairScopeSummary.fromJson(result.output) else null
        val candidate = if (result.exitCode == 0 && !result.timedOut) RepairCandidateSummary.fromJson(result.output) else null
        when {
            scope != null -> show(scope)
            candidate != null -> show(candidate)
            else -> show(RepairSandboxUnavailable.from(result))
        }
    }

    fun show(scope: RepairScopeSummary) {
        latestScope = scope
        latestCandidate = null
        status.text = "Scope sealed: ${scope.paths.size} path(s) from '${scope.changeList}'. Candidate runner and apply remain unavailable."
        summary.text = scope.brief()
        raw.text = scope.rawJson
        pathsModel.removeAllElements()
        scope.paths.forEach(pathsModel::addElement)
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    fun show(candidate: RepairCandidateSummary) {
        latestCandidate = candidate
        status.text = "Candidate patch is path-scoped: ${candidate.touchedPaths.size} path(s). Independent verifier and human apply still required."
        summary.text = candidate.brief()
        raw.text = candidate.rawJson
        pathsModel.removeAllElements()
        candidate.touchedPaths.forEach(pathsModel::addElement)
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    fun show(unavailable: RepairSandboxUnavailable) {
        status.text = "Repair Sandbox unavailable: ${unavailable.message}"
        summary.text = "Repair Sandbox could not produce a trusted scope or candidate result.\n\n${unavailable.message}\n\nNo patch is eligible to apply and no quality result was inferred."
        raw.text = unavailable.rawOutput
        pathsModel.removeAllElements()
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    private fun openSelectedScopePath() {
        val selected = paths.selectedValue ?: run {
            status.text = "Choose a sealed path before opening it."
            return
        }
        status.text = openProjectFile(project, selected) ?: "Opened local scope path: $selected"
    }

    private fun openCandidatePatch() {
        val candidate = latestCandidate ?: run {
            status.text = "Validate a trusted candidate patch before opening it."
            return
        }
        status.text = openProjectFile(project, candidate.patchPath) ?: "Opened candidate patch: ${candidate.patchPath}"
    }

    private fun copyBrief() {
        val brief = latestCandidate?.brief() ?: latestScope?.brief() ?: run {
            status.text = "Prepare a trusted scope or candidate before copying a team brief."
            return
        }
        CopyPasteManager.getInstance().setContents(StringSelection(brief))
        status.text = "Copied a local scope/candidate brief. It contains no apply authority."
    }

    private fun copyAiContext() {
        val brief = latestCandidate?.brief() ?: latestScope?.brief() ?: run {
            status.text = "Prepare a trusted scope or candidate before copying proof context."
            return
        }
        val context = buildString {
            appendLine("FactoryLine local proof context")
            appendLine("Use these facts as review context. Do not treat them as approval, production readiness, or permission to edit, run, commit, publish, deploy, or send anything.")
            appendLine()
            append(brief)
        }
        CopyPasteManager.getInstance().setContents(StringSelection(context))
        status.text = "Copied local proof context for a manual AI Chat paste. No AI service was contacted."
    }

    private fun copyMcpConfig() {
        val root = project.basePath ?: run {
            status.text = "The project has no local workspace path for an MCP configuration."
            return
        }
        val command = FactoryLineSettings.instance().executable()
        fun escaped(value: String): String = value.replace("\\", "\\\\").replace("\"", "\\\"")
        val config = """
            {
              "mcpServers": {
                "factoryline": {
                  "command": "${escaped(command)}",
                  "args": ["mcp", "serve", "--root", "${escaped(root)}"]
                }
              }
            }
        """.trimIndent()
        CopyPasteManager.getInstance().setContents(StringSelection(config))
        status.text = "Copied a local, read-only MCP configuration. Add it manually to an MCP-capable client."
    }
}

private fun openProjectFile(project: Project, value: String): String? {
    val root = project.basePath?.let(Path::of) ?: return "The project has no local workspace path."
    val path = WorkspacePath.resolve(root, value) ?: return "Path is outside the current project."
    if (!Files.isRegularFile(path)) return "Path is unavailable or is not a file."
    val virtualFile = LocalFileSystem.getInstance().refreshAndFindFileByNioFile(path)
        ?: return "Path could not be opened in the IDE."
    FileEditorManager.getInstance(project).openFile(virtualFile, true)
    return null
}
