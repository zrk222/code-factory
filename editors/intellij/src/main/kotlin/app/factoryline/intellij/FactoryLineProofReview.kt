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
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.datatransfer.StringSelection
import java.nio.file.Files
import java.nio.file.Path
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSplitPane
import javax.swing.JTabbedPane

/**
 * Stable markers used by the editor adapter's proof-review contract. They
 * describe local UI states; they never certify code quality or a release.
 */
object ProofReviewMarkers {
    const val TAB_AVAILABLE = "PROOF_REVIEW_TAB_AVAILABLE"
    const val CONFIRMATION_REQUIRED = "PROOF_REVIEW_CONFIRMATION_REQUIRED"
    const val ACTIVE_FILE_SCOPE = "PROOF_REVIEW_ACTIVE_FILE_SCOPE"
    const val STRUCTURED_RESULT = "PROOF_REVIEW_STRUCTURED_RESULT"
    const val UNAVAILABLE = "PROOF_REVIEW_UNAVAILABLE"
    const val PATH_NAVIGATION_BOUND = "PROOF_REVIEW_PATH_NAVIGATION_BOUND"
    const val ATTENTION_FIRST = "PROOF_REVIEW_ATTENTION_FIRST"
    const val HANDOFF_SAVED = "PROOF_REVIEW_HANDOFF_SAVED"
    const val LOCAL_SCOPE_UNION = "PROOF_REVIEW_LOCAL_SCOPE_UNION"
    const val EXPLICIT_SCOPE = "PROOF_REVIEW_EXPLICIT_SCOPE"
    const val FACTS_PRESERVED = "PROOF_REVIEW_FACTS_PRESERVED"
    const val NO_AUTONOMY = "PROOF_REVIEW_NO_AUTONOMY"

    val all = setOf(
        TAB_AVAILABLE,
        CONFIRMATION_REQUIRED,
        ACTIVE_FILE_SCOPE,
        STRUCTURED_RESULT,
        UNAVAILABLE,
        PATH_NAVIGATION_BOUND,
        ATTENTION_FIRST,
        HANDOFF_SAVED,
        LOCAL_SCOPE_UNION,
        EXPLICIT_SCOPE,
        FACTS_PRESERVED,
        NO_AUTONOMY,
    )
}

data class ProofReviewFinding(
    val severity: String,
    val kind: String,
    val message: String,
)

data class ProofReviewSummary(
    val reviewSha256: String,
    val inputSource: String,
    val changedPaths: List<String>,
    val nextAction: String,
    val nextReason: String,
    val findings: List<ProofReviewFinding>,
    val unprovenClaims: List<String>,
    val handoffArtifactPaths: List<String>,
    val rawJson: String,
) {
    val markers: Set<String>
        get() = buildSet {
            add(ProofReviewMarkers.STRUCTURED_RESULT)
            add(ProofReviewMarkers.ATTENTION_FIRST)
            add(ProofReviewMarkers.FACTS_PRESERVED)
            add(ProofReviewMarkers.NO_AUTONOMY)
            add(if (inputSource == "explicit") ProofReviewMarkers.EXPLICIT_SCOPE else ProofReviewMarkers.LOCAL_SCOPE_UNION)
            if (handoffArtifactPaths.isNotEmpty()) add(ProofReviewMarkers.HANDOFF_SAVED)
        }

    val orderedFindings: List<ProofReviewFinding>
        get() = findings.sortedWith(compareBy<ProofReviewFinding> { severityRank(it.severity) }.thenBy { it.kind })

    fun brief(): String = buildString {
        appendLine("FactoryLine Proof Review")
        appendLine("Review: $reviewSha256")
        appendLine("Scope: ${changedPaths.size} changed path(s), source=$inputSource")
        appendLine("Next action: $nextAction")
        appendLine("Reason: $nextReason")
        if (orderedFindings.isNotEmpty()) {
            appendLine("Findings:")
            orderedFindings.forEach { appendLine("- ${it.severity.uppercase()}: ${it.kind} - ${it.message}") }
        }
        if (unprovenClaims.isNotEmpty()) {
            appendLine("Unproven:")
            unprovenClaims.forEach { appendLine("- $it") }
        }
        if (handoffArtifactPaths.isNotEmpty()) {
            appendLine("Local handoff packet:")
            handoffArtifactPaths.forEach { appendLine("- $it") }
        }
        append("Boundary: analysis only; no test, edit, commit, publication, deployment, credential, or network action was performed.")
    }

    companion object {
        private const val SCHEMA = "factory.change_review.v1"

        fun fromJson(rawJson: String): ProofReviewSummary? {
            if (JsonFields.string(rawJson, "schema") != SCHEMA) return null
            val nextAction = JsonFields.container(rawJson, "next_action", '{', '}') ?: return null
            val findings = JsonFields.objects(rawJson, "findings").mapNotNull { finding ->
                val severity = JsonFields.string(finding, "severity") ?: return@mapNotNull null
                val kind = JsonFields.string(finding, "kind") ?: return@mapNotNull null
                val message = JsonFields.string(finding, "message") ?: return@mapNotNull null
                ProofReviewFinding(severity, kind, message)
            }
            val artifacts = JsonFields.container(rawJson, "artifacts", '{', '}')
            val artifactPaths = artifacts?.let { artifact ->
                JsonFields.container(artifact, "paths", '{', '}')?.let { paths ->
                    listOf("json", "markdown", "mermaid").mapNotNull { JsonFields.string(paths, it) }
                }
            }.orEmpty()
            return ProofReviewSummary(
                reviewSha256 = JsonFields.string(rawJson, "review_sha256") ?: return null,
                inputSource = JsonFields.string(rawJson, "input_source") ?: return null,
                changedPaths = JsonFields.strings(rawJson, "changed_paths"),
                nextAction = JsonFields.string(nextAction, "action") ?: return null,
                nextReason = JsonFields.string(nextAction, "reason") ?: return null,
                findings = findings,
                unprovenClaims = JsonFields.strings(rawJson, "unproven_claims"),
                handoffArtifactPaths = artifactPaths,
                rawJson = rawJson,
            )
        }

        private fun severityRank(value: String): Int = when (value.lowercase()) {
            "blocking" -> 0
            "required" -> 1
            "review" -> 2
            "info" -> 3
            else -> 4
        }
    }
}

class FactoryLineProofReviewPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Review a local diff. FactoryLine will not edit, test, commit, or send anything.")
    private val valueSummary = """
        What this solves

        - AI or teammate changes are hard to trust: review the exact local diff with a visible proof gap and next action.
        - Several tasks share one working tree: focus the active file to exclude unrelated changes.
        - Review context gets lost between people or sessions: save a local JSON, Markdown, and Mermaid handoff packet.
        - An AI suggestion might overreach: this tab never edits code, runs tests, commits, publishes, or sends project data.

        Start with Review current diff, or focus the active file. Results are local, analysis-only evidence - not a release decision.
    """.trimIndent()
    private val summary = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = "Start with Review current diff, or focus the active file. Results are local, analysis-only evidence—not a release decision."
    }
    private val raw = JBTextArea().apply { isEditable = false; lineWrap = false }
    private val pathsModel = DefaultListModel<String>()
    private val paths = JBList(pathsModel)
    private var latest: ProofReviewSummary? = null

    init {
        summary.text = valueSummary
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Review current diff").apply { addActionListener { FactoryLineController.reviewCurrentDiff(project) } })
            add(JButton("Review this file").apply { addActionListener { FactoryLineController.reviewCurrentFile(project) } })
            add(JButton("Open selected file").apply { addActionListener { openSelectedPath() } })
            add(JButton("Copy handoff brief").apply { copyBrief() })
            add(JButton("Save review handoff").apply { addActionListener { FactoryLineController.saveProofReviewHandoff(project) } })
        }
        val pathsPanel = JPanel(BorderLayout(0, 4)).apply {
            add(JLabel("Changed paths"), BorderLayout.NORTH)
            add(JBScrollPane(paths), BorderLayout.CENTER)
        }
        paths.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(event: MouseEvent) {
                if (event.clickCount == 2) openSelectedPath()
            }
        })
        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JBScrollPane(summary), pathsPanel).apply {
            resizeWeight = 0.72
        }
        val details = JTabbedPane().apply {
            addTab("Summary", split)
            addTab("Details", JBScrollPane(raw))
        }
        add(controls, BorderLayout.NORTH)
        add(details, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        val parsed = if (result.exitCode == 0 && !result.timedOut) ProofReviewSummary.fromJson(result.output) else null
        if (parsed == null) show(ProofReviewUnavailable.from(result)) else show(parsed)
    }

    fun show(value: ProofReviewSummary) {
        latest = value
        status.text = "Proof Review: ${value.changedPaths.size} path(s), ${value.orderedFindings.size} finding(s). Analysis only."
        summary.text = value.brief()
        raw.text = value.rawJson
        pathsModel.removeAllElements()
        value.changedPaths.forEach(pathsModel::addElement)
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    fun show(value: ProofReviewUnavailable) {
        latest = null
        status.text = "Proof Review unavailable: ${value.message}"
        summary.text = "Proof Review could not produce a trusted structured result.\n\n${value.message}\n\nNo pass, release decision, or proof finding was inferred."
        raw.text = value.rawOutput
        pathsModel.removeAllElements()
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    private fun openSelectedPath() {
        val selected = paths.selectedValue ?: run {
            status.text = "Choose a changed path before opening a file."
            return
        }
        val failure = ProofReviewPathNavigator.open(project, selected)
        status.text = failure ?: "Opened local changed path: $selected"
    }

    private fun copyBrief() {
        val value = latest ?: run {
            status.text = "Run a trusted structured Proof Review before copying a handoff brief."
            return
        }
        CopyPasteManager.getInstance().setContents(StringSelection(value.brief()))
        status.text = "Copied a local, analysis-only handoff brief."
    }
}

object ProofReviewPathNavigator {
    fun open(project: Project, value: String): String? {
        val root = project.basePath?.let(Path::of) ?: return "The project has no local workspace path."
        val path = WorkspacePath.resolve(root, value) ?: return "Changed path is outside the current project."
        if (!Files.isRegularFile(path)) return "Changed path is unavailable or is not a file."
        val virtualFile = LocalFileSystem.getInstance().refreshAndFindFileByNioFile(path)
            ?: return "Changed path could not be opened in the IDE."
        FileEditorManager.getInstance(project).openFile(virtualFile, true)
        return null
    }
}

data class ProofReviewUnavailable(
    val message: String,
    val rawOutput: String,
) {
    val markers: Set<String> = setOf(ProofReviewMarkers.UNAVAILABLE, ProofReviewMarkers.NO_AUTONOMY)

    companion object {
        fun from(result: CommandResult): ProofReviewUnavailable {
            val code = JsonFields.string(result.output, "code")
            val message = JsonFields.string(result.output, "message")
            val detail = listOfNotNull(code, message).joinToString(": ").ifBlank {
                when {
                    result.timedOut -> "Proof Review reached the 300 second command boundary."
                    result.exitCode != null -> "Proof Review exited ${result.exitCode}."
                    else -> "Proof Review could not start."
                }
            }
            return ProofReviewUnavailable(detail, result.output)
        }
    }
}

/** Minimal JSON reader for fixed, schema-bound FactoryLine CLI fields. */
internal object JsonFields {
    fun string(raw: String, key: String): String? {
        val keyIndex = keyIndex(raw, key) ?: return null
        val colon = raw.indexOf(':', keyIndex)
        if (colon < 0) return null
        return readQuoted(raw, raw.indexOfFirstNonWhitespace(colon + 1)).first
    }

    fun strings(raw: String, key: String): List<String> {
        val value = container(raw, key, '[', ']') ?: return emptyList()
        val result = mutableListOf<String>()
        var index = 0
        while (index < value.length) {
            if (value[index] == '"') {
                val parsed = readQuoted(value, index)
                parsed.first?.let(result::add)
                index = parsed.second
            } else {
                index += 1
            }
        }
        return result
    }

    fun number(raw: String, key: String): String? {
        val keyIndex = keyIndex(raw, key) ?: return null
        val colon = raw.indexOf(':', keyIndex)
        if (colon < 0) return null
        val start = raw.indexOfFirstNonWhitespace(colon + 1)
        if (start !in raw.indices) return null
        val end = generateSequence(start) { index -> (index + 1).takeIf { it < raw.length && raw[it].isDigit() } }
            .lastOrNull() ?: return null
        return raw.substring(start, end + 1).takeIf { it.all(Char::isDigit) }
    }

    fun objects(raw: String, key: String): List<String> {
        val value = container(raw, key, '[', ']') ?: return emptyList()
        val objects = mutableListOf<String>()
        var index = 0
        while (index < value.length) {
            if (value[index] == '{') {
                val end = matchingEnd(value, index, '{', '}') ?: return objects
                objects += value.substring(index, end + 1)
                index = end + 1
            } else {
                index += 1
            }
        }
        return objects
    }

    fun container(raw: String, key: String, open: Char, close: Char): String? {
        val keyIndex = keyIndex(raw, key) ?: return null
        val colon = raw.indexOf(':', keyIndex)
        if (colon < 0) return null
        val start = raw.indexOfFirstNonWhitespace(colon + 1)
        if (start !in raw.indices || raw[start] != open) return null
        val end = matchingEnd(raw, start, open, close) ?: return null
        return raw.substring(start + 1, end)
    }

    private fun keyIndex(raw: String, key: String): Int? =
        Regex("\\\"${Regex.escape(key)}\\\"\\s*:").find(raw)?.range?.first

    private fun String.indexOfFirstNonWhitespace(start: Int): Int {
        var index = start
        while (index < length && this[index].isWhitespace()) index += 1
        return index
    }

    private fun readQuoted(raw: String, start: Int): Pair<String?, Int> {
        if (start !in raw.indices || raw[start] != '"') return null to start
        val value = StringBuilder()
        var index = start + 1
        var escaped = false
        while (index < raw.length) {
            val character = raw[index]
            if (escaped) {
                value.append(
                    when (character) {
                        'n' -> '\n'
                        'r' -> '\r'
                        't' -> '\t'
                        else -> character
                    }
                )
                escaped = false
            } else when (character) {
                '\\' -> escaped = true
                '"' -> return value.toString() to index + 1
                else -> value.append(character)
            }
            index += 1
        }
        return null to raw.length
    }

    private fun matchingEnd(raw: String, start: Int, open: Char, close: Char): Int? {
        var depth = 0
        var quoted = false
        var escaped = false
        for (index in start until raw.length) {
            val character = raw[index]
            if (quoted) {
                if (escaped) escaped = false
                else if (character == '\\') escaped = true
                else if (character == '"') quoted = false
                continue
            }
            when (character) {
                '"' -> quoted = true
                open -> depth += 1
                close -> {
                    depth -= 1
                    if (depth == 0) return index
                }
            }
        }
        return null
    }
}
