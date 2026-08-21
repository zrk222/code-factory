package app.factoryline.intellij

import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import java.awt.BorderLayout
import java.awt.Color
import java.awt.FlowLayout
import java.awt.datatransfer.StringSelection
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTabbedPane

/**
 * A schema-bound projection of tracked Judgment Capsules. The panel is intentionally
 * inspection-only: it cannot create, promote, waive, or apply a decision.
 */
object JudgmentMarkers {
    const val TAB_AVAILABLE = "JUDGMENT_TAB_AVAILABLE"
    const val STATUS_READ_ONLY = "JUDGMENT_STATUS_READ_ONLY"
    const val SAFETY_CASE_READ_ONLY = "JUDGMENT_SAFETY_CASE_READ_ONLY"
    const val NO_EXECUTION = "JUDGMENT_NO_EXECUTION"
    const val UNAVAILABLE = "JUDGMENT_UNAVAILABLE"
}

data class JudgmentSummary(
    val schema: String,
    val state: String,
    val marker: String,
    val route: String?,
    val active: String?,
    val proposed: String?,
    val reviewDue: String?,
    val requiredReviewers: List<String>,
    val changedPaths: List<String>,
    val missingObligations: List<String>,
    val rawJson: String,
) {
    fun brief(): String = buildString {
        appendLine("FactoryLine Engineering Judgment")
        appendLine("State: $state")
        route?.let { appendLine("Safety-case route: $it") }
        active?.let { appendLine("Active capsules: $it") }
        proposed?.let { appendLine("Proposed capsules: $it") }
        reviewDue?.let { appendLine("Review due: $it") }
        if (changedPaths.isNotEmpty()) appendLine("Explicit changed paths: ${changedPaths.size}")
        if (requiredReviewers.isNotEmpty()) appendLine("Named reviewers: ${requiredReviewers.joinToString()}")
        if (missingObligations.isNotEmpty()) appendLine("Missing proof obligations: ${missingObligations.size}")
        append("Boundary: the panel reads local Capsule metadata and deterministic routing only. It cannot infer intent, promote or waive a decision, execute a repair, approve code, merge, publish, deploy, sign, message, or access credentials.")
    }

    companion object {
        fun fromJson(rawJson: String): JudgmentSummary? {
            val schema = JsonFields.string(rawJson, "schema") ?: return null
            if (schema !in setOf("factory.judgment.status.v1", "factory.judgment.safety-case.v1")) return null
            val counts = JsonFields.container(rawJson, "counts", '{', '}')
            return JudgmentSummary(
                schema = schema,
                state = JsonFields.string(rawJson, "state") ?: JsonFields.string(rawJson, "route") ?: return null,
                marker = JsonFields.string(rawJson, "marker") ?: return null,
                route = JsonFields.string(rawJson, "route"),
                active = counts?.let { JsonFields.number(it, "active") },
                proposed = counts?.let { JsonFields.number(it, "proposed") },
                reviewDue = counts?.let { JsonFields.number(it, "review_due") },
                requiredReviewers = JsonFields.strings(rawJson, "required_reviewers"),
                changedPaths = JsonFields.strings(rawJson, "changed_paths"),
                missingObligations = JsonFields.strings(rawJson, "missing_obligations"),
                rawJson = rawJson,
            )
        }
    }
}

class FactoryLineJudgmentPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Inspect repository-tracked Engineering Judgment Capsules before accepting an affected local Change List.")
    private val state = JLabel("UNINSPECTED").apply { foreground = Color(0x9A, 0x67, 0x00) }
    private val summary = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = "A Capsule has a named owner, explicit scope, review date, and declared proof obligations. This panel only renders local, schema-bound results."
    }
    private val raw = JBTextArea().apply { isEditable = false; lineWrap = false }
    private var latest: JudgmentSummary? = null

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Inspect decisions").apply { addActionListener { FactoryLineController.inspectJudgment(project) } })
            add(JButton("Safety-case selected Change List").apply { addActionListener { FactoryLineController.inspectJudgmentSafetyCase(project) } })
            add(JButton("Copy review brief").apply { copyBrief() })
        }
        val header = JPanel(BorderLayout(8, 0)).apply {
            add(JLabel("Judgment status:"), BorderLayout.WEST)
            add(state, BorderLayout.CENTER)
        }
        val content = JTabbedPane().apply {
            addTab("Safety case", JBScrollPane(summary))
            addTab("Raw local result", JBScrollPane(raw))
        }
        add(controls, BorderLayout.NORTH)
        add(JPanel(BorderLayout(0, 8)).apply { add(header, BorderLayout.NORTH); add(content, BorderLayout.CENTER) }, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        val parsed = if (result.exitCode == 0 && !result.timedOut) JudgmentSummary.fromJson(result.output) else null
        if (parsed == null) showUnavailable(result) else show(parsed)
    }

    fun show(value: JudgmentSummary) {
        latest = value
        state.text = (value.route ?: value.state).uppercase()
        state.foreground = when (value.route ?: value.state) {
            "GREEN", "valid" -> Color(0x1B, 0x6D, 0x3A)
            "AMBER", "empty" -> Color(0x9A, 0x67, 0x00)
            else -> Color(0xA8, 0x2A, 0x2A)
        }
        status.text = when (value.route) {
            "RED" -> "Safety Case: declared proof is missing or invalid. A named owner must resolve it."
            "AMBER" -> "Safety Case: exact declared proof is bound; named owner review remains required."
            "GREEN" -> "Safety Case: no active tracked Capsule matched. This is not approval or production readiness."
            else -> "Engineering Judgment status is local and read-only. Human promotion and review remain required."
        }
        summary.text = value.brief()
        raw.text = value.rawJson
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    private fun showUnavailable(result: CommandResult) {
        latest = null
        state.text = "UNAVAILABLE"
        state.foreground = Color(0xA8, 0x2A, 0x2A)
        status.text = "Engineering Judgment unavailable: no trusted structured result was inferred."
        summary.text = "FactoryLine could not parse a trusted Judgment Capsule result. No decision, proof, or readiness conclusion was inferred.\n\n${result.output}"
        raw.text = result.output
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    private fun copyBrief() {
        val value = latest ?: run {
            status.text = "Inspect the tracked decision state or an explicit Change List safety case before copying a brief."
            return
        }
        CopyPasteManager.getInstance().setContents(StringSelection(value.brief()))
        status.text = "Copied a local judgment brief. It is not an approval, release, or execution decision."
    }
}
