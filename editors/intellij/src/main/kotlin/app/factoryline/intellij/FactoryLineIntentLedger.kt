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
 * A deliberately local, human-supervised Change List contract view.  It does
 * not query the VCS itself: selection remains in the action/controller, and
 * this panel only renders the CLI's schema-bound result.
 */
object IntentLedgerMarkers {
    const val TAB_AVAILABLE = "INTENT_LEDGER_TAB_AVAILABLE"
    const val CAPTURE_CONFIRMATION_REQUIRED = "INTENT_LEDGER_CAPTURE_CONFIRMATION_REQUIRED"
    const val READ_ONLY_INSPECTION = "INTENT_LEDGER_READ_ONLY_INSPECTION"
    const val HUMAN_REVIEW_ONLY = "INTENT_LEDGER_HUMAN_REVIEW_ONLY"
    const val UNAVAILABLE = "INTENT_LEDGER_UNAVAILABLE"
}

data class IntentLedgerSummary(
    val changeList: String,
    val state: String,
    val promise: String?,
    val nonGoal: String?,
    val failureCase: String?,
    val paths: List<String>,
    val nextAction: String?,
    val nextReason: String?,
    val recordPath: String?,
    val rawJson: String,
) {
    fun brief(): String = buildString {
        appendLine("FactoryLine Intent Ledger")
        appendLine("Change List: $changeList")
        appendLine("State: $state")
        promise?.let { appendLine("Behavioral promise: $it") }
        nonGoal?.let { appendLine("Explicit non-goal: $it") }
        failureCase?.let { appendLine("Negative case: $it") }
        appendLine("Selected paths: ${paths.size}")
        nextAction?.let { appendLine("Next action: $it") }
        nextReason?.let { appendLine("Reason: $it") }
        recordPath?.let { appendLine("Local record: $it") }
        append("Boundary: this view never edits source or a Change List, runs a test, starts an agent, or grants repair, merge, release, deployment, credential, or connector authority.")
    }

    companion object {
        fun fromJson(rawJson: String): IntentLedgerSummary? {
            val schema = JsonFields.string(rawJson, "schema") ?: return null
            val capture = schema == "factory.intent-ledger-capture.v1"
            if (!capture && schema != "factory.intent-ledger-inspection.v1") return null
            val record = JsonFields.container(rawJson, "record", '{', '}')
            val intent = record?.let { JsonFields.container(it, "intent", '{', '}') }
            val next = JsonFields.container(rawJson, "next_action", '{', '}')
            return IntentLedgerSummary(
                changeList = JsonFields.string(rawJson, "change_list") ?: record?.let { JsonFields.string(it, "change_list") } ?: return null,
                state = if (capture) "intent_captured" else JsonFields.string(rawJson, "state") ?: return null,
                promise = intent?.let { JsonFields.string(it, "promise") },
                nonGoal = intent?.let { JsonFields.string(it, "non_goal") },
                failureCase = intent?.let { JsonFields.string(it, "failure_case") },
                paths = if (capture) record?.let { JsonFields.strings(it, "declared_scope_paths") }.orEmpty() else JsonFields.strings(rawJson, "current_changed_paths"),
                nextAction = next?.let { JsonFields.string(it, "action") },
                nextReason = next?.let { JsonFields.string(it, "reason") },
                recordPath = JsonFields.string(rawJson, "record_path") ?: JsonFields.string(rawJson, "path"),
                rawJson = rawJson,
            )
        }
    }
}

class FactoryLineIntentLedgerPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Capture one behavioral contract for a selected local Change List, then inspect proof freshness without running it.")
    private val state = JLabel("UNCONTRACTED").apply { foreground = Color(0x9A, 0x67, 0x00) }
    private val summary = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = "The Intent Ledger prevents AI or teammate work from quietly changing what a Change List means. Capture is named and explicit; inspection is local and read-only."
    }
    private val raw = JBTextArea().apply { isEditable = false; lineWrap = false }
    private var latest: IntentLedgerSummary? = null

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Inspect selected Change List").apply { addActionListener { FactoryLineController.inspectIntentLedger(project) } })
            add(JButton("Capture behavioral contract").apply { addActionListener { FactoryLineController.captureIntentLedger(project) } })
            add(JButton("Copy supervision brief").apply { copyBrief() })
        }
        val header = JPanel(BorderLayout(8, 0)).apply {
            add(JLabel("Intent status:"), BorderLayout.WEST)
            add(state, BorderLayout.CENTER)
        }
        val content = JTabbedPane().apply {
            addTab("Supervision", JBScrollPane(summary))
            addTab("Raw local result", JBScrollPane(raw))
        }
        val body = JPanel(BorderLayout(0, 8)).apply {
            add(header, BorderLayout.NORTH)
            add(content, BorderLayout.CENTER)
        }
        add(controls, BorderLayout.NORTH)
        add(body, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        val parsed = if (result.exitCode == 0 && !result.timedOut) IntentLedgerSummary.fromJson(result.output) else null
        if (parsed == null) showUnavailable(result) else show(parsed)
    }

    fun show(value: IntentLedgerSummary) {
        latest = value
        state.text = value.state.uppercase().replace('_', ' ')
        state.foreground = when (value.state) {
            "ready_for_human_review", "intent_captured" -> Color(0x1B, 0x6D, 0x3A)
            "uncontracted", "coverage_incomplete", "stale_proof" -> Color(0x9A, 0x67, 0x00)
            else -> Color(0xA8, 0x2A, 0x2A)
        }
        status.text = "Intent Ledger: ${value.paths.size} selected path(s). Human review remains required."
        summary.text = value.brief()
        raw.text = value.rawJson
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    private fun showUnavailable(result: CommandResult) {
        latest = null
        state.text = "UNAVAILABLE"
        state.foreground = Color(0xA8, 0x2A, 0x2A)
        status.text = "Intent Ledger unavailable: no trusted structured result was inferred."
        summary.text = "FactoryLine could not parse a trusted Intent Ledger result. No behavioral contract, proof freshness, or readiness result was inferred.\n\n${result.output}"
        raw.text = result.output
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    private fun copyBrief() {
        val value = latest ?: run {
            status.text = "Inspect or capture a structured Intent Ledger before copying a brief."
            return
        }
        CopyPasteManager.getInstance().setContents(StringSelection(value.brief()))
        status.text = "Copied a local supervision brief. It is not a release decision."
    }
}
