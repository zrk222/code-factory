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

object IndexContinuityMarkers {
    const val TAB_AVAILABLE = "INDEX_CONTINUITY_TAB_AVAILABLE"
    const val LOCAL_STRUCTURAL_ONLY = "INDEX_CONTINUITY_LOCAL_STRUCTURAL_ONLY"
    const val EXPLICIT_BASELINE_WRITE = "INDEX_CONTINUITY_ARTIFACT_EXPLICIT"
    const val NO_IDE_MUTATION = "INDEX_CONTINUITY_NO_IDE_MUTATION"
    const val NO_DURATION_PREDICTION = "INDEX_CONTINUITY_NO_DURATION_PREDICTION"
}

data class IndexContinuitySummary(
    val reviewScope: String,
    val recommendation: String,
    val changes: List<String>,
    val baselinePath: String?,
    val rawJson: String,
) {
    fun brief(): String = buildString {
        appendLine("FactoryLine Index Continuity Guard")
        appendLine("Review scope: $reviewScope")
        baselinePath?.let { appendLine("Baseline: $it") }
        appendLine("Next step: $recommendation")
        if (changes.isNotEmpty()) {
            appendLine("Observed structural changes:")
            changes.forEach { appendLine("- $it") }
        }
        append("Boundary: this compares local workspace structure only. It does not inspect or repair an IDE index, mutate caches or settings, or predict reindexing duration.")
    }

    companion object {
        fun fromJson(rawJson: String): IndexContinuitySummary? {
            val schema = JsonFields.string(rawJson, "schema")
            return when (schema) {
                "factory.index_continuity.v1" -> IndexContinuitySummary(
                    reviewScope = JsonFields.string(rawJson, "review_scope") ?: return null,
                    recommendation = JsonFields.string(rawJson, "recommendation") ?: return null,
                    changes = JsonFields.objects(rawJson, "changes").mapNotNull { JsonFields.string(it, "kind") },
                    baselinePath = JsonFields.container(rawJson, "baseline", '{', '}')?.let { JsonFields.string(it, "path") },
                    rawJson = rawJson,
                )
                "factory.index_continuity_baseline.v1" -> IndexContinuitySummary(
                    reviewScope = "baseline captured",
                    recommendation = "Run Compare baseline after a project-model or index symptom appears.",
                    changes = emptyList(),
                    baselinePath = JsonFields.string(rawJson, "baseline_path"),
                    rawJson = rawJson,
                )
                else -> null
            }
        }
    }
}

class FactoryLineIndexContinuityPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Capture a baseline before a project model changes; compare it when an index symptom appears.")
    private val summary = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = """
            Index Continuity Guard

            Capture a local structural baseline for this workspace. Later, compare it to see whether build manifests, source roots, managed generated/dependency directories, or local path classification changed.

            The guard points to the exact drift to review. It cannot see a JetBrains index, decide an index is corrupt, or tell you how long a reindex will take. FactoryLine never changes a cache or project setting.
        """.trimIndent()
    }
    private val raw = JBTextArea().apply { isEditable = false; lineWrap = false }
    private var latest: IndexContinuitySummary? = null

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Capture baseline").apply { addActionListener { FactoryLineController.captureIndexContinuityBaseline(project) } })
            add(JButton("Compare baseline").apply { addActionListener { FactoryLineController.compareIndexContinuityBaseline(project) } })
            add(JButton("Copy continuity brief").apply { addActionListener { copy() } })
        }
        add(controls, BorderLayout.NORTH)
        add(JTabbedPane().apply {
            addTab("Continuity", JBScrollPane(summary))
            addTab("Details", JBScrollPane(raw))
        }, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        val parsed = if (result.exitCode == 0 && !result.timedOut) IndexContinuitySummary.fromJson(result.output) else null
        if (parsed == null) {
            latest = null
            status.text = "Index Continuity Guard unavailable. No structural conclusion was inferred."
            summary.text = "The Guard did not return a trusted structured result.\n\n${result.output}"
            raw.text = result.output
        } else {
            latest = parsed
            status.text = "${parsed.reviewScope}: local structural evidence only; no IDE configuration changed."
            summary.text = parsed.brief()
            raw.text = parsed.rawJson
        }
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    private fun copy() {
        val value = latest ?: run {
            status.text = "Capture or compare a baseline before copying a continuity brief."
            return
        }
        CopyPasteManager.getInstance().setContents(StringSelection(value.brief()))
        status.text = "Copied a local continuity brief. No project content or IDE index data was included."
    }
}
