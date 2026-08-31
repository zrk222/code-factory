package app.factoryline.intellij

import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel

/**
 * Local, evidence-only AppForge Mission Control. It renders receipts already
 * inside the project and deliberately leaves credential, device, TestFlight,
 * App Store Connect, and final-submission authority outside the IDE adapter.
 */
data class AppForgeSummary(
    val currentCount: String,
    val invalidCount: String,
    val initCount: String,
    val appReviewCount: String,
    val qualityCount: String,
    val submissionCount: String,
    val claimBoundary: String,
    val rawJson: String,
) {
    fun brief(): String = buildString {
        appendLine("AppForge Mission Control")
        appendLine("Hash-valid design receipts: $currentCount; invalid receipts: $invalidCount")
        appendLine("Mission captures: $initCount | App Review gates: $appReviewCount | Strict quality audits: $qualityCount | Submission dossiers: $submissionCount")
        appendLine()
        appendLine("Before the next App Review queue, inspect what is actually bound to this exact candidate: the user design input, storyboard, real media journeys, strict quality evidence, SaaS proof, and final dossier.")
        appendLine("A missing receipt is a visible work item, not a green guess. This can avoid preventable rework and the days-long repeat review cycles that follow it; it cannot guarantee Apple approval.")
        append("Boundary: $claimBoundary")
    }

    companion object {
        private const val SCHEMA = "factory.appforge.design-projection.v1"

        fun fromJson(rawJson: String): AppForgeSummary? {
            val root = runCatching { JsonParser.parseString(rawJson).asJsonObject }.getOrNull() ?: return null
            fun string(value: JsonObject, key: String): String? = value.get(key)?.let {
                if (it.isJsonPrimitive && it.asJsonPrimitive.isString) it.asString else null
            }
            fun count(value: JsonObject, key: String): String? = value.get(key)?.let {
                if (it.isJsonPrimitive && it.asJsonPrimitive.isNumber && it.toString().matches(Regex("0|[1-9][0-9]*"))) it.toString() else null
            }
            fun section(key: String): JsonObject? = root.get(key)?.let { if (it.isJsonObject) it.asJsonObject else null }
            if (string(root, "schema") != SCHEMA) return null
            val init = section("init") ?: return null
            val appReview = section("app_review") ?: return null
            val quality = section("quality_audit") ?: return null
            val submission = section("submission_assurance") ?: return null
            return AppForgeSummary(
                currentCount = count(root, "current_count") ?: return null,
                invalidCount = count(root, "invalid_count") ?: return null,
                initCount = count(init, "current_count") ?: return null,
                appReviewCount = count(appReview, "current_count") ?: return null,
                qualityCount = count(quality, "current_count") ?: return null,
                submissionCount = count(submission, "current_count") ?: return null,
                claimBoundary = string(root, "claim_boundary") ?: return null,
                rawJson = rawJson,
            )
        }
    }
}

class FactoryLineAppForgePanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("No AppForge receipt has been read in this project. Refresh reads only local, hash-verified status.")
    private val output = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = "AppForge helps a team inspect the candidate-specific evidence story before a repeat App Review queue. It never uploads media, accesses credentials, starts TestFlight, or submits to Apple."
    }

    init {
        add(JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Refresh local AppForge status").apply { addActionListener { FactoryLineController.inspectAppForge(project) } })
            add(JButton("Open AppForge Graph Ops").apply { addActionListener { FactoryLineController.openStudio(project, graphMode = true) } })
        }, BorderLayout.NORTH)
        add(JBScrollPane(output), BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        val summary = if (result.exitCode == 0 && !result.timedOut) AppForgeSummary.fromJson(result.output) else null
        if (summary == null) {
            status.text = "AppForge status is unavailable; no readiness was inferred."
            output.text = result.output.ifBlank { "The local AppForge status command did not produce a trusted receipt projection." }
        } else {
            status.text = "AppForge status read locally: ${summary.currentCount} design receipt(s), ${summary.submissionCount} submission dossier(s)."
            output.text = summary.brief() + "\n\nRaw local projection:\n" + summary.rawJson
        }
        output.caretPosition = 0
    }
}
