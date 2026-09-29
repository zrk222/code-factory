package app.factoryline.intellij

import com.google.gson.JsonParser
import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.process.CapturingProcessHandler
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.nio.file.Path
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel

/** Explicit local observations for a JetBrains project; never a release decision. */
class FactoryLineAuditPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private data class Lane(val label: String, val executable: String, val args: List<String>, val limit: String)

    private val lanes = listOf(
        Lane("CF change review", "factory", listOf("change", "review"), "Pattern and guard-path checks require .factory/review-audits.json; tests are not executed."),
        Lane("CF architecture health", "factory", listOf("architecture", "health"), "Configured architecture budgets; not runtime verification."),
        Lane("CF security patterns", "factory", listOf("audit", "security"), "Bounded Python static analysis; not a penetration test or multilingual scan."),
        Lane("CF runtime readiness", "factory", listOf("runtime-audit", "status"), "Existing readiness evidence; runtime tests are not executed."),
        Lane("ForgeLine repository inventory", "forge", listOf("qa", "--repo-wide"), "Static repository inventory; not a feature-scoped release gate."),
    )
    private val status = JLabel("NOT_RUN · Local project audit. Candidate binding: UNBOUND.")
    private val output = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = "Run the five bounded local lanes to see CF and ForgeLine evidence and each lane's limits. Results do not approve or certify code."
    }

    init {
        add(JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(JButton("Run CF + ForgeLine").apply { addActionListener { runAudit() } })
        }, BorderLayout.NORTH)
        add(JBScrollPane(output), BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    private fun runAudit() {
        val forgeExecutable = FactoryLineSettings.instance().forgeExecutable()
        if (forgeExecutable == null) {
            status.text = "BLOCKED · ForgeLine executable is not configured."
            output.text = "Set an absolute, executable ForgeLine path in Settings | Tools | FactoryLine. The combined audit never searches PATH."
            return
        }
        if (!FactoryLineExecutionConfirmation.confirm(
                project,
                "Run CF and ForgeLine evidence",
                "ForgeLine executable resolved to:\n$forgeExecutable",
            )
        ) return
        val root = project.basePath?.let(Path::of) ?: return
        status.text = "Running local audits · Candidate binding: UNBOUND."
        output.text = ""
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "FactoryLine: CF + ForgeLine", true) {
            private val results = mutableListOf<String>()
            override fun run(indicator: ProgressIndicator) {
                for (lane in lanes) {
                    if (indicator.isCanceled) break
                    indicator.text = lane.label
                    val executable = if (lane.executable == "factory") FactoryLineSettings.instance().executable() else forgeExecutable.toString()
                    val args = lane.args + listOf("--root", root.toString()) + if (lane.executable == "factory") listOf("--json") else emptyList()
                    val result = try {
                        val process = CapturingProcessHandler(GeneralCommandLine(executable).withParameters(args).withWorkDirectory(root.toFile()))
                            .runProcess(120_000)
                        val report = runCatching { JsonParser.parseString(process.stdout.trim()).asJsonObject }.getOrNull()
                        val fields = listOf("state", "verdict", "status", "grade", "passed").mapNotNull { key ->
                            report?.get(key)?.let { "$key=${it.toString().take(80)}" }
                        }
                        val state = when {
                            process.isTimeout -> "TIMEOUT"
                            report == null -> "INCOMPLETE"
                            process.exitCode == 0 -> "OBSERVED"
                            else -> "FAILED"
                        }
                        "$state${if (fields.isNotEmpty()) " · ${fields.joinToString(", ")}" else ""}${if (report == null) " · ${OutputRedactor.redact(process.stderr.take(240))}" else ""}"
                    } catch (error: Exception) {
                        "UNAVAILABLE · ${OutputRedactor.redact(error.message ?: "Unable to start command")}"
                    }
                    results.add("${lane.label}: $result\nLimit: ${lane.limit}")
                }
            }
            override fun onSuccess() {
                val complete = results.size == lanes.size
                status.text = "${if (complete) "Collected" else "CANCELLED"} · Candidate binding: UNBOUND · Results can become stale after edits."
                output.text = (results + lanes.drop(results.size).map { "${it.label}: NOT_RUN\nLimit: ${it.limit}" } +
                    "These observations do not approve a release. Run candidate-bound gates and independent specialty AI review separately.").joinToString("\n\n")
                output.caretPosition = 0
            }
            override fun onCancel() = onSuccess()
        })
    }
}
