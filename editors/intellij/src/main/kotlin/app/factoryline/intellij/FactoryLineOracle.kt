package app.factoryline.intellij

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel

/**
 * Read-only supervision for the Oracle Firewall. This panel deliberately
 * cannot seal intent, approve a change, run an implementation, or authorize
 * a release. It makes the independent evidence chain visible in the IDE.
 */
data class OracleFirewallSummary(
    val contracts: String,
    val blockedDrifts: String,
    val challenges: String,
    val incidents: String,
    val invalid: String,
    val claimBoundary: String,
    val rawJson: String,
) {
    fun brief(): String = buildString {
        appendLine("Oracle Firewall Supervision")
        appendLine("Sealed contracts: $contracts | blocked oracle weakenings: $blockedDrifts")
        appendLine("Independent implementation challenges: $challenges | agent incidents: $incidents | invalid artifacts: $invalid")
        appendLine()
        appendLine("Evidence path: source -> approved obligation -> forbidden behavior -> gate -> test -> evidence -> decision.")
        appendLine("Only a human-confirmed or trusted-source rule may block or release work. Agent-proposed rules remain advisory until separately approved.")
        appendLine("A threshold relaxation, deleted negative case, new exception, or reclassified defect is surfaced as E_ORACLE_WEAKENING for human review.")
        append("Boundary: $claimBoundary")
    }

    companion object {
        private const val SCHEMA = "factory.oracle-firewall-projection.v1"

        fun fromJson(rawJson: String): OracleFirewallSummary? {
            val root = runCatching { JsonParser.parseString(rawJson).asJsonObject }.getOrNull() ?: return null
            fun string(value: JsonObject, key: String): String? = value.get(key)?.let {
                if (it.isJsonPrimitive && it.asJsonPrimitive.isString) it.asString else null
            }
            fun count(key: String): String? = root.get(key)?.let {
                if (it.isJsonPrimitive && it.asJsonPrimitive.isNumber && it.toString().matches(Regex("0|[1-9][0-9]*"))) it.toString() else null
            }
            if (string(root, "schema") != SCHEMA) return null
            return OracleFirewallSummary(
                contracts = count("contract_count") ?: return null,
                blockedDrifts = count("blocked_drift_count") ?: return null,
                challenges = count("challenge_count") ?: return null,
                incidents = count("incident_count") ?: return null,
                invalid = count("invalid_count") ?: return null,
                claimBoundary = string(root, "claim_boundary") ?: return null,
                rawJson = rawJson,
            )
        }
    }
}

class FactoryLineOraclePanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("No Oracle Firewall projection has been read. Refresh only reads local hash-verified artifacts.")
    private val output = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = "Use Oracle Firewall supervision to inspect whether the worker is being held to a sealed, source-bound intent contract. It never approves intent, changes a gate, writes code, or releases work."
    }

    init {
        add(JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Refresh Oracle Firewall").apply { addActionListener { FactoryLineController.inspectOracleFirewall(project) } })
            add(JButton("Open Oracle Graph Ops").apply { addActionListener { FactoryLineController.openStudio(project, graphMode = true) } })
        }, BorderLayout.NORTH)
        add(JBScrollPane(output), BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        val summary = if (result.exitCode == 0 && !result.timedOut) OracleFirewallSummary.fromJson(result.output) else null
        if (summary == null) {
            status.text = "Oracle Firewall status is unavailable; no approval or release readiness was inferred."
            output.text = result.output.ifBlank { "The local Oracle Firewall command did not produce a trusted projection." }
        } else {
            status.text = "Oracle Firewall read locally: ${summary.contracts} contract(s), ${summary.blockedDrifts} blocked weakening(s)."
            output.text = summary.brief() + "\n\nRaw local projection:\n" + summary.rawJson
        }
        output.caretPosition = 0
    }
}
