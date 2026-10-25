package app.factoryline.intellij

import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.google.gson.JsonParser
import com.intellij.ui.components.JBList
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.ui.components.JBTextField
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
import javax.swing.BoxLayout

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
        append("Boundary: this scope record grants no repair, apply, commit, merge, publication, deployment, credential, or network authority. Repair requires a separate exact-candidate approval.")
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

data class RepairApprovalSummary(
    val approvalSha256: String,
    val path: String,
    val state: String,
    val rawJson: String,
) {
    companion object {
        private val digest = Regex("[a-f0-9]{64}")

        fun fromJson(rawJson: String): RepairApprovalSummary? = runCatching {
            val json = JsonParser.parseString(rawJson).asJsonObject
            val hash = json.get("approval_sha256")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: return null
            val path = json.get("path")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: return null
            val state = json.get("state")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: return null
            if (json.entrySet().map { it.key }.toSet() != setOf("approval_sha256", "path", "state") ||
                !digest.matches(hash) || state != "APPROVED_NOT_EXECUTED" || path != ".factory/repair-approvals/$hash.json") return null
            RepairApprovalSummary(hash, path, state, rawJson)
        }.getOrNull()
    }
}

data class RepairAttemptSummary(
    val approvalSha256: String,
    val attemptPath: String,
    val status: String,
    val phase: String,
    val cleanupConfirmed: Boolean,
    val primaryCheckoutUnchanged: Boolean,
    val errorCode: String?,
    val rawJson: String,
) {
    val verified: Boolean
        get() = status == "VERIFIED" && phase == "VERIFIED" && cleanupConfirmed && primaryCheckoutUnchanged

    companion object {
        private val digest = Regex("[a-f0-9]{64}")

        fun fromJson(rawJson: String, expectedApprovalSha256: String): RepairAttemptSummary? = runCatching {
            val json = JsonParser.parseString(rawJson).asJsonObject
            fun string(name: String) = json.get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            fun nullableDigest(name: String): String? {
                val value = json.get(name) ?: return null
                if (value.isJsonNull) return null
                return value.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
                    ?.asString?.takeIf { digest.matches(it) }
                    ?: throw IllegalArgumentException("invalid $name")
            }
            fun nullableSequence(name: String): Long? {
                val value = json.get(name) ?: return null
                if (value.isJsonNull) return null
                val primitive = value.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
                    ?.asJsonPrimitive ?: throw IllegalArgumentException("invalid $name")
                val text = primitive.asString
                if (!Regex("0|[1-9][0-9]*").matches(text)) throw IllegalArgumentException("invalid $name")
                val sequence = text.toLongOrNull() ?: throw IllegalArgumentException("invalid $name")
                if (sequence !in 1L..100_000L) throw IllegalArgumentException("invalid $name")
                return sequence
            }
            fun boolean(name: String): Boolean? {
                val value = json.get(name) ?: return null
                if (value.isJsonNull) return false
                return value.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
            }
            val hash = string("approval_sha256") ?: return null
            val path = string("attempt_path") ?: return null
            val status = string("status") ?: return null
            val phase = string("phase") ?: return null
            val cleanup = boolean("cleanup_confirmed") ?: return null
            val unchanged = boolean("primary_checkout_unchanged") ?: return null
            val origin = json.get("origin_audit") ?: return null
            var originCandidate: String? = null
            if (!origin.isJsonNull) {
                val binding = origin.takeIf { it.isJsonObject }?.asJsonObject
                    ?: return null
                val fields = setOf("run_id", "candidate_sha256", "manifest_sha256", "event_sha256", "sequence")
                if (binding.entrySet().map { it.key }.toSet() != fields) return null
                val runId = binding.get("run_id")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                    ?: return null
                if (runId.isBlank() || runId.length > 128) return null
                for (field in listOf("candidate_sha256", "manifest_sha256", "event_sha256")) {
                    val value = binding.get(field)
                    if (value == null || !value.isJsonPrimitive || !value.asJsonPrimitive.isString ||
                        !digest.matches(value.asString)) return null
                }
                originCandidate = binding.get("candidate_sha256").asString
                val originSequence = binding.get("sequence")
                    ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asJsonPrimitive?.asString
                    ?: return null
                if (!Regex("0|[1-9][0-9]*").matches(originSequence) || originSequence.toLongOrNull() == null) return null
            }
            val candidateBefore = nullableDigest("candidate_before_sha256")
            val candidateAfter = nullableDigest("candidate_after_sha256")
            val eventSequence = nullableSequence("event_sequence")
            val eventDigest = nullableDigest("event_sha256")
            if ((candidateBefore != null && candidateBefore != originCandidate) ||
                (candidateAfter != null && candidateBefore == null) ||
                ((eventSequence == null) != (eventDigest == null))) return null
            if (json.get("checks")?.isJsonArray != true) return null
            val error = json.get("error") ?: return null
            if (!error.isJsonNull && !error.isJsonObject) return null
            if (json.entrySet().map { it.key }.toSet() != setOf(
                    "schema", "attempt_path", "approval_sha256", "status", "state", "phase",
                    "cleanup_confirmed", "primary_checkout_unchanged", "origin_audit",
                    "candidate_before_sha256", "candidate_after_sha256", "event_sequence",
                    "event_sha256", "checks", "error",
                ) || string("schema") != "factory.repair_attempt.v1" || string("state") != status ||
                !digest.matches(hash) || hash != expectedApprovalSha256 ||
                path != ".factory/repair-attempts/$hash/state.json" ||
                status !in setOf("VERIFIED", "FAILED", "STOPPED")) return null
            if (status == "VERIFIED" &&
                (eventSequence == null || eventDigest == null ||
                    (!origin.isJsonNull && (candidateBefore == null || candidateAfter == null || candidateBefore != originCandidate)))) return null
            val code = error.takeIf { it.isJsonObject }?.asJsonObject?.get("code")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            RepairAttemptSummary(hash, path, status, phase, cleanup, unchanged, code, rawJson)
        }.getOrNull()
    }
}

data class RepairApprovalActionSummary(val approvalSha256: String, val state: String) {
    companion object {
        fun fromJson(rawJson: String, expectedHash: String, expectedState: String): RepairApprovalActionSummary? = runCatching {
            val json = JsonParser.parseString(rawJson).asJsonObject
            val hash = json.get("approval_sha256")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString ?: return null
            val state = json.get("state")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString ?: return null
            if (json.entrySet().map { it.key }.toSet() != setOf("approval_sha256", "state") ||
                hash != expectedHash || state != expectedState) return null
            RepairApprovalActionSummary(hash, state)
        }.getOrNull()
    }
}

data class RepairApprovalRequestToken(val id: Long, val scopeSha256: String, val candidateSha256: String)

internal class RepairSandboxActionState {
    enum class Attempt { NONE, READY, RUNNING, UNKNOWN, CONSUMED, STOP_REQUESTED }

    var selectedScopeSha256: String? = null
        private set
    var selectedCandidateSha256: String? = null
        private set
    var approvalSha256: String? = null
        private set
    var approvedScopeSha256: String? = null
        private set
    var approvedCandidateSha256: String? = null
        private set
    var attempt: Attempt = Attempt.NONE
        private set
    var pendingApproval: RepairApprovalRequestToken? = null
        private set
    var orphanApprovalSha256: String? = null
        private set
    private val invalidatedRequests = mutableSetOf<Long>()
    private var nextRequestId = 0L
    val approvalRequestInFlight: Boolean
        get() = pendingApproval != null || invalidatedRequests.isNotEmpty()

    fun selectScope(scopeSha256: String?) {
        selectedScopeSha256 = scopeSha256
        selectedCandidateSha256 = null
        pendingApproval?.let { invalidatedRequests += it.id }
        pendingApproval = null
    }

    fun selectCandidate(scopeSha256: String, candidateSha256: String) {
        if (scopeSha256 != selectedScopeSha256) {
            selectedCandidateSha256 = null
            pendingApproval?.let { invalidatedRequests += it.id }
            pendingApproval = null
            return
        }
        if (selectedCandidateSha256 != candidateSha256) {
            pendingApproval?.let { invalidatedRequests += it.id }
            pendingApproval = null
        }
        selectedCandidateSha256 = candidateSha256
    }

    fun beginApproval(): RepairApprovalRequestToken? {
        val scope = selectedScopeSha256 ?: return null
        val candidate = selectedCandidateSha256 ?: return null
        if (pendingApproval != null || invalidatedRequests.isNotEmpty() || orphanApprovalSha256 != null ||
            attempt in setOf(Attempt.READY, Attempt.RUNNING, Attempt.UNKNOWN, Attempt.STOP_REQUESTED)) return null
        return RepairApprovalRequestToken(++nextRequestId, scope, candidate).also { pendingApproval = it }
    }

    fun completeApproval(token: RepairApprovalRequestToken, approvalHash: String?): Boolean {
        if (pendingApproval != token) {
            if (invalidatedRequests.remove(token.id)) orphanApprovalSha256 = approvalHash
            return false
        }
        pendingApproval = null
        if (approvalHash == null) return false
        if (selectedScopeSha256 != token.scopeSha256 || selectedCandidateSha256 != token.candidateSha256) {
            orphanApprovalSha256 = approvalHash
            return false
        }
        approvalSha256 = approvalHash
        approvedScopeSha256 = token.scopeSha256
        approvedCandidateSha256 = token.candidateSha256
        attempt = Attempt.READY
        return true
    }

    fun cancelApproval(token: RepairApprovalRequestToken) {
        if (pendingApproval == token) pendingApproval = null
        invalidatedRequests.remove(token.id)
    }

    fun canRun(): Boolean = approvalSha256 != null && selectedScopeSha256 == approvedScopeSha256 &&
        selectedCandidateSha256 == approvedCandidateSha256 && attempt == Attempt.READY

    fun beginRun(): Boolean {
        if (!canRun()) return false
        attempt = Attempt.RUNNING
        return true
    }

    fun finishRun(approvalHash: String, resultKnown: Boolean) {
        if (approvalHash != approvalSha256 || attempt !in setOf(Attempt.RUNNING, Attempt.STOP_REQUESTED)) return
        attempt = if (resultKnown) Attempt.CONSUMED else Attempt.UNKNOWN
    }

    fun stopResponse(approvalHash: String, succeeded: Boolean) {
        if (approvalHash != approvalSha256 || attempt !in setOf(Attempt.RUNNING, Attempt.UNKNOWN, Attempt.STOP_REQUESTED)) return
        if (succeeded) attempt = Attempt.STOP_REQUESTED
        // A failed stop preserves the current active/unknown state so recovery remains available.
    }

    fun revoke(approvalHash: String, succeeded: Boolean) {
        if (approvalHash == orphanApprovalSha256 && succeeded) {
            orphanApprovalSha256 = null
            return
        }
        if (approvalHash != approvalSha256 || !succeeded || attempt in setOf(Attempt.RUNNING, Attempt.UNKNOWN, Attempt.STOP_REQUESTED)) return
        approvalSha256 = null
        approvedScopeSha256 = null
        approvedCandidateSha256 = null
        attempt = Attempt.NONE
    }

    fun canStop(): Boolean = approvalSha256 != null && attempt in setOf(Attempt.RUNNING, Attempt.UNKNOWN, Attempt.STOP_REQUESTED)

    fun canRevoke(): Boolean = orphanApprovalSha256 != null ||
        (approvalSha256 != null && attempt == Attempt.READY)
}

private fun artifactPaths(rawJson: String, names: List<String>): List<String> {
    val artifacts = JsonFields.container(rawJson, "artifacts", '{', '}') ?: return emptyList()
    val paths = JsonFields.container(artifacts, "paths", '{', '}') ?: return emptyList()
    return names.mapNotNull { JsonFields.string(paths, it) }
}

internal fun repairFieldRow(labelText: String, field: JBTextField): JPanel = JPanel(BorderLayout(8, 0)).apply {
    val label = JLabel(labelText)
    label.labelFor = field
    label.accessibleContext.accessibleName = labelText
    field.accessibleContext.accessibleName = labelText
    add(label, BorderLayout.WEST)
    add(field, BorderLayout.CENTER)
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

internal fun buildAiAgentProofMission(brief: String): String = buildString {
    appendLine("FactoryLine AI Agent Proof Mission")
    appendLine("Use this sealed local scope with Junie or another AI coding agent.")
    appendLine()
    appendLine("Working contract:")
    appendLine("- Preserve the stated intent, non-goals, and negative case.")
    appendLine("- Change only the sealed paths. Stop and ask before expanding scope.")
    appendLine("- Do not delete, skip, weaken, or replace a failing test merely to make the run green.")
    appendLine("- Return the exact changed paths, tests run, failures, and remaining unknowns.")
    appendLine("- Do not claim approval or production readiness. FactoryLine will independently review the returned Change List and evidence.")
    appendLine()
    appendLine("Sealed proof context:")
    append(brief)
}

class FactoryLineRepairSandboxPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Seal one Change List before a supervised repair candidate enters review.")
    private val summary = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = """
            Verified Repair Sandbox

            Select one native Change List to create a hash-bound Scope Passport. Copy its Proof Mission into Junie or another AI coding agent, then bring the returned Change List back to Proof Review. FactoryLine verifies only local scope and supplied evidence; the independent verifier and human apply steps remain explicit.

            Junie helps you build. FactoryLine helps you know whether the build and its tests deserve trust. No agent is contacted or granted authority by this panel.
        """.trimIndent()
    }
    private val raw = JBTextArea().apply { isEditable = false; lineWrap = false }
    private val pathsModel = DefaultListModel<String>()
    private val paths = JBList(pathsModel)
    private var latestScope: RepairScopeSummary? = null
    private var latestCandidate: RepairCandidateSummary? = null
    private var latestApproval: RepairApprovalSummary? = null
    private val actionState = RepairSandboxActionState()
    private val operatorField = JBTextField()
    private val expiryField = JBTextField()
    private val imageField = JBTextField()
    private val digestField = JBTextField()
    private val checksField = JBTextField(".factory/repair-sandboxes/checks.json")
    private val reasonField = JBTextField()
    private lateinit var approveButton: JButton
    private lateinit var runButton: JButton
    private lateinit var revokeButton: JButton
    private lateinit var stopButton: JButton

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Prepare Change List").apply { addActionListener { FactoryLineController.prepareRepairScope(project) } })
            add(JButton("Validate candidate patch").apply { addActionListener { FactoryLineController.validateRepairCandidate(project, latestScope) } })
            add(JButton("Open selected scope file").apply { addActionListener { openSelectedScopePath() } })
            add(JButton("Open candidate patch").apply { addActionListener { openCandidatePatch() } })
            add(JButton("Copy team brief").apply { addActionListener { copyBrief() } })
            add(JButton("Copy Proof Mission for AI agent").apply { addActionListener { copyAiContext() } })
            add(JButton("Review returned Change List").apply { addActionListener { FactoryLineController.reviewCurrentDiff(project) } })
            add(JButton("Install Junie MCP").apply { addActionListener { FactoryLineController.installProofAdapter(project, "junie") } })
            add(JButton("Install Copilot Proof Agent").apply { addActionListener { FactoryLineController.installProofAdapter(project, "copilot") } })
            add(JButton("Verify agent + analyzer").apply { addActionListener { FactoryLineController.verifyAgentAndAnalyzer(project, latestScope) } })
            add(JButton("Open Graph Ops").apply { addActionListener { FactoryLineController.openStudio(project, graphMode = true) } })
            add(JButton("Copy generic MCP config").apply { addActionListener { copyMcpConfig() } })
        }
        val repairControls = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(JLabel("One explicit approval binds the candidate hash, scope, checks, image digest, operator, and expiry."))
            add(repairFieldRow("Operator", operatorField))
            add(repairFieldRow("Expiry (ISO-8601 with timezone)", expiryField))
            add(repairFieldRow("Container image", imageField))
            add(repairFieldRow("Container SHA-256 digest", digestField))
            add(repairFieldRow("Checks JSON path", checksField))
            add(repairFieldRow("Revoke/stop reason", reasonField))
            val actions = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
            approveButton = JButton("Approve exact candidate").apply {
                isEnabled = false
                addActionListener {
                    val token = actionState.beginApproval()
                    if (token == null) {
                        status.text = "Approval is pending or an earlier approval/attempt must be resolved first."
                        updateActionButtons()
                    } else {
                        updateActionButtons()
                        val launched = FactoryLineController.approveRepair(
                            project, latestScope, latestCandidate, operatorField.text, expiryField.text,
                            imageField.text, digestField.text, checksField.text,
                        ) { result -> showApprovalResult(token, result) }
                        if (!launched) {
                            actionState.cancelApproval(token)
                            updateActionButtons()
                        }
                    }
                }
            }
            runButton = JButton("Run approved repair").apply {
                isEnabled = false
                addActionListener {
                    if (!actionState.canRun()) {
                        status.text = "Select the exact candidate bound to the active approval before running it."
                        updateActionButtons()
                    } else FactoryLineController.runApprovedRepair(project, latestApproval, latestCandidate) {
                        val started = actionState.beginRun()
                        if (started) updateActionButtons()
                        started
                    }
                }
            }
            revokeButton = JButton("Revoke approval").apply {
                isEnabled = false
                addActionListener { FactoryLineController.revokeRepairApproval(project, latestApproval, operatorField.text, reasonField.text) }
            }
            stopButton = JButton("Request stop").apply {
                isEnabled = false
                addActionListener { FactoryLineController.stopRepairAttempt(project, latestApproval, operatorField.text, reasonField.text) }
            }
            actions.add(approveButton); actions.add(runButton); actions.add(revokeButton); actions.add(stopButton)
            add(actions)
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
            addTab("Approve & Repair", JBScrollPane(repairControls))
        }, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun show(result: CommandResult) {
        when (result.title) {
            "Approve Repair" -> {
                show(RepairSandboxUnavailable("Approval result was not paired with its captured candidate request and was ignored.", result.output))
                return
            }
            "Run Approved Repair" -> {
                val expected = latestApproval?.approvalSha256
                val attempt = expected?.let { RepairAttemptSummary.fromJson(result.output, it) }
                if (result.timedOut) {
                    expected?.let { actionState.finishRun(it, resultKnown = false) }
                    status.text = "Repair command timed out; container cleanup is unknown. Use Request stop and inspect the durable attempt record before retrying."
                    raw.text = result.output
                    updateActionButtons()
                } else if (attempt == null) {
                    expected?.let { actionState.finishRun(it, resultKnown = false) }
                    status.text = "Repair result was malformed or did not match the active approval; cleanup is unknown. Request stop and inspect durable attempt evidence."
                    raw.text = result.output
                    updateActionButtons()
                }
                else {
                    actionState.finishRun(attempt.approvalSha256, resultKnown = attempt.cleanupConfirmed)
                    status.text = when {
                        result.exitCode == 0 && !result.timedOut && attempt.verified -> "Repair verified in disposable worktree; cleanup and primary checkout checks passed."
                        attempt.status == "STOPPED" -> "Repair stopped (${attempt.errorCode ?: attempt.phase}); inspect retained attempt evidence."
                        else -> "Repair not verified (${attempt.errorCode ?: attempt.phase}); inspect retained attempt evidence."
                    }
                    raw.text = attempt.rawJson
                    updateActionButtons()
                }
                return
            }
            "Revoke Repair Approval", "Stop Repair Attempt" -> {
                val expected = latestApproval?.approvalSha256
                val target = if (result.title == "Revoke Repair Approval") "REVOKED" else "STOP_REQUESTED"
                val action = expected?.let { RepairApprovalActionSummary.fromJson(result.output, it, target) }
                if (result.exitCode == 0 && !result.timedOut && action != null) {
                    if (target == "REVOKED") {
                        actionState.revoke(action.approvalSha256, succeeded = true)
                        latestApproval = null
                    } else actionState.stopResponse(action.approvalSha256, succeeded = true)
                    status.text = if (target == "REVOKED") "Approval revoked; it cannot be executed." else "Stop request recorded for the active attempt."
                    raw.text = result.output
                    updateActionButtons()
                } else {
                    if (target == "STOP_REQUESTED" && expected != null) actionState.stopResponse(expected, succeeded = false)
                    status.text = if (target == "STOP_REQUESTED") "Stop request failed or was malformed. Active approval and stop recovery remain available." else "Approval action failed or was malformed; the current approval state is unchanged."
                    raw.text = result.output
                    updateActionButtons()
                }
                return
            }
        }
        val scope = if (result.exitCode == 0 && !result.timedOut) RepairScopeSummary.fromJson(result.output) else null
        val candidate = if (result.exitCode == 0 && !result.timedOut) RepairCandidateSummary.fromJson(result.output) else null
        when {
            scope != null -> show(scope)
            candidate != null -> show(candidate)
            else -> show(RepairSandboxUnavailable.from(result))
        }
    }

    fun show(scope: RepairScopeSummary) {
        actionState.selectScope(scope.scopeSha256)
        latestScope = scope
        latestCandidate = null
        updateActionButtons()
        status.text = "Scope sealed: ${scope.paths.size} path(s) from '${scope.changeList}'. Any repair run requires separate exact-candidate approval."
        summary.text = scope.brief()
        raw.text = scope.rawJson
        pathsModel.removeAllElements()
        scope.paths.forEach(pathsModel::addElement)
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    fun show(candidate: RepairCandidateSummary) {
        if (latestScope?.scopeSha256 != candidate.scopeSha256) {
            show(RepairSandboxUnavailable("Candidate does not match the currently selected sealed scope.", candidate.rawJson))
            return
        }
        latestCandidate = candidate
        actionState.selectCandidate(candidate.scopeSha256, candidate.candidateSha256)
        updateActionButtons()
        status.text = "Candidate patch is path-scoped: ${candidate.touchedPaths.size} path(s). Independent verifier and human apply still required."
        summary.text = candidate.brief()
        raw.text = candidate.rawJson
        pathsModel.removeAllElements()
        candidate.touchedPaths.forEach(pathsModel::addElement)
        summary.caretPosition = 0
        raw.caretPosition = 0
    }

    fun show(unavailable: RepairSandboxUnavailable) {
        actionState.selectScope(null)
        status.text = "Repair Sandbox unavailable: ${unavailable.message}"
        summary.text = "Repair Sandbox could not produce a trusted scope or candidate result.\n\n${unavailable.message}\n\nNo patch is eligible to apply and no quality result was inferred."
        raw.text = unavailable.rawOutput
        pathsModel.removeAllElements()
        summary.caretPosition = 0
        raw.caretPosition = 0
        latestScope = null
        latestCandidate = null
        updateActionButtons()
    }

    private fun showApprovalResult(token: RepairApprovalRequestToken, result: CommandResult) {
        val approval = if (result.exitCode == 0 && !result.timedOut) RepairApprovalSummary.fromJson(result.output) else null
        val attached = actionState.completeApproval(token, approval?.approvalSha256)
        if (!attached || approval == null) {
            if (approval != null && actionState.orphanApprovalSha256 == approval.approvalSha256) latestApproval = approval
            status.text = if (approval == null) "Approval failed or returned malformed data; no approval was attached." else
                "Approval completed for a prior selection (${approval.approvalSha256}) and cannot run for the current candidate. Revoke it here or inspect its saved artifact."
            raw.text = result.output
            updateActionButtons()
            return
        }
        latestApproval = approval
        status.text = "Approval recorded for ${approval.approvalSha256}. It is single-use and has not run."
        raw.text = approval.rawJson
        updateActionButtons()
    }

    private fun updateActionButtons() {
        if (!::approveButton.isInitialized) return
        approveButton.isEnabled = latestScope != null && latestCandidate != null && !actionState.approvalRequestInFlight && actionState.orphanApprovalSha256 == null &&
            actionState.attempt !in setOf(RepairSandboxActionState.Attempt.READY, RepairSandboxActionState.Attempt.RUNNING, RepairSandboxActionState.Attempt.UNKNOWN, RepairSandboxActionState.Attempt.STOP_REQUESTED)
        runButton.isEnabled = latestApproval != null && actionState.canRun()
        revokeButton.isEnabled = latestApproval != null && actionState.canRevoke()
        stopButton.isEnabled = latestApproval != null && actionState.canStop()
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
        val context = buildAiAgentProofMission(brief)
        CopyPasteManager.getInstance().setContents(StringSelection(context))
        status.text = "Copied a sealed Proof Mission for a manual Junie or AI-agent paste. No AI service was contacted."
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
    OpenFileDescriptor(project, virtualFile).navigate(true)
    return null
}
