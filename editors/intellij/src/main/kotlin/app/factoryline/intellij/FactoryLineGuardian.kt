package app.factoryline.intellij

import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTabbedPane

/**
 * A deterministic interpretation of the bounded, local IDE-health window.
 * It deliberately reports observations and review routes, never a diagnosis.
 */
enum class GuardianState(val label: String) {
    NO_DATA("No local data yet"),
    READY("No elevated signal observed"),
    OBSERVE("Indexing observed"),
    ATTENTION("Review observed signals"),
}

data class GuardianSignal(
    val id: String,
    val label: String,
    val detail: String,
)

data class GuardianTimelineEvent(
    val sampleNumber: Int,
    val detail: String,
)

data class GuardianAssessment(
    val state: GuardianState,
    val sampleCount: Int,
    val elevatedSignalCount: Int,
    val indexingActiveCount: Int,
    val signals: List<GuardianSignal>,
    val timeline: List<GuardianTimelineEvent>,
) {
    fun overview(): String = buildString {
        appendLine("Guardian Core")
        appendLine("State: ${state.label}")
        appendLine("Local samples: $sampleCount / 20")
        appendLine()
        appendLine("What was observed")
        signals.forEach { appendLine("- ${it.label}: ${it.detail}") }
        appendLine()
        appendLine("Manual review options")
        if (sampleCount == 0) {
            appendLine("- Start a short local recording. Guardian does not infer an IDE state before it has samples.")
        } else {
            appendLine("- Review IDE Health for the retained aggregate samples.")
            if (indexingActiveCount > 0) appendLine("- Compare Index Continuity if the workspace structure recently changed.")
            appendLine("- Review the current AI or teammate diff with Proof Review.")
            appendLine("- Re-check the selected Change List intent before a human review decision.")
            appendLine("- Use Workspace Advisor for bounded local workspace and WSL-path guidance.")
        }
        appendLine()
        append("Boundary: local aggregate observations only. Guardian does not identify a root cause, score plugins, change IDE settings, invalidate caches, run a FactoryLine CLI command, or apply a fix.")
    }

    fun timelineBrief(): String = buildString {
        appendLine("Observed incident timeline")
        if (timeline.isEmpty()) {
            appendLine("No threshold crossing or indexing state transition was observed in this local window.")
        } else {
            timeline.forEach { appendLine("- Sample ${it.sampleNumber}: ${it.detail}") }
        }
        append("Timeline events are time-aligned observations, not causal findings.")
    }
}

/** Stable, navigation-only routes surfaced by the Guardian panel. */
object GuardianReviewRoutes {
    const val IDE_HEALTH = "IDE Health"
    const val INDEX_CONTINUITY = "Index Continuity"
    const val PROOF_REVIEW = "Proof Review"
    const val INTENT_LEDGER = "Intent Ledger"
    const val ENGINEERING_JUDGMENT = "Engineering Judgment"
    const val WORKSPACE_ADVISOR = "Workspace Advisor"

    val all: List<String> = listOf(
        IDE_HEALTH,
        INDEX_CONTINUITY,
        PROOF_REVIEW,
        INTENT_LEDGER,
        ENGINEERING_JUDGMENT,
        WORKSPACE_ADVISOR,
    )
}

object FactoryLineGuardian {
    private const val ELEVATED_EDT_DELAY_MS = 250L
    private const val ELEVATED_CPU_PERCENT = 80.0
    private const val ELEVATED_HEAP_PERCENT = 85.0

    fun assess(samples: List<IdeHealthSample>): GuardianAssessment {
        if (samples.isEmpty()) {
            return GuardianAssessment(
                state = GuardianState.NO_DATA,
                sampleCount = 0,
                elevatedSignalCount = 0,
                indexingActiveCount = 0,
                signals = listOf(GuardianSignal("no_data", "No samples yet", "Start a short local recording before drawing any conclusion.")),
                timeline = emptyList(),
            )
        }

        val edtSamples = samples.filter { it.edtDelayMs >= ELEVATED_EDT_DELAY_MS }
        val cpuSamples = samples.filter { (it.processCpuPercent ?: Double.NEGATIVE_INFINITY) >= ELEVATED_CPU_PERCENT }
        val heapSamples = samples.filter { heapPercent(it) >= ELEVATED_HEAP_PERCENT }
        val indexingSamples = samples.filter { it.indexingActive }
        val signals = buildList {
            if (edtSamples.isNotEmpty()) add(
                GuardianSignal(
                    "edt_delay",
                    "EDT dispatch delay elevated",
                    "${edtSamples.size}/${samples.size} samples at or above ${ELEVATED_EDT_DELAY_MS} ms; latest ${edtSamples.last().edtDelayMs} ms.",
                )
            )
            if (cpuSamples.isNotEmpty()) add(
                GuardianSignal(
                    "process_cpu",
                    "Process CPU elevated",
                    "${cpuSamples.size}/${samples.size} available samples at or above ${ELEVATED_CPU_PERCENT.toInt()}%; latest ${IdeHealthAssessment.cpu(cpuSamples.last().processCpuPercent)}.",
                )
            )
            if (heapSamples.isNotEmpty()) add(
                GuardianSignal(
                    "heap",
                    "Heap use elevated",
                    "${heapSamples.size}/${samples.size} samples at or above ${ELEVATED_HEAP_PERCENT.toInt()}%; latest ${IdeHealthAssessment.heap(heapSamples.last().heapUsedBytes, heapSamples.last().heapMaxBytes)}.",
                )
            )
            if (indexingSamples.isNotEmpty()) add(
                GuardianSignal(
                    "indexing",
                    "Indexing active",
                    "${indexingSamples.size}/${samples.size} samples reported indexing active.",
                )
            )
            if (isEmpty()) add(
                GuardianSignal(
                    "window_clear",
                    "No configured threshold observed",
                    "This local window has no EDT, CPU, heap, or indexing observation that needs extra review.",
                )
            )
        }
        val elevatedCount = edtSamples.size + cpuSamples.size + heapSamples.size
        val state = when {
            elevatedCount > 0 -> GuardianState.ATTENTION
            indexingSamples.isNotEmpty() -> GuardianState.OBSERVE
            else -> GuardianState.READY
        }
        return GuardianAssessment(
            state = state,
            sampleCount = samples.size,
            elevatedSignalCount = elevatedCount,
            indexingActiveCount = indexingSamples.size,
            signals = signals,
            timeline = timeline(samples),
        )
    }

    private fun heapPercent(sample: IdeHealthSample): Double = when {
        sample.heapMaxBytes <= 0L -> Double.NEGATIVE_INFINITY
        else -> sample.heapUsedBytes.toDouble() * 100.0 / sample.heapMaxBytes.toDouble()
    }

    private fun timeline(samples: List<IdeHealthSample>): List<GuardianTimelineEvent> = buildList {
        var previous: IdeHealthSample? = null
        samples.forEachIndexed { index, sample ->
            val prior = previous
            if (prior != null && prior.indexingActive != sample.indexingActive) {
                add(GuardianTimelineEvent(index + 1, if (sample.indexingActive) "Indexing became active." else "Indexing became idle."))
            }
            if (prior != null && prior.edtDelayMs < ELEVATED_EDT_DELAY_MS && sample.edtDelayMs >= ELEVATED_EDT_DELAY_MS) {
                add(GuardianTimelineEvent(index + 1, "EDT dispatch delay reached ${sample.edtDelayMs} ms."))
            }
            val priorCpu = prior?.processCpuPercent ?: Double.NEGATIVE_INFINITY
            val currentCpu = sample.processCpuPercent ?: Double.NEGATIVE_INFINITY
            if (prior != null && priorCpu < ELEVATED_CPU_PERCENT && currentCpu >= ELEVATED_CPU_PERCENT) {
                add(GuardianTimelineEvent(index + 1, "Process CPU reached ${IdeHealthAssessment.cpu(sample.processCpuPercent)}."))
            }
            if (prior != null && heapPercent(prior) < ELEVATED_HEAP_PERCENT && heapPercent(sample) >= ELEVATED_HEAP_PERCENT) {
                add(GuardianTimelineEvent(index + 1, "Heap use reached ${IdeHealthAssessment.heap(sample.heapUsedBytes, sample.heapMaxBytes)}."))
            }
            previous = sample
        }
    }.takeLast(12)
}

class FactoryLineGuardianPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Guardian is local-only. It does not change the IDE or run a FactoryLine command.")
    private val overview = JBTextArea().apply { isEditable = false; lineWrap = true; wrapStyleWord = true }
    private val timeline = JBTextArea().apply { isEditable = false; lineWrap = true; wrapStyleWord = true }

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Start 60-second recording").apply { addActionListener { start() } })
            add(JButton("Refresh").apply { addActionListener { showCurrent() } })
            add(JButton("Stop").apply { addActionListener { stop() } })
            add(JButton("IDE Health").apply { addActionListener { FactoryLinePanels.selectTab(project, GuardianReviewRoutes.IDE_HEALTH) } })
            add(JButton("Index Continuity").apply { addActionListener { FactoryLinePanels.selectTab(project, GuardianReviewRoutes.INDEX_CONTINUITY) } })
            add(JButton("AI Changes").apply { addActionListener { FactoryLinePanels.selectTab(project, GuardianReviewRoutes.PROOF_REVIEW) } })
            add(JButton("Intent Ledger").apply { addActionListener { FactoryLinePanels.selectTab(project, GuardianReviewRoutes.INTENT_LEDGER) } })
            add(JButton("Engineering Judgment").apply { addActionListener { FactoryLinePanels.selectTab(project, GuardianReviewRoutes.ENGINEERING_JUDGMENT) } })
            add(JButton("Workspace Advisor").apply { addActionListener { FactoryLinePanels.selectTab(project, GuardianReviewRoutes.WORKSPACE_ADVISOR) } })
        }
        add(controls, BorderLayout.NORTH)
        add(JTabbedPane().apply {
            addTab("Overview", JBScrollPane(overview))
            addTab("Timeline", JBScrollPane(timeline))
        }, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
        showCurrent()
    }

    fun showCurrent() = showSamples(FactoryLineIdeHealthMonitor.snapshot(project))

    private fun start() {
        FactoryLineIdeHealthMonitor.start(project) { samples -> showSamples(samples) }
        status.text = "Recording aggregate local samples every 3 seconds; at most 20 remain in memory. No source, plugin list, or network data is collected."
    }

    private fun stop() {
        FactoryLineIdeHealthMonitor.stop(project)
        showCurrent()
        status.text = "Recording stopped. Existing samples remain in memory only until this project closes."
    }

    private fun showSamples(samples: List<IdeHealthSample>) {
        val assessment = FactoryLineGuardian.assess(samples)
        overview.text = assessment.overview()
        timeline.text = assessment.timelineBrief()
        overview.caretPosition = 0
        timeline.caretPosition = 0
        if (FactoryLineIdeHealthMonitor.running(project)) {
            status.text = "Recording ${samples.size}/20 local samples. Guardian reports observations, not a causal diagnosis."
        }
    }
}
