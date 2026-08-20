package app.factoryline.intellij

import com.intellij.openapi.Disposable
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.DumbService
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.util.Key
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.util.concurrency.AppExecutorUtil
import com.sun.management.OperatingSystemMXBean
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.datatransfer.StringSelection
import java.lang.management.ManagementFactory
import java.util.Locale
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel

/** Aggregate, in-memory IDE observations. These are not causal diagnoses. */
data class IdeHealthSample(
    val capturedAtMs: Long,
    val heapUsedBytes: Long,
    val heapMaxBytes: Long,
    val processCpuPercent: Double?,
    val systemCpuPercent: Double?,
    val indexingActive: Boolean,
    val edtDelayMs: Long,
)

object IdeHealthMarkers {
    const val TAB_AVAILABLE = "IDE_HEALTH_TAB_AVAILABLE"
    const val LOCAL_RUNTIME_ONLY = "IDE_HEALTH_LOCAL_RUNTIME_ONLY"
    const val NO_CONFIGURATION_MUTATION = "IDE_HEALTH_NO_CONFIGURATION_MUTATION"
    const val NO_NETWORK = "IDE_HEALTH_NO_NETWORK"
    const val BOUNDED_SESSION = "IDE_HEALTH_BOUNDED_SESSION"
    const val CORRELATION_NOT_CAUSATION = "IDE_HEALTH_CORRELATION_NOT_CAUSATION"
    const val SIGNAL_UNAVAILABLE = "IDE_HEALTH_SIGNAL_UNAVAILABLE"
}

object IdeHealthAssessment {
    fun cpu(value: Double?): String = value?.let { "${"%.1f".format(Locale.ROOT, it)}%" } ?: "unavailable"

    fun heap(usedBytes: Long, maxBytes: Long): String {
        if (maxBytes <= 0) return "unavailable"
        return "${usedBytes / (1024 * 1024)} MB / ${maxBytes / (1024 * 1024)} MB"
    }

    fun dispatch(delayMs: Long): String = "$delayMs ms"

    fun reviewNote(sample: IdeHealthSample): String = when {
        sample.edtDelayMs >= 250 -> "EDT dispatch delay is elevated in this sample; inspect the time-aligned event before assigning a cause."
        sample.indexingActive -> "Indexing was active in this sample; compare it with a structural baseline before choosing manual recovery."
        sample.processCpuPercent == null -> "Process CPU is unavailable from this runtime; no CPU conclusion is shown."
        else -> "No single sample is a root cause. Compare the trend with your reported symptom."
    }
}

private class IdeHealthSession : Disposable {
    private val samples = ArrayDeque<IdeHealthSample>()
    private var task: ScheduledFuture<*>? = null

    @Synchronized
    fun start(project: Project, onSample: (List<IdeHealthSample>) -> Unit) {
        stop()
        task = AppExecutorUtil.getAppScheduledExecutorService().scheduleAtFixedRate({
            val requestedAt = System.nanoTime()
            ApplicationManager.getApplication().invokeLater {
                val delay = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - requestedAt).coerceAtLeast(0)
                val sample = capture(project, delay)
                val snapshot = synchronized(this) {
                    samples.addLast(sample)
                    while (samples.size > 20) samples.removeFirst()
                    samples.toList()
                }
                onSample(snapshot)
            }
        }, 0, 3, TimeUnit.SECONDS)
    }

    @Synchronized
    fun stop() {
        task?.cancel(false)
        task = null
    }

    @Synchronized
    fun running(): Boolean = task?.isCancelled == false && task?.isDone == false

    @Synchronized
    fun snapshot(): List<IdeHealthSample> = samples.toList()

    override fun dispose() = stop()

    private fun capture(project: Project, edtDelayMs: Long): IdeHealthSample {
        val runtime = Runtime.getRuntime()
        val bean = ManagementFactory.getOperatingSystemMXBean() as? OperatingSystemMXBean
        fun percentage(value: Double): Double? = value.takeIf { it >= 0.0 }?.times(100.0)
        return IdeHealthSample(
            capturedAtMs = System.currentTimeMillis(),
            heapUsedBytes = runtime.totalMemory() - runtime.freeMemory(),
            heapMaxBytes = runtime.maxMemory(),
            processCpuPercent = bean?.let { percentage(it.processCpuLoad) },
            systemCpuPercent = bean?.let { percentage(it.cpuLoad) },
            indexingActive = DumbService.getInstance(project).isDumb,
            edtDelayMs = edtDelayMs,
        )
    }
}

object FactoryLineIdeHealthMonitor {
    private val key: Key<IdeHealthSession> = Key.create("app.factoryline.intellij.ideHealthSession")

    private fun session(project: Project): IdeHealthSession {
        project.getUserData(key)?.let { return it }
        return IdeHealthSession().also { created ->
            project.putUserData(key, created)
            Disposer.register(project, created)
        }
    }

    fun start(project: Project, onSample: (List<IdeHealthSample>) -> Unit) = session(project).start(project, onSample)
    fun stop(project: Project) = session(project).stop()
    fun running(project: Project): Boolean = session(project).running()
    fun snapshot(project: Project): List<IdeHealthSample> = session(project).snapshot()
}

class FactoryLineIdeHealthPanel(private val project: Project) : JPanel(BorderLayout(0, 8)) {
    private val status = JLabel("Start a local 3-second sample stream. Nothing is saved or sent.")
    private val output = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = intro()
    }

    init {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(JButton("Start local recording").apply { addActionListener { start() } })
            add(JButton("Stop").apply { addActionListener { stop() } })
            add(JButton("Copy health brief").apply { addActionListener { copy() } })
        }
        add(controls, BorderLayout.NORTH)
        add(JBScrollPane(output), BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    fun showCurrent() = showSamples(FactoryLineIdeHealthMonitor.snapshot(project))

    private fun start() {
        FactoryLineIdeHealthMonitor.start(project) { samples -> showSamples(samples) }
        status.text = "Recording local aggregate samples every 3 seconds; retained in memory only (max 20)."
    }

    private fun stop() {
        FactoryLineIdeHealthMonitor.stop(project)
        status.text = "Recording stopped. The samples remain in memory until this project closes."
        showCurrent()
    }

    private fun copy() {
        val samples = FactoryLineIdeHealthMonitor.snapshot(project)
        if (samples.isEmpty()) {
            status.text = "Start a recording before copying a health brief."
            return
        }
        CopyPasteManager.getInstance().setContents(StringSelection(render(samples)))
        status.text = "Copied local aggregate observations. No source, credentials, or network data was included."
    }

    private fun showSamples(samples: List<IdeHealthSample>) {
        output.text = if (samples.isEmpty()) intro() else render(samples)
        output.caretPosition = 0
        if (FactoryLineIdeHealthMonitor.running(project)) {
            status.text = "Recording ${samples.size}/20 local samples. Signals are observations, not a causal diagnosis."
        }
    }

    private fun render(samples: List<IdeHealthSample>): String = buildString {
        appendLine("FactoryLine IDE Health Flight Recorder")
        appendLine("${samples.size} local samples retained in memory. No project content, plugin list, credential, or network data is collected.")
        appendLine()
        samples.forEachIndexed { index, sample ->
            appendLine("Sample ${index + 1} — heap ${IdeHealthAssessment.heap(sample.heapUsedBytes, sample.heapMaxBytes)}; process CPU ${IdeHealthAssessment.cpu(sample.processCpuPercent)}; system CPU ${IdeHealthAssessment.cpu(sample.systemCpuPercent)}; indexing ${if (sample.indexingActive) "active" else "idle"}; EDT ${IdeHealthAssessment.dispatch(sample.edtDelayMs)}.")
        }
        appendLine()
        appendLine("Current review note: ${IdeHealthAssessment.reviewNote(samples.last())}")
        append("Boundary: aggregate local runtime observations only. FactoryLine does not change heap, caches, indexes, plugins, inspections, project files, or remote settings. It does not assign a root cause.")
    }

    private fun intro(): String = """
        IDE Health Flight Recorder

        Record a short local window when the IDE is behaving badly. The recorder shows aggregate heap use, process CPU when the bundled runtime exposes it, indexing state, and the delay before an EDT probe runs.

        Use the trend to decide what to inspect next. A sample is not proof that a plugin, cache, index, or project setting caused the symptom. Recording never changes any of them.
    """.trimIndent()
}
