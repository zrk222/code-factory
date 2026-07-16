package app.factoryline.intellij

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.process.CapturingProcessHandler
import com.intellij.execution.process.OSProcessHandler
import com.intellij.execution.process.ProcessEvent
import com.intellij.execution.process.ProcessListener
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.SystemInfo
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.util.Key
import com.intellij.ui.components.JBTextField
import com.intellij.util.concurrency.AppExecutorUtil
import com.intellij.util.ui.FormBuilder
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.FileVisitResult
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import javax.swing.JComponent
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

object FactoryLineIds {
    const val TOOL_WINDOW = "FactoryLine"
    const val OUTPUT_LIMIT = 1_000_000
    const val TIMEOUT_MS = 300_000
}

object FeatureName {
    private val pattern = Regex("[A-Za-z0-9][A-Za-z0-9_-]*")

    fun isValid(value: String): Boolean = pattern.matches(value)
}

object StudioUrl {
    private val pattern = Regex("Factory Studio:\\s+(http://127\\.0\\.0\\.1:\\d+/)")

    fun find(output: String): String? = pattern.find(output)?.groupValues?.get(1)
}

enum class FactoryLineOperation(val arguments: List<String>, val title: String) {
    ASSEMBLE(listOf("assemble"), "Spec-to-Ship Assembly"),
    VERIFY(listOf("verify"), "Verify Feature Receipts")
}

data class CommandResult(
    val title: String,
    val command: List<String>,
    val exitCode: Int?,
    val timedOut: Boolean,
    val output: String
)

data class ReceiptSummary(val source: Path, val fields: Map<String, String>, val rawJson: String) {
    val display: String
        get() = buildString {
            appendLine("Receipt: $source")
            appendLine("Trust: unassessed. Signature presence is not identity verification.")
            if (fields.isEmpty()) appendLine("No common receipt fields found; showing raw JSON.")
            fields.forEach { (key, value) -> appendLine("$key: $value") }
        }

    companion object {
        private val scalar = Regex("\"([^\"]+)\"\\s*:\\s*(\"([^\"]*)\"|true|false|null|-?\\d+(?:\\.\\d+)?)")
        private val preferredKeys = listOf("feature", "status", "stage", "gate", "verdict", "ok", "result", "schema")

        fun fromJson(source: Path, rawJson: String): ReceiptSummary {
            val values = scalar.findAll(rawJson).associate { match ->
                match.groupValues[1] to match.groupValues[2].removeSurrounding("\"")
            }
            val selected = preferredKeys.mapNotNull { key -> values[key]?.let { key to it } }.toMap()
            return ReceiptSummary(source, selected, rawJson)
        }
    }
}

data class MeterSummary(val fields: Map<String, String>, val rawJson: String) {
    val display: String
        get() = buildString {
            appendLine("Local FactoryLine Meter")
            appendLine("Token totals are measured only when modules report usage.")
            fields.forEach { (key, value) -> appendLine("$key: $value") }
        }

    companion object {
        private val scalar = Regex("\\\"([^\\\"]+)\\\"\\s*:\\s*(\\\"([^\\\"]*)\\\"|true|false|null|-?\\d+(?:\\.\\d+)?)")
        private val preferredKeys = listOf(
            "stages_measured", "build_wall_ms", "build_model_calls", "build_tokens",
            "tokens_reported_by_modules", "runs_observed", "stages_successful", "stages_failed",
            "stage_success_rate", "last_measurement_at"
        )

        fun fromJson(rawJson: String): MeterSummary {
            val values = scalar.findAll(rawJson).associate { match ->
                match.groupValues[1] to match.groupValues[2].removeSurrounding("\\\"")
            }
            return MeterSummary(preferredKeys.mapNotNull { key -> values[key]?.let { key to it } }.toMap(), rawJson)
        }
    }
}

object ReceiptLocator {
    private val roots = listOf(".factory", "receipts")
    private val excluded = setOf(".git", "node_modules", ".pnpm", "build", "dist", ".gradle", "out")

    fun latest(projectRoot: Path): Path? {
        val candidates = roots.map { projectRoot.resolve(it) }.filter { Files.isDirectory(it) }
        val receipts = mutableListOf<Path>()
        candidates.forEach { root ->
            try {
                Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
                    override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
                        return if (directory != root && directory.fileName.toString() in excluded) {
                            FileVisitResult.SKIP_SUBTREE
                        } else {
                            FileVisitResult.CONTINUE
                        }
                    }

                    override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                        if (attributes.isRegularFile && file.fileName.toString().endsWith(".json")) receipts.add(file)
                        return FileVisitResult.CONTINUE
                    }

                    override fun visitFileFailed(file: Path, error: IOException): FileVisitResult = FileVisitResult.CONTINUE
                })
            } catch (_: IOException) {
                // Receipts can disappear while a build is cleaning its output. Keep the view read-only and best-effort.
            }
        }
        return receipts.mapNotNull { receipt ->
            runCatching { receipt to Files.getLastModifiedTime(receipt).toMillis() }.getOrNull()
        }.maxByOrNull { (_, modifiedAt) -> modifiedAt }?.first
    }

    fun read(path: Path): ReceiptSummary {
        require(Files.size(path) <= FactoryLineIds.OUTPUT_LIMIT) { "Receipt is larger than 1 MB." }
        return ReceiptSummary.fromJson(path, Files.readString(path, StandardCharsets.UTF_8))
    }
}

@State(name = "FactoryLineSettings", storages = [Storage("factoryline.xml")])
class FactoryLineSettings : PersistentStateComponent<FactoryLineSettings.State> {
    data class State(var command: String = "factory")

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    fun executable(): String {
        val configured = state.command.trim().ifBlank { "factory" }
        return if (SystemInfo.isWindows && configured == "factory") "factory.exe" else configured
    }

    fun configuredCommand(): String = state.command

    fun setConfiguredCommand(command: String) {
        state.command = command.trim().ifBlank { "factory" }
    }

    companion object {
        fun instance(): FactoryLineSettings = ApplicationManager.getApplication().service()
    }
}

class FactoryLineSettingsConfigurable : Configurable {
    private var commandField: JBTextField? = null

    override fun getDisplayName(): String = "FactoryLine"

    override fun createComponent(): JComponent {
        commandField = JBTextField(FactoryLineSettings.instance().configuredCommand())
        return FormBuilder.createFormBuilder()
            .addLabeledComponent("FactoryLine executable:", commandField!!)
            .addComponentFillVertically(javax.swing.JPanel(), 0)
            .panel
    }

    override fun isModified(): Boolean = commandField?.text?.trim() != FactoryLineSettings.instance().configuredCommand()

    override fun apply() {
        FactoryLineSettings.instance().setConfiguredCommand(commandField?.text.orEmpty())
    }

    override fun reset() {
        commandField?.text = FactoryLineSettings.instance().configuredCommand()
    }

    override fun disposeUIResources() {
        commandField = null
    }
}

object FactoryLineRunner {
    fun run(project: Project, operation: FactoryLineOperation, feature: String): CommandResult {
        if (!FeatureName.isValid(feature)) {
            return CommandResult(operation.title, emptyList(), null, false, "Blocked: feature names use letters, digits, hyphens, and underscores only.")
        }
        return execute(project, operation.title, operation.arguments + feature + rootArguments(project))
    }

    fun analyzeChangedProof(project: Project): CommandResult =
        execute(project, "Analyze Changed Proof", listOf("risk-diff") + rootArguments(project) + "--json")

    fun receiptStatus(project: Project, receipt: Path): CommandResult =
        execute(project, "Check Receipt Signature State", listOf("receipt", "status", receipt.toString()))

    fun meter(project: Project): CommandResult =
        execute(project, "Open Local Meter", listOf("meter") + rootArguments(project) + "--json")

    fun startStudio(project: Project, onStarted: (String) -> Unit, onFailure: (String) -> Unit) {
        val root = project.basePath?.let(Path::of) ?: run {
            onFailure("The project has no local workspace path.")
            return
        }
        val executable = FactoryLineSettings.instance().executable()
        val arguments = listOf("studio", "--root", root.toString(), "--port", "0", "--no-browser")
        val commandLine = GeneralCommandLine(executable)
            .withParameters(arguments)
            .withWorkDirectory(root.toFile())
        try {
            val handler = OSProcessHandler(commandLine)
            val output = StringBuilder()
            val completed = AtomicBoolean(false)
            val timeout = AppExecutorUtil.getAppScheduledExecutorService().schedule({
                if (completed.compareAndSet(false, true)) {
                    handler.destroyProcess()
                    ApplicationManager.getApplication().invokeLater {
                        onFailure("Factory Studio did not report a loopback URL within 15 seconds.")
                    }
                }
            }, 15, TimeUnit.SECONDS)
            handler.addProcessListener(object : ProcessListener {
                override fun onTextAvailable(event: ProcessEvent, outputType: Key<*>) {
                    if (output.length < FactoryLineIds.OUTPUT_LIMIT) {
                        output.append(event.text.take(FactoryLineIds.OUTPUT_LIMIT - output.length))
                    }
                    val url = StudioUrl.find(output.toString())
                    if (url != null && completed.compareAndSet(false, true)) {
                        timeout.cancel(false)
                        ApplicationManager.getApplication().invokeLater { onStarted(url) }
                    }
                }

                override fun processTerminated(event: ProcessEvent) {
                    if (completed.compareAndSet(false, true)) {
                        timeout.cancel(false)
                        ApplicationManager.getApplication().invokeLater {
                            onFailure("Factory Studio exited before reporting a loopback URL (code ${event.exitCode}).")
                        }
                    }
                }
            })
            Disposer.register(project) { if (!handler.isProcessTerminated) handler.destroyProcess() }
            handler.startNotify()
        } catch (error: Exception) {
            onFailure("Failed to start Factory Studio: ${error.message}")
        }
    }

    private fun rootArguments(project: Project): List<String> {
        val root = project.basePath?.let(Path::of) ?: return emptyList()
        return listOf("--root", root.toString())
    }

    private fun execute(project: Project, title: String, arguments: List<String>): CommandResult {
        val root = project.basePath?.let(Path::of)
            ?: return CommandResult(title, emptyList(), null, false, "Blocked: the project has no local workspace path.")
        if (arguments.isEmpty() || (arguments.contains("--root") && arguments.last() == "--root")) {
            return CommandResult(title, emptyList(), null, false, "Blocked: the project has no local workspace path.")
        }
        val executable = FactoryLineSettings.instance().executable()
        val commandLine = GeneralCommandLine(executable)
            .withParameters(arguments)
            .withWorkDirectory(root.toFile())
        return try {
            val output = CapturingProcessHandler(commandLine).runProcess(FactoryLineIds.TIMEOUT_MS)
            val combined = (output.stdout + output.stderr).take(FactoryLineIds.OUTPUT_LIMIT)
            CommandResult(title, listOf(executable) + arguments, output.exitCode, output.isTimeout, combined)
        } catch (error: Exception) {
            CommandResult(title, listOf(executable) + arguments, null, false, "Failed to start FactoryLine: ${error.message}")
        }
    }
}
