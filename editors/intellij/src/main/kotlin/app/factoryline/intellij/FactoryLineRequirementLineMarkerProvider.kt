package app.factoryline.intellij

import com.intellij.codeInsight.daemon.GutterIconNavigationHandler
import com.intellij.codeInsight.daemon.LineMarkerInfo
import com.intellij.codeInsight.daemon.LineMarkerProvider
import com.intellij.icons.AllIcons
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.psi.PsiElement
import com.intellij.openapi.editor.markup.GutterIconRenderer
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes

data class RequirementEvidence(val path: Path, val line: Int)

object RequirementEvidenceLocator {
    private val pattern = Regex("\\b(?:REQ|FR|NFR)-[A-Z0-9][A-Z0-9_-]*\\b")
    private val roots = listOf(".factory", "receipts", "coverage", "tests", "specs")
    private val extensions = setOf("json", "md", "yaml", "yml", "txt")
    private val excluded = setOf(".git", "node_modules", ".pnpm", "dist", "build", ".gradle", "out")

    fun ids(text: String): List<String> = pattern.findAll(text).map { it.value }.distinct().toList()

    fun first(projectRoot: Path, requirementId: String): RequirementEvidence? {
        var inspected = 0
        roots.map { projectRoot.resolve(it) }.filter(Files::isDirectory).forEach { root ->
            var found: RequirementEvidence? = null
            try {
                Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
                    override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult =
                        if (directory != root && directory.fileName.toString() in excluded) FileVisitResult.SKIP_SUBTREE
                        else FileVisitResult.CONTINUE

                    override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                        if (found != null || inspected >= 2_000) return FileVisitResult.TERMINATE
                        inspected += 1
                        val extension = file.fileName.toString().substringAfterLast('.', "").lowercase()
                        if (!attributes.isRegularFile || extension !in extensions || attributes.size() > 2_000_000) {
                            return FileVisitResult.CONTINUE
                        }
                        try {
                            Files.readAllLines(file, StandardCharsets.UTF_8).forEachIndexed { index, line ->
                                if (found == null && line.contains(requirementId)) found = RequirementEvidence(file, index)
                            }
                        } catch (_: IOException) {
                            // Evidence may disappear during builds. Navigation stays best-effort and read-only.
                        }
                        return if (found == null) FileVisitResult.CONTINUE else FileVisitResult.TERMINATE
                    }

                    override fun visitFileFailed(file: Path, error: IOException): FileVisitResult = FileVisitResult.CONTINUE
                })
            } catch (_: IOException) {
                // Continue with the next bounded evidence root.
            }
            if (found != null) return found
        }
        return null
    }
}

class FactoryLineRequirementLineMarkerProvider : LineMarkerProvider {
    override fun getLineMarkerInfo(element: PsiElement): LineMarkerInfo<*>? {
        if (element.firstChild != null) return null
        val requirementId = RequirementEvidenceLocator.ids(element.text).firstOrNull() ?: return null
        val handler = GutterIconNavigationHandler<PsiElement> { _, source ->
            val root = source.project.basePath?.let(Path::of) ?: return@GutterIconNavigationHandler
            val evidence = RequirementEvidenceLocator.first(root, requirementId)
            val virtualFile = evidence?.path?.let(LocalFileSystem.getInstance()::findFileByNioFile)
            if (evidence != null && virtualFile != null) {
                OpenFileDescriptor(source.project, virtualFile, evidence.line, 0).navigate(true)
            }
        }
        return LineMarkerInfo(
            element,
            element.textRange,
            AllIcons.Gutter.Unique,
            { "Open local FactoryLine proof for $requirementId" },
            handler,
            GutterIconRenderer.Alignment.RIGHT,
            { "FactoryLine proof for $requirementId" },
        )
    }
}
