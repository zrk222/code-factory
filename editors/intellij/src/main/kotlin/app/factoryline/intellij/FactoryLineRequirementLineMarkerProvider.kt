package app.factoryline.intellij

import com.intellij.codeInsight.daemon.GutterIconNavigationHandler
import com.intellij.codeInsight.daemon.LineMarkerInfo
import com.intellij.codeInsight.daemon.LineMarkerProvider
import com.intellij.icons.AllIcons
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.ui.Messages
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import com.intellij.openapi.util.TextRange
import com.intellij.openapi.editor.markup.GutterIconRenderer
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

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

data class TestDeclaration(val line: Int, val name: String)

object TestProofDraft {
    fun declarationAt(source: String, languageId: String, offset: Int): TestDeclaration? {
        val line = source.take(offset.coerceIn(0, source.length)).count { it == '\n' }
        val text = source.lineSequence().drop(line).firstOrNull() ?: return null
        return declarationOnLine(text, languageId, line)
    }

    fun declarationOnLine(text: String, languageId: String, line: Int): TestDeclaration? {
        if (line < 0 || text.length > MAX_TEST_PROOF_LINE_CHARS) return null
        val language = languageId.lowercase()
        val name = when {
            language.contains("python") -> Regex("^\\s*(?:async\\s+)?def\\s+(test_[A-Za-z0-9_]*)\\s*\\(").find(text)?.groupValues?.get(1)
            language.contains("javascript") || language.contains("typescript") || language.contains("ecmascript") ->
                Regex("\\b(?:test|it)\\s*\\(\\s*(['\"])([^'\"\\n]+)\\1\\s*,").find(text)?.groupValues?.get(2)
            else -> null
        } ?: return null
        return TestDeclaration(line, name)
    }

    fun create(root: Path, relativeFile: String, testName: String, line: Int): Path {
        require(line >= 0) { "Test declaration line must be non-negative." }
        val realRoot = root.toRealPath()
        val relative = Path.of(relativeFile).normalize()
        require(!relative.isAbsolute && relative.none { it.toString() == ".." }) { "Test source must remain inside the workspace." }
        val source = realRoot.resolve(relative).toRealPath()
        require(source.startsWith(realRoot) && Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) { "Test source must be a regular workspace file." }
        val normalizedFile = relative.joinToString("/")
        val slug = testName.replace(Regex("[^A-Za-z0-9._-]+"), "-").trimStart('-', '.').take(40).ifEmpty { "test" }
        val digest = MessageDigest.getInstance("SHA-256").digest("$normalizedFile\u0000$testName\u0000$line".toByteArray()).take(8).joinToString("") { "%02x".format(it) }
        val id = "test-$slug-line-${line + 1}-$digest"
        var directory = realRoot
        for (component in listOf(".factory", "requirement-proofs", id)) {
            directory = directory.resolve(component)
            try { Files.createDirectory(directory) } catch (_: java.nio.file.FileAlreadyExistsException) { }
            require(Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(directory)) { "Proof path contains a linked or non-directory component." }
        }
        val manifest = directory.resolve("e2e-manifest.json")
        val json = """{
  "schema": "factory.e2e_proof_manifest.v1",
  "id": "$id",
  "approval": {"state": "unapproved", "approved_by": ""},
  "working_directory": ".",
  "timeout_seconds": 120,
  "network_egress": "not_granted",
  "positive": {"argv": []},
  "negative": {"argv": []},
  "artifact_paths": [${jsonString(normalizedFile)}]
}
"""
        Files.writeString(manifest, json, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        return manifest
    }

    private fun jsonString(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
            }
        }
        append('"')
    }
}

class FactoryLineRequirementLineMarkerProvider : LineMarkerProvider {
    override fun getLineMarkerInfo(element: PsiElement): LineMarkerInfo<*>? {
        if (element.firstChild != null) return null
        val requirementId = RequirementEvidenceLocator.ids(element.text).firstOrNull()
        if (requirementId == null) return testProofMarker(element)
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

    private fun testProofMarker(element: PsiElement): LineMarkerInfo<*>? {
        val document = PsiDocumentManager.getInstance(element.project).getDocument(element.containingFile) ?: return null
        if (document.textLength > MAX_TEST_PROOF_DOCUMENT_CHARS) return null
        val lineNumber = document.getLineNumber(element.textRange.startOffset.coerceIn(0, document.textLength))
        val lineStart = document.getLineStartOffset(lineNumber)
        val lineEnd = document.getLineEndOffset(lineNumber)
        if (lineEnd - lineStart > MAX_TEST_PROOF_LINE_CHARS) return null
        val lineText = document.getText(TextRange(lineStart, lineEnd))
        val firstDeclarationOffset = lineStart + lineText.indexOfFirstNonWhitespace()
        if (element.textRange.startOffset != firstDeclarationOffset) return null
        val declaration = TestProofDraft.declarationOnLine(lineText, element.language.id, lineNumber) ?: return null
        val handler = GutterIconNavigationHandler<PsiElement> { _, source ->
            val root = source.project.basePath?.let(Path::of) ?: return@GutterIconNavigationHandler
            val sourcePath = source.containingFile.virtualFile?.path?.let(Path::of) ?: return@GutterIconNavigationHandler
            val relative = runCatching { root.toRealPath().relativize(sourcePath.toRealPath()).toString() }.getOrNull() ?: return@GutterIconNavigationHandler
            val choice = Messages.showOkCancelDialog(
                source.project,
                "Create a blank, unapproved E2E proof draft for $relative :: ${declaration.name} (line ${declaration.line + 1})? This bounded syntax match is not universal test discovery. No command is generated or run, and no pass is asserted.",
                "Draft Test Proof",
                "Create Unapproved Draft",
                "Cancel",
                null,
            )
            if (choice == Messages.OK) {
                runCatching { TestProofDraft.create(root, relative, declaration.name, declaration.line) }
                    .onSuccess { Messages.showInfoMessage(source.project, "Created unapproved test-proof draft: ${root.relativize(it)}. Review and edit manually; this action did not run a test.", "FactoryLine") }
                    .onFailure { Messages.showErrorDialog(source.project, it.message ?: "Could not create test-proof draft.", "FactoryLine") }
            }
        }
        return LineMarkerInfo(
            element,
            element.textRange,
            AllIcons.Gutter.Unique,
            { "Draft unapproved proof for test ${declaration.name}" },
            handler,
            GutterIconRenderer.Alignment.RIGHT,
            { "FactoryLine test-proof draft" },
        )
    }

    private fun String.indexOfFirstNonWhitespace(): Int = indexOfFirst { !it.isWhitespace() }.let { if (it < 0) length else it }
}

private const val MAX_TEST_PROOF_DOCUMENT_CHARS = 1_000_000
private const val MAX_TEST_PROOF_LINE_CHARS = 8_192
