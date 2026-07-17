package app.factoryline.intellij

import java.nio.file.Files
import java.nio.file.attribute.FileTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class FactoryLineCoreTest {
    @Test
    fun featureNamesAreBounded() {
        assertTrue(FeatureName.isValid("receipt-integrity_2"))
        assertFalse(FeatureName.isValid("receipt integrity"))
        assertFalse(FeatureName.isValid("../receipt"))
        assertFalse(FeatureName.isValid(""))
    }

    @Test
    fun studioUrlAcceptsOnlyLiteralLoopbackOutput() {
        assertEquals(
            "http://127.0.0.1:43117/",
            StudioUrl.find("marker: STUDIO_STARTED\nFactory Studio: http://127.0.0.1:43117/\n")
        )
        assertEquals(null, StudioUrl.find("Factory Studio: http://0.0.0.0:43117/"))
        assertEquals(null, StudioUrl.find("Factory Studio: https://example.com/"))
    }

    @Test
    fun receiptSummarySelectsKnownFieldsWithoutRenderingHtml() {
        val summary = ReceiptSummary.fromJson(
            Files.createTempFile("factoryline", ".json"),
            """{ "status": "passed", "feature": "<script>alert(1)</script>", "ignored": "value" }"""
        )

        assertEquals("passed", summary.fields["status"])
        assertEquals("<script>alert(1)</script>", summary.fields["feature"])
        assertFalse(summary.display.contains("<html", ignoreCase = true))
    }

    @Test
    fun meterSummarySeparatesMeasuredAndUnavailableValues() {
        val summary = MeterSummary.fromJson(
            """{ "stages_measured": 2, "build_wall_ms": 15, "tokens_reported_by_modules": false, "stages_successful": 2 }"""
        )

        assertEquals("2", summary.fields["stages_measured"])
        assertEquals("false", summary.fields["tokens_reported_by_modules"])
        assertTrue(summary.display.contains("Token totals are measured"))
    }

    @Test
    fun receiptLocatorIgnoresDependencyTreesAndReturnsNewestReceipt() {
        val root = Files.createTempDirectory("factoryline-receipts")
        val receipts = Files.createDirectories(root.resolve("receipts"))
        val ignored = Files.createDirectories(receipts.resolve("node_modules"))
        val older = receipts.resolve("older.json")
        val newest = receipts.resolve("newest.json")
        Files.writeString(older, "{\"status\":\"old\"}")
        Files.writeString(ignored.resolve("ignored.json"), "{\"status\":\"ignored\"}")
        Files.writeString(newest, "{\"status\":\"passed\"}")
        Files.setLastModifiedTime(older, FileTime.fromMillis(1_000))
        Files.setLastModifiedTime(newest, FileTime.fromMillis(2_000))

        val found = ReceiptLocator.latest(root)

        assertNotNull(found)
        assertEquals(newest.fileName.toString(), found.fileName.toString())
    }

    @Test
    fun requirementEvidenceIsBoundedAndNavigable() {
        val root = Files.createTempDirectory("factoryline-requirements")
        val evidence = Files.createDirectories(root.resolve(".factory")).resolve("proof.json")
        Files.writeString(evidence, """{"requirement":"FR-101","status":"passed"}""")

        assertEquals(listOf("FR-101", "NFR-A11Y"), RequirementEvidenceLocator.ids("FR-101 and NFR-A11Y and FR-101"))
        val found = RequirementEvidenceLocator.first(root, "FR-101")
        assertNotNull(found)
        assertEquals(evidence, found.path)
        assertEquals(0, found.line)
    }
}
