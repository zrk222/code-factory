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
}
