package app.factoryline.intellij

import com.intellij.ide.BrowserUtil
import com.intellij.ide.util.PropertiesComponent
import com.intellij.notification.Notification
import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.project.Project

object FactoryLineGitHubStarPrompt {
    // Keep this in step with build.gradle.kts. Reading the descriptor through
    // PluginManager is an internal API and fails Marketplace verification.
    private const val RELEASE_VERSION = "0.8.12"
    private const val PROMPTED_VERSION_KEY = "factoryline.githubStarPromptedVersion"
    private const val NOTIFICATION_GROUP_ID = "FactoryLine"
    private const val REPOSITORY_URL = "https://github.com/zrk222/code-factory"

    fun shouldOffer(exitCode: Int?, timedOut: Boolean, promptedVersion: String?, installedVersion: String): Boolean =
        exitCode == 0 && !timedOut && promptedVersion != installedVersion

    fun afterSuccessfulLocalWork(project: Project, result: CommandResult) {
        val properties = PropertiesComponent.getInstance()
        if (!shouldOffer(result.exitCode, result.timedOut, properties.getValue(PROMPTED_VERSION_KEY), RELEASE_VERSION)) {
            return
        }
        properties.setValue(PROMPTED_VERSION_KEY, RELEASE_VERSION)
        val notification = NotificationGroupManager.getInstance()
            .getNotificationGroup(NOTIFICATION_GROUP_ID)
            .createNotification(
                "FactoryLine completed local work",
                "If it clarified what is proven, you can star Code Factory to follow updates. No workspace data is shared.",
                NotificationType.INFORMATION,
            )
        notification.addAction(object : NotificationAction("Star Code Factory") {
            override fun actionPerformed(event: AnActionEvent, notification: Notification) {
                BrowserUtil.browse(REPOSITORY_URL)
                notification.expire()
            }
        })
        notification.notify(project)
    }
}
