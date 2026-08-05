package app.factoryline.intellij

import com.intellij.ide.BrowserUtil
import com.intellij.ide.plugins.PluginManagerCore
import com.intellij.ide.util.PropertiesComponent
import com.intellij.notification.Notification
import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.extensions.PluginId
import com.intellij.openapi.project.Project

object FactoryLineGitHubStarPrompt {
    private const val PLUGIN_ID = "app.factoryline"
    private const val PROMPTED_VERSION_KEY = "factoryline.githubStarPromptedVersion"
    private const val NOTIFICATION_GROUP_ID = "FactoryLine"
    private const val REPOSITORY_URL = "https://github.com/zrk222/code-factory"

    fun shouldOffer(exitCode: Int?, timedOut: Boolean, promptedVersion: String?, installedVersion: String): Boolean =
        exitCode == 0 && !timedOut && promptedVersion != installedVersion

    fun afterSuccessfulLocalWork(project: Project, result: CommandResult) {
        val installedVersion = PluginManagerCore.getPlugin(PluginId.getId(PLUGIN_ID))?.version ?: "0.8.0"
        val properties = PropertiesComponent.getInstance()
        if (!shouldOffer(result.exitCode, result.timedOut, properties.getValue(PROMPTED_VERSION_KEY), installedVersion)) {
            return
        }
        properties.setValue(PROMPTED_VERSION_KEY, installedVersion)
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
