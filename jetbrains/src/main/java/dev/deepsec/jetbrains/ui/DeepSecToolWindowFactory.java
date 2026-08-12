package dev.deepsec.jetbrains.ui;

import com.intellij.openapi.project.DumbAware;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import org.jetbrains.annotations.NotNull;

/** Creates the on-demand VibeGuard review surface without adding startup work. */
public final class DeepSecToolWindowFactory implements ToolWindowFactory, DumbAware {
  @Override
  public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
    DeepSecPanel panel = new DeepSecPanel(project);
    Content content = ContentFactory.getInstance().createContent(panel, "", false);
    content.setDisposer(panel);
    toolWindow.getContentManager().addContent(content);
  }
}
