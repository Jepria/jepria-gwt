package com.technology.jep.jepria.client.ui.toolbar;

/**
 * Интерфейс инструментальной панели с заголовком.
 */
public interface ToolBarWithHeaderView extends ToolBarView {
  
  /**
   * Устанавливает текст заголовка.
   */
  void setHeaderHTML(String text);
}
