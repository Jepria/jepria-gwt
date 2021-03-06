package com.technology.jep.jepria.client.widget.list.cell;

import static com.technology.jep.jepria.client.JepRiaClientConstant.JepTexts;

import java.util.Set;

import com.google.gwt.cell.client.AbstractCell;
import com.google.gwt.safehtml.shared.SafeHtmlBuilder;

/**
 * Реализация ячейки,
 * которая отображает на списочной форме логическое (True/False) значение в текстовом виде (Да/Нет).<br/>
 * Также поддерживается null, в этом случае в ячейке выводится пустая строка.
 */
public class BooleanCell extends AbstractCell<Boolean> {

  /**
   * Создает объект BooleanCell c заданными событиями.<br/> 
   * Реализация заключается в вызове конструктора базового класса AbstractCell.<br/>
   * Подробности смотрите в com.google.gwt.cell.client.AbstractCell
   * 
   * @param consumedEvents события, используемые ячейкой
   * @see com.google.gwt.cell.client.AbstractCell
   */
  public BooleanCell(String... consumedEvents) {
    super(consumedEvents);
  }

  /**
   * Создает объект BooleanCel c заданными событиями.<br/>
   * Реализация заключается в вызове конструктора базового класса AbstractCell.<br/>
   * Подробности смотрите в com.google.gwt.cell.client.AbstractCell
   * 
   * @param consumedEvents события, используемые ячейкой
   * @see com.google.gwt.cell.client.AbstractCell
   */
  public BooleanCell(Set<String> consumedEvents) {
    super(consumedEvents);
  }

  /**
   * Отрисовывает ячейку таблицы.
   * @param context контекст ячейки 
   * @param value значение ячейки
   * @param sb объект, в который помещается конечное содержимое ячейки 
   */
  @Override
  public void render(Context context, Boolean value, SafeHtmlBuilder sb) {
    
    String label = "";
    
    if (value != null){
      label = Boolean.TRUE.equals(value) ? JepTexts.yes() : JepTexts.no();
    }
    
    sb.appendEscaped(label);
  }
}
