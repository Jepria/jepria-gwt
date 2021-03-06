package com.technology.jep.jepria.server.dao.transaction.handler;

import com.technology.jep.jepria.server.dao.CallContext;

import java.sql.SQLException;

/**
 * Стандартная реализация обработчика завершения транзакции.<br/>
 * При кастомной реализации рекомендуется наследоваться от стандартной.
 */
public class EndTransactionHandlerImpl implements EndTransactionHandler {
  
  /**
   * Стандартная реализация метода, выполняемого после завершения транзакции.<br/>
   * Выполняет следующие действия:
   * <ul>
   *   <li>Если в ходе транзакции не возникло исключения, то транзакция фиксируется
   *   ({@link CallContext#commit()}).</li>
   *   <li>Если было перехвачено исключение (<code>caught != null</code>), транзакция
   *   откатывается ({@link CallContext#rollback()}).</li>
   *   <li>С помощью {@link CallContext#end()} освобождаются ресурсы.
   *   <li>Если в ходе транзакции возникло исключение, или же оно возникло во время
   *   commit либо rollback, выбрасывается последнее возникшее исключение.</li>
   * </ul>
   * @param caught перехваченное исключение
   */
  @Override
  public void handle(Throwable caught) {
    try {
      if (caught == null) {
        CallContext.commit();
      }
      else {
        CallContext.rollback();
      }
    } catch (SQLException e) {
      // Необходимо сигнализировать о последнем выброшенном исключении.
      caught = e;
    }
    finally {
      CallContext.end();
    }
  }

}
