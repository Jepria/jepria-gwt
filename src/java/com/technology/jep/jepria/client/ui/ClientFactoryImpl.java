package com.technology.jep.jepria.client.ui;

import com.google.gwt.event.shared.EventBus;
import com.technology.jep.jepria.client.JepRiaClientConstant;
import com.technology.jep.jepria.client.exception.ExceptionManager;
import com.technology.jep.jepria.client.exception.ExceptionManagerImpl;
import com.technology.jep.jepria.client.history.place.JepPlaceController;
import com.technology.jep.jepria.client.message.JepMessageBox;
import com.technology.jep.jepria.client.message.JepMessageBoxImpl;
import com.technology.jep.jepria.shared.log.JepLogger;
import com.technology.jep.jepria.shared.log.JepLoggerImpl;
import com.technology.jep.jepria.shared.text.JepRiaText;

abstract public class ClientFactoryImpl<E extends EventBus>  implements ClientFactory<E> {

  protected static JepLogger logger;
  
  protected JepPlaceController placeController = null;
  protected E eventBus = null;
  
  protected JepMessageBox messageBox;
  protected ExceptionManager exceptionManager;

  public ClientFactoryImpl() {
    
    logger = JepLoggerImpl.instance;
    messageBox = JepMessageBoxImpl.instance;
    exceptionManager = ExceptionManagerImpl.instance;
    
    initActivityMappers(this);
  }
  
  @Override
  public E getEventBus() {
    if (eventBus == null) {
      eventBus = createEventBus();
    }
    return eventBus;
  }
  
  /**
   * Создание шины событий.<br/>
   *
   * @return новый экземпляр
   */
  protected abstract E createEventBus();
  
  public JepLogger getLogger() {
    return logger;
  }
  
  public JepMessageBox getMessageBox() {
    return messageBox;
  }
 
  public ExceptionManager getExceptionManager() {
    return exceptionManager;
  }

  /**
   * Тексты JepRia.
   */
  public JepRiaText getTexts() {
    return JepRiaClientConstant.JepTexts;
  }
  
  /**
   * Метод вызывается в конструкторе с целью инициализации ActivityMapper'ов и ActivityManager'ов.<br/>
   * Необходимо для возможности соответствующих презентеров (Activity в понятиях GWT) прослушивать, подписываться и обрабатывать события,
   * с которыми работает EventBus.
   * <br><br>
   * Предназначен для переопределения в потомках.
   * <b>Порядок инициализации ActivityMapper'ов важен:</b> он определяет порядок, в котором подписчики будут обрабатывать полученные события.
   *
   * @param clientFactory клиентская фабрика модуля
   */
  protected void initActivityMappers(ClientFactory<E> clientFactory) {
  }
  
}
