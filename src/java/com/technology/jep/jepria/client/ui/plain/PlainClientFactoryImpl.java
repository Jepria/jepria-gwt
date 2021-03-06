package com.technology.jep.jepria.client.ui.plain;

import com.google.gwt.activity.shared.ActivityManager;
import com.google.gwt.core.client.GWT;
import com.google.gwt.user.client.ui.AcceptsOneWidget;
import com.google.gwt.user.client.ui.IsWidget;
import com.technology.jep.jepria.client.history.place.PlainPlaceController;
import com.technology.jep.jepria.client.ui.ClientFactory;
import com.technology.jep.jepria.client.ui.ClientFactoryImpl;
import com.technology.jep.jepria.client.ui.eventbus.main.MainEventBus;
import com.technology.jep.jepria.client.ui.eventbus.plain.PlainEventBus;
import com.technology.jep.jepria.client.ui.main.MainClientFactoryImpl;
import com.technology.jep.jepria.shared.record.JepRecordDefinition;
import com.technology.jep.jepria.shared.service.JepMainServiceAsync;
import com.technology.jep.jepria.shared.service.data.JepDataService;
import com.technology.jep.jepria.shared.service.data.JepDataServiceAsync;

/**
 * Реализация клиентской фабрики простого модуля.
 */
abstract public class PlainClientFactoryImpl<E extends PlainEventBus, S extends JepDataServiceAsync> 
  extends ClientFactoryImpl<E> implements PlainClientFactory<E, S> {

  /**
   * Представление модуля.
   */
  protected IsWidget moduleView = null;

  /**
   * Сервис работы с данными.
   */
  protected S dataService = null;

  /**
   * Определение данных модуля.
   */
  protected JepRecordDefinition recordDefinition;
  
  /**
   * Создает клиентскую фабрику модуля с заданным определением данных модуля.
   *
   * @param recordDefinition определение данных модуля
   */
  public PlainClientFactoryImpl(JepRecordDefinition recordDefinition) {
    this.recordDefinition = recordDefinition;
  }

  /**
   * Получение представления (View) модуля.<br/>
   * Если объект еще не создан, то метод создает его и возвращает созданный объект. 
   *
   * @return представление (View) модуля
   */
  @Override
  public IsWidget getModuleView() {
    if(moduleView == null) {
      moduleView = new PlainModuleViewImpl();
    }
    return moduleView;
  }

  /**
   * Получение клиентской фабрики главного модуля.
   *
   * @return клиентская фабрика главного модуля
   */
  @Override
  public MainClientFactoryImpl<MainEventBus, JepMainServiceAsync> getMainClientFactory() {
    return MainClientFactoryImpl.instance;
  }

  /**
   * Получение объекта управления Place'ами модуля.
   *
   * @return объект управления Place'ами модуля
   */
  @Override
  public PlainPlaceController getPlaceController() {
    if(placeController == null) {
      placeController = new PlainPlaceController((PlainEventBus)getEventBus(), this);
    }
    return (PlainPlaceController) placeController;
  }
  
  @SuppressWarnings("unchecked")/*допустимо*/
  @Override
  protected E createEventBus() {
    return (E) new PlainEventBus();
  }
  
  @Override
  public S getService() {
    if (dataService == null) {
      dataService = createService();
    }
    return dataService;
  }
  
  /**
   * Создание сервиса работы с данными модуля.<br/>
   *
   * @return новый экземпляр
   */
  protected S createService() {
    return GWT.create(JepDataService.class);
  }

  /**
   * Получение определения данных модуля.
   *
   * @return определение данных модуля
   */
  public JepRecordDefinition getRecordDefinition() {
    return recordDefinition;
  }
  
  @Override
  protected void initActivityMappers(ClientFactory<E> clientFactory) {
    
    super.initActivityMappers(clientFactory);
    
    /*
     * Создадим ActivityMapper и ActivityManager для модуля.
     */
    ActivityManager plainActivityManager = new ActivityManager(
      new PlainActivityMapper((PlainClientFactory<E, S>)clientFactory)
      , clientFactory.getEventBus()
    );

    // Необходимо для предотвращения де-регистрации в EventBus и сбором garbage collection (смотри описание метода в JavaDoc GWT).
    plainActivityManager.setDisplay(new AcceptsOneWidget() {
      public void setWidget(IsWidget widget) {}
    });
  }
  
}
