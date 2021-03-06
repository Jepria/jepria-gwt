package com.technology.jep.jepria.client.ui.main;

import static com.technology.jep.jepria.client.JepRiaClientConstant.JepTexts;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.google.gwt.activity.shared.ActivityManager;
import com.google.gwt.core.client.GWT;
import com.google.gwt.place.shared.Place;
import com.google.gwt.user.client.ui.AcceptsOneWidget;
import com.google.gwt.user.client.ui.IsWidget;
import com.technology.jep.jepria.client.history.place.JepSearchPlace;
import com.technology.jep.jepria.client.history.place.MainPlaceController;
import com.technology.jep.jepria.client.history.scope.JepScopeStack;
import com.technology.jep.jepria.client.ui.ClientFactory;
import com.technology.jep.jepria.client.ui.ClientFactoryImpl;
import com.technology.jep.jepria.client.ui.eventbus.main.MainEventBus;
import com.technology.jep.jepria.shared.service.JepMainService;
import com.technology.jep.jepria.shared.service.JepMainServiceAsync;

/**
 * Базовый класс реализации для клиентской фабрики приложения.<br/>
 * <br/>
 * Пример реализации клиентской фабрики прикладного приложения:
 * <pre>
 * ...
 * public class &lt;Application Name&gt;ClientFactoryImpl&lt;E extends MainEventBus, S extends JepMainServiceAsync&gt;
 *   extends JepMainClientFactoryImpl&lt;E&gt;
 *     implements JepMainClientFactory&lt;E&gt; {
 *
 *   static public JepMainClientFactory&lt;MainEventBus&gt; getInstance() {
 *     if(instance == null) {
 *       instance = new &lt;Application Name&gt;ClientFactoryImpl&lt;MainEventBus, JepMainServiceAsync&gt;();
 *     }
 *     return instance;
 *   }
 * 
 *   private &lt;Application Name&gt;ClientFactoryImpl() {
 *     super(new String[] {
 *       &lt;MODULE NAME 1&gt;_MODULE_ID
 *       , &lt;MODULE NAME 2&gt;_MODULE_ID
 *       ...
 *       , &lt;MODULE NAME N&gt;_MODULE_ID
 *     },
 *     new String[] {
 *       &lt;application Name&gt;Text.submodule_&lt;module Name 1&gt;_title()
 *       , &lt;application Name&gt;Text.submodule_&lt;module Name 2&gt;_title()
 *       ...
 *       , &lt;application Name&gt;Text.submodule_&lt;module Name N&gt;_title()
 *     });
 *     
 *     eventBus = new &lt;Application Name&gt;MainEventBus(this);
 *     placeController = new MainPlaceController((MainEventBus)eventBus, this);
 *     
 *     initActivityMappers(this);
 *   }
 *   
 *   public Activity createMainModulePresenter() {
 *     return new &lt;Application Name&gt;MainModulePresenter(this);
 *   }
 *   
 *   public void getPlainClientFactory(String moduleId, final LoadAsyncCallback&lt;JepBaseClientFactory&lt;PlainEventBus&gt;&gt; callback) {
 *     if(&lt;MODULE NAME 1&gt;_MODULE_ID.equals(moduleId)) {
 *       GWT.runAsync(new LoadPlainClientFactory(callback) {
 *         public JepBaseClientFactory&lt;PlainEventBus&gt; getPlainClientFactory() {
 *           return &lt;Module Name 1&gt;ClientFactoryImpl.getInstance();
 *         }
 *       });
 *     } else if(&lt;MODULE NAME 2&gt;_MODULE_ID.equals(moduleId)) {
 *       GWT.runAsync(new LoadPlainClientFactory(callback) {
 *         public JepBaseClientFactory&lt;PlainEventBus&gt; getPlainClientFactory() {
 *           return &lt;Module Name 2&gt;ClientFactoryImpl.getInstance();
 *         }
 *       });
 *       ...
 *     } else if(&lt;MODULE NAME N&gt;_MODULE_ID.equals(moduleId)) {
 *       GWT.runAsync(new LoadPlainClientFactory(callback) {
 *         public JepBaseClientFactory&lt;PlainEventBus&gt; getPlainClientFactory() {
 *           return &lt;Module Name N&gt;ClientFactoryImpl.getInstance();
 *         }
 *       });
 *     }
 *     
 *   }
 * 
 * }
 * </pre>
 */
public abstract class MainClientFactoryImpl<E extends MainEventBus, S extends JepMainServiceAsync> 
  extends ClientFactoryImpl<E> implements MainClientFactory<E, S> {
  
  /**
   * Поле для реализации singleton'а клиентской фабрики приложения.
   */
  public static MainClientFactoryImpl<MainEventBus, JepMainServiceAsync> instance = null;
  
  /**
   * Главное представление приложения.
   */
  protected IsWidget mainView = null;

  /**
   * Главный сервис приложения.
   */
  protected S mainService = null;

  /**
   * Список идентификаторов модулей приложения.
   */
  private final List<String> moduleIdsAbsList;
  
  /**
   * Создает клиентскую фабрику главного модуля приложения.
   * 
   * Пример использования:<pre>
   * 
   * Было:
   * MainClientFactoryImplExt() {
   *   super(
   *     new String[]{
   *       id1,
   *       id2,
   *       id3
   *     },
   *     new String[]{
   *       name1, 
   *       name2, 
   *       name3
   *     },
   *   );
   * }
   * 
   * Стало:
   * MainClientFactoryImplExt() {
   *   super(
   *     new ModuleItem(id1, name1),
   *     new ModuleItem(id2, name2),
   *     new ModuleItem(id3, name3)
   *   );
   * }</pre>
   *
   * @param moduleIds идентификаторы модулей приложения (вместе с наименованиями)
   */
  public MainClientFactoryImpl(String...moduleIds) {
    
    logger.debug(this.getClass() + ".MainClientFactoryImpl() moduleIds = " + Arrays.toString(moduleIds));
    
    if (moduleIds == null || moduleIds.length == 0) {
      throw new IllegalArgumentException(JepTexts.errors_mainClientFactory_illegalArgument_moduleIds());
    }
    
    
    moduleIdsAbsList = Collections.unmodifiableList(Arrays.asList(moduleIds));
    
    JepScopeStack.instance.setMainClientFactory((MainClientFactory)this);
  }

  /**
   * Получение объекта управления Place'ами приложения.<br/>
   * Если объект еще не создан, то метод создает его и возвращает созданный объект. 
   *
   * @return объект управления Place'ами приложения
   */
  @Override
  public MainPlaceController getPlaceController() {
    if(placeController == null) {
      placeController = new MainPlaceController((MainEventBus)getEventBus(), this);
    }
    return (MainPlaceController) placeController;
  }

  @SuppressWarnings("unchecked")/*допустимо*/
  @Override
  protected E createEventBus() {
    return (E) new MainEventBus();
  }

  /**
   * Получение Place'а по умолчанию для приложения.
   *
   * @return Place по умолчанию для приложения
   */
  @Override
  public Place getDefaultPlace() {
    return new JepSearchPlace();
  }

  @Override
  public S getMainService() {
    if (mainService == null) {
      mainService = createMainService();
    }
    return mainService;
  }
  
  /**
   * Создание главного сервиса приложения.<br/>
   *
   * @return новый экземпляр
   */
  protected S createMainService() {
    return GWT.create(JepMainService.class);
  }

  @Override
  public List<String> getModuleIds() {
    return moduleIdsAbsList;
  }
  
  @Override
  protected void initActivityMappers(ClientFactory<E> clientFactory) {
    
    super.initActivityMappers(clientFactory);
    
    /*
     * Создадим ActivityMapper и ActivityManager для главного модуля (приложения).
     */
    ActivityManager mainActivityManager = new MainActivityManager(
      new MainActivityMapper((MainClientFactory<E, S>)clientFactory)
      , clientFactory.getEventBus()
    );

    // Необходимо для предотвращения де-регистрации в EventBus и сбором garbage collection (смотри описание метода в JavaDoc GWT).
    mainActivityManager.setDisplay(new AcceptsOneWidget() {
      public void setWidget(IsWidget widget) {}
    });
  }
  
}
