package com.technology.jep.jepria.client.entrance;

import com.google.gwt.user.client.rpc.AsyncCallback;
import com.technology.jep.jepria.shared.service.JepMainServiceAsync;

/**
 * TODO Напрашивается переименование
 * <p>
 * Класс обработки Logout
 */
public class Entrance {

  private static JepMainServiceAsync mainService = null;

  public static void setService(JepMainServiceAsync service) {
    mainService = service;
  }

  /**
   * Выход из приложения
   */
  public static void logout() {
    mainService.logout(getLocation(), new AsyncCallback<String>() {
      public void onFailure(Throwable caught) {
        reload();
      }

      public void onSuccess(String logoutUrl) {
        if (logoutUrl != null && !logoutUrl.equals(getLocation())) {
          goTo(logoutUrl);
        } else {
          reload();
        }
      }
    });
  }

  public native static String getLocation()/*-{
    return $wnd.location.href;
  }-*/;

  /**
   * Перезагрузка страницы (с учётом окружения - с Navigation или без)
   */
  public native static void reload() /*-{
    $wnd.location.reload(true); // На
  }-*/;

  /**
   * Переход по заданному Url
   *
   * @param url
   */
  public native static void goTo(String url) /*-{
    $wnd.location.href = url;
  }-*/;
}
