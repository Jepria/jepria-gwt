package com.technology.jep.jepria.server.security.module;

import com.technology.jep.jepcommon.security.pkg_Operator;
import com.technology.jep.jepria.server.db.Db;
import com.technology.jep.jepria.server.security.servlet.oauth.OAuthRequestWrapper;
import org.apache.log4j.Logger;
import org.jepria.oauth.sdk.State;
import com.technology.jep.jepria.server.env.EnvironmentPropertySupport;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Objects;

import static com.technology.jep.jepria.server.security.JepSecurityConstant.*;
import static org.jepria.oauth.sdk.OAuthConstants.*;

/**
 * Модуль поддержки безопасности для Tomcat
 * TODO Убрать избыточный код из аналогов
 */
public class JepSecurityModuleImpl extends JepAbstractSecurityModule {

  static {
    logger = Logger.getLogger(JepSecurityModuleImpl.class.getName());
  }

  private JepSecurityModuleImpl() {
  }

  /**
   * Возвращает объект типа JepSecurityModule из сессии. Если объект не
   * найден в сессии или устаревший (например, оставшийся в сессии модуля после logout()),
   * то создается новый объект и помещается в сессию.
   *
   * @param request запрос, из которого получим сессию
   * @return объект типа JepSecurityModule из сессии
   * TODO Попробовать уменьшить размер синхронизируемого кода (synchronized). Точно ли нужна синхронизация ?
   */
  public static synchronized JepSecurityModule getInstance(HttpServletRequest request) {
    HttpSession session = request.getSession();
    Principal principal = request.getUserPrincipal();
    JepSecurityModuleImpl securityModule;
    securityModule = (JepSecurityModuleImpl) session.getAttribute(JEP_SECURITY_MODULE_ATTRIBUTE_NAME);
    if (principal == null) { // Работает гость ?
      if (securityModule == null) { // Первый вход ?
        securityModule = new JepSecurityModuleImpl();
        session.setAttribute(JEP_SECURITY_MODULE_ATTRIBUTE_NAME, securityModule);
        securityModule.doLogonByGuest();
      }
    } else {  // Входили через SSO
      if (securityModule == null || securityModule.isObsolete(principal)) {
        securityModule = new JepSecurityModuleImpl();
        session.setAttribute(JEP_SECURITY_MODULE_ATTRIBUTE_NAME, securityModule);
        securityModule.updateSubject(principal);
      }
    }
    return securityModule;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String logout(HttpServletRequest request, HttpServletResponse response, String currentUrl) throws Exception {
    logger.info(this.getClass() + ".logout(request, response, " + currentUrl + ")");
    if (request instanceof OAuthRequestWrapper) {
      String clientId = request.getServletContext().getInitParameter(CLIENT_ID_PROPERTY);
      URL url = URI.create(currentUrl).toURL();
      State state = new State();
      Cookie stateCookie = new Cookie(state.toString(), currentUrl);
      stateCookie.setSecure(request.isSecure());
      stateCookie.setPath(request.getContextPath());
      stateCookie.setHttpOnly(true);
      response.addCookie(stateCookie);
      String hostUrl = url.getProtocol() + "://" + url.getHost() + (url.getPort() != -1 ? (":" + url.getPort()) : "");
      currentUrl = hostUrl + OAUTH_LOGOUT_CONTEXT_PATH + "?"
          + "&" + CLIENT_ID + "=" + clientId
          + "&" + REDIRECT_URI + "="
          + URLEncoder.encode(url.getPath().endsWith("/") ? url.getPath().substring(0, url.getPath().length() - 1) : url.getPath(),
          StandardCharsets.UTF_8.name()).replaceAll("\\+", "%20")
          + "&" + STATE + "=" + state.toString();
    }
    request.getSession().invalidate();
    request.logout();
    return currentUrl;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Integer getJepPrincipalOperatorId(Principal principal) {
    Integer result;
    if (isObsolete(principal)) { // Обновить свойства, если изменился информация об операторе
      updateSubject(principal);
    }
    result = operatorId;

    return result;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void updateSubject(Principal principal) {
    Db db = getDb();
    logger.trace(this.getClass() + ".updateSubject() BEGIN");
    String principalName = principal.getName();
    logger.trace("principalName = " + principalName);
    this.username = principalName;

    isAuthorizedBySso = principal != null;

    try {
      roles = pkg_Operator.getRoles(db, principalName);
      Integer logonOperatorId = pkg_Operator.logon(db, principalName);
      if (logonOperatorId != null) {
        operatorId = logonOperatorId;
      }
    } catch (SQLException ex) {
      logger.error("pkg_Operator error", ex);
    } finally {
      db.closeAll(); // освобождение соединения, берущегося в logon->db.prepare
    }

    logger.trace(this.getClass() + ".updateSubject() END");
  }

  /**
   * Проверка "свежести" объекта securityModule, закешированного в Http-сессии
   * Выполняется на основе сравнения значений operatorId principal-а и объекта jepSecurityModule.
   *
   * @param principal принципал
   * @return true, если объект jepSecurityModule устарел, иначе - false
   */
  protected boolean isObsolete(Principal principal) {
    return !Objects.equals(this.username, principal == null ? null : principal.getName());
  }
}
