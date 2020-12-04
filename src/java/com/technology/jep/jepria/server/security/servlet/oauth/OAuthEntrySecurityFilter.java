package com.technology.jep.jepria.server.security.servlet.oauth;

import com.technology.jep.jepria.server.env.EnvironmentPropertySupport;
import com.technology.jep.jepria.server.security.servlet.MultiInstanceSecurityFilter;
import com.technology.jep.jepria.shared.exceptions.ApplicationException;
import org.apache.log4j.Logger;
import org.jepria.oauth.sdk.*;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static com.technology.jep.jepria.server.security.JepSecurityConstant.OAUTH_TOKEN;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static org.jepria.oauth.sdk.OAuthConstants.*;

/**
 * <pre>
 * Фильтр для GUI url-mapping.
 * Применяется для *.jsp/Servlet'ов которые возвращают html-страницы.
 * В первую очередь для Entry.jsp в GWT приложениях.
 * @see <a href="http://google.com">https://github.com/Jepria/jepria-showcase</a>
 * </pre>
 */
public class OAuthEntrySecurityFilter extends MultiInstanceSecurityFilter {
  
  private static Logger logger = Logger.getLogger(OAuthEntrySecurityFilter.class.getName());
  
  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    super.init(filterConfig);
  }
  
  @Override
  public void doFilter(final ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;
    
    if (isSubPath(request.getServletPath())) {
      filterChain.doFilter(servletRequest, servletResponse);
      return;
    }
    
    OAuthRequestWrapper oauthRequest;
    try {
      oauthRequest = request instanceof OAuthRequestWrapper ? (OAuthRequestWrapper) request : new OAuthRequestWrapper(request);
    } catch (ApplicationException e) {
      e.printStackTrace();
      throw new ServletException(e);
    }
    
    if (securityRoles.size() == 0 && !passAllRoles) {
      /**
       * For public resource: authorize request, if it has token. (for cases where JepMainServiceServlet is public)
       */
      String token = oauthRequest.getTokenFromRequest();
      if (token != null) {
        oauthRequest.authenticate(response);
      }
      filterChain.doFilter(oauthRequest, servletResponse);
      return;
    } else {
      /**
       * Если запрос содержит авторизационный код, то следует запросить по нему токен.
       */
      if (oauthRequest.getParameter(CODE) != null && oauthRequest.getParameter(STATE) != null) {
        String state = getState(request, response);
        /**
         * Обязательная проверка CSRF
         */
        if (state != null) {
          try {
            TokenResponse tokenObject = oauthRequest.getToken(request.getParameter(CODE));
            if (tokenObject != null) {
              String token = tokenObject.getAccessToken();
              Cookie tokenCookie = new Cookie(OAUTH_TOKEN, token);
              tokenCookie.setSecure(request.isSecure());
              tokenCookie.setPath("/");
              tokenCookie.setHttpOnly(true);
              response.addCookie(tokenCookie);
              response.sendRedirect(state);
              return;
            } else {
              logger.error("Token request failed");
              throw new ServletException("Token request failed");
            }
          } catch (Throwable th) {
            th.printStackTrace();
            throw new RuntimeException(th);
          }
        } else {
          logger.error("State param is not valid");
          oauthRequest.buildAuthorizationRequest(response);
          return;
        }
      } else if (oauthRequest.getParameterMap().size() == 1 && oauthRequest.getParameter(STATE) != null) {
        /**
         * Вход после logout;
         */
        String state = getState(request, response);
        /**
         * Обязательная проверка CSRF
         */
        if (state != null) {
          response.sendRedirect(state);
          return;
        }
      }
      
      if (oauthRequest.authenticate(response)) {
        if (securityRoles.stream().anyMatch(oauthRequest::isUserInRole) || passAllRoles) {
          filterChain.doFilter(oauthRequest, servletResponse);
        } else {
          response.sendError(SC_FORBIDDEN, "Access denied");
        }
      } else {
        oauthRequest.buildAuthorizationRequest(response);
        return;
      }
    }
  }
  
  private String getState(HttpServletRequest request, HttpServletResponse response) {
    String state = request.getParameter(STATE);
    Cookie[] cookies = request.getCookies();
    if (cookies != null && cookies.length > 0) {
      for (Cookie cookie : cookies) {
        if (cookie.getName().equals(state)) {
          cookie.setMaxAge(0);
          response.addCookie(cookie);
          return cookie.getValue();
        }
      }
    }
    return null;
  }
  
  @Override
  public void destroy() {
    securityRoles = null;
  }
}
