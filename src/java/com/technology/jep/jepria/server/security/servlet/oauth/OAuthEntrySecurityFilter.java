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
  protected String clientId;
  protected String clientSecret;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    super.init(filterConfig);
    clientId = EnvironmentPropertySupport.getInstance(filterConfig.getServletContext()).getProperty(moduleName + "/" + CLIENT_ID_PROPERTY);
    clientSecret = EnvironmentPropertySupport.getInstance(filterConfig.getServletContext()).getProperty(moduleName + "/" + CLIENT_SECRET_PROPERTY);
  }

  /**
   * Request token from OAuth server
   */
  private TokenResponse getToken(HttpServletRequest httpServletRequest, String code) throws IOException, URISyntaxException {
    logger.trace("BEGIN getToken()");
    TokenRequest tokenRequest = TokenRequest.Builder()
      .resourceURI(URI.create(httpServletRequest.getRequestURL().toString().replaceFirst(httpServletRequest.getRequestURI(), OAUTH_TOKEN_CONTEXT_PATH)))
      .grantType(GrantType.AUTHORIZATION_CODE)
      .clientId(clientId)
      .clientSecret(clientSecret)
      .redirectionURI(URI.create(httpServletRequest.getRequestURL().toString()))
      .authorizationCode(code)
      .build();
    TokenResponse response = tokenRequest.execute();
    logger.trace("END getToken()");
    return response;
  }

  private void buildAuthorizationRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
    logger.trace("BEGIN buildAuthorizationRequest()");
    try {
      /**
       * Create state param and save it to Cookie for checking in future to prevent 'Replay attacks'
       */
      String redirectUri;
      if (httpServletRequest.getQueryString() != null && httpServletRequest.getQueryString().length() > 0) {
        redirectUri = httpServletRequest.getRequestURL().append("?").append(httpServletRequest.getQueryString()).toString();
      } else {
        redirectUri = httpServletRequest.getRequestURL().toString();
      }
      State state = new State();
      Cookie stateCookie = new Cookie(state.toString(), redirectUri);
      stateCookie.setSecure(httpServletRequest.isSecure());
      stateCookie.setPath(httpServletRequest.getContextPath());
      stateCookie.setHttpOnly(true);
      httpServletResponse.addCookie(stateCookie);

      String authorizationRequestURI = AuthorizationRequest.Builder()
        .resourceURI(URI.create(httpServletRequest.getRequestURL().toString().replaceFirst(httpServletRequest.getRequestURI(), OAUTH_AUTHORIZATION_CONTEXT_PATH)))
        .responseType(ResponseType.CODE)
        .clientId(clientId)
        .redirectionURI(URI.create(httpServletRequest.getRequestURL().toString()))
        .state(state)
        .build()
        .toString();

      httpServletResponse.sendRedirect(authorizationRequestURI);
    } catch (Throwable e) {
      e.printStackTrace();
    }
    logger.trace("END buildAuthorizationRequest()");
  }

  @Override
  public void doFilter(final ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    if (isSubPath(request.getServletPath())) {
      filterChain.doFilter(servletRequest, servletResponse);
      return;
    }

    /**
     * Если запрос содержит авторизационный код, то следует запросить по нему токен.
     */
    if (request.getParameter(CODE) != null && request.getParameter(STATE) != null) {
      String state = getState(request, response);
      /**
       * Обязательная проверка CSRF
       */
      if (state != null) {
        try {
          TokenResponse tokenObject = getToken(request, request.getParameter(CODE));
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
        buildAuthorizationRequest(request, response);
        return;
      }
    } else if (request.getParameterMap().size() == 1 && request.getParameter(STATE) != null) {
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
  
    OAuthRequestWrapper oauthRequest;
    try {
      oauthRequest = request instanceof OAuthRequestWrapper ? (OAuthRequestWrapper) request : new OAuthRequestWrapper(request);
    } catch (ApplicationException e) {
      e.printStackTrace();
      throw new ServletException(e);
    }
  
    if (securityRoles.size() == 0) {
      /**
       * For public resource: authorize request, if it has token. (for cases where JepMainServiceServlet is public)
       */
      String token = oauthRequest.getTokenFromRequest();
      if (token != null) {
        oauthRequest.authenticate(response);
      }
      filterChain.doFilter(oauthRequest, servletResponse);
      return;
    } else if (oauthRequest.authenticate(response)) {
      if (securityRoles.stream().anyMatch(oauthRequest::isUserInRole)) {
        filterChain.doFilter(oauthRequest, servletResponse);
      } else {
        response.sendError(SC_FORBIDDEN, "Access denied");
      }
    } else {
      buildAuthorizationRequest(request, response);
      return;
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
