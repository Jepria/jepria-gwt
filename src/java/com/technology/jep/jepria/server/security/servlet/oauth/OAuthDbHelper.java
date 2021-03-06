package com.technology.jep.jepria.server.security.servlet.oauth;

import com.technology.jep.jepria.server.db.Db;
import com.technology.jep.jepria.shared.exceptions.ApplicationException;
import oracle.jdbc.OracleTypes;

import java.sql.CallableStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;

import static org.jepria.oauth.sdk.OAuthConstants.CLIENT_SECRET;

public class OAuthDbHelper {
  
  public static String getClientSecret(Db db, String clientId) throws NullPointerException, ApplicationException, SQLException {
    Objects.requireNonNull(clientId);
    Objects.requireNonNull(db);
    String sqlQuery = "begin " +
      "? := pkg_OAuth.findClient(" +
        "clientShortName => ?," +
        "clientName => ''," +
        "clientNameEn => ''," +
        "maxRowCount => 1," +
        "operatorId => 1" +
      "); " +
      "end;";
    String result = null;
    try (CallableStatement cs = db.prepare(sqlQuery)) {
      cs.registerOutParameter(1, OracleTypes.CURSOR);
      cs.setString(2, clientId);
      cs.executeQuery();

      //Получим набор.
      ResultSet resultSet = (ResultSet) cs.getObject(1);
      if (resultSet.next()) {
        result = resultSet.getString(CLIENT_SECRET);
      }
    } catch (SQLException ex) {
      throw new ApplicationException(ex.getMessage(), ex);
    }
    return result;
  }
  
}
