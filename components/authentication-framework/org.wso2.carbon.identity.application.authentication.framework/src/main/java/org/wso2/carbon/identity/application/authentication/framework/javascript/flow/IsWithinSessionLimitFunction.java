/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.carbon.identity.application.authentication.framework.javascript.flow;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.SessionValidationConfigParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static java.lang.Integer.parseInt;

/**
 * Function to check if the given user has valid number of sessions.
 * The purpose is to perform dynamic authentication selection based on the active session count.
 */
public class IsWithinSessionLimitFunction implements IsValidFunction {

    private static final Log log = LogFactory.getLog(IsWithinSessionLimitFunction.class);
    private static final String USERNAME_CONFIG_NAME = "AnalyticsCredentials.Username";
    private static final String PASSWORD_CONFIG_NAME = "AnalyticsCredentials.Password";
    private static final Map<String, Object> configurations = SessionValidationConfigParser.getInstance()
            .getConfiguration();

    /**
     * Method to validate user session a given the authentication context and set of required attributes
     *
     * @param context Authentication context
     * @param map     Hash map of attributes required for validation
     * @return boolean value indicating the validation success/failure
     * @throws AuthenticationFailedException when exception occurred in session retrieving method
     */
    @Override
    public Boolean validate(JsAuthenticationContext context, Map<String, String> map)
            throws AuthenticationFailedException {

        boolean state = false;
        int sessionLimit = getSessionLimitFromMap(map);
        AuthenticatedUser authenticatedUser = context.getWrapped().getLastAuthenticatedUser();

        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Unable to find the Authenticated user from previous step");
        }
        try {
            int sessionCount = getActiveSessionCount(authenticatedUser);
            if (sessionCount < sessionLimit) {
                state = true;
            }
        } catch (IOException | FrameworkException e) {
            if(log.isDebugEnabled()){
                log.debug("Problem occurred in session data retrieving");
            }
            throw new AuthenticationFailedException("Problem occurred in session data retrieving", e);
        } catch (NumberFormatException e) {
            if(log.isDebugEnabled()){
                log.debug("Failed to retrieve session count from response");
            }
            throw new AuthenticationFailedException("Failed to retrieve session count from response", e);
        }
        return state;
    }

    /**
     * Method used for adding authentication header for httpMethod.
     *
     * @param httpMethod httpMethod that needs auth header to be added
     * @param username   username of user
     * @param password   password of the user
     */
    private void setAuthorizationHeader(HttpRequestBase httpMethod, String username, String password) {

        String toEncode = username + FrameworkConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR + password;
        byte[] encoding = Base64.encodeBase64(toEncode.getBytes(Charset.forName(StandardCharsets.UTF_8.name())));
        String authHeader = new String(encoding, Charset.defaultCharset());
        httpMethod.addHeader(HTTPConstants.HEADER_AUTHORIZATION,
                FrameworkConstants.JSSessionCountValidation.AUTH_TYPE_KEY + authHeader);
    }

    /**
     * Method for generating the table query for retrieving session information.
     *
     * @param tenantDomain Tenant Domain User belong to
     * @param username     Username of the user
     * @param userStore    Userstore of the user
     * @return Query String
     */
    private String getQuery(String tenantDomain, String username, String userStore) {

        return FrameworkConstants.JSSessionCountValidation.QUOTE +
                FrameworkConstants.JSSessionCountValidation.TENANT_DOMAIN_TAG +
                FrameworkConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR +
                tenantDomain +
                FrameworkConstants.JSSessionCountValidation.AND_TAG +
                FrameworkConstants.JSSessionCountValidation.USERNAME_TAG +
                FrameworkConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR +
                username +
                FrameworkConstants.JSSessionCountValidation.AND_TAG +
                FrameworkConstants.JSSessionCountValidation.USER_STORE_TAG +
                FrameworkConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR +
                userStore +
                FrameworkConstants.JSSessionCountValidation.QUOTE;
    }

    /**
     * Method for retrieving user defined maximum session limit from parameter map
     *
     * @param map parameter map passed from JS
     * @return inter indicating the maximum session Limit
     */
    private int getSessionLimitFromMap(Map<String, String> map) {

        return parseInt(map.get(FrameworkConstants.JSSessionCountValidation.SESSION_LIMIT_TAG));
    }

    /**
     * Method to retrieve active session count for the given authenticated user
     *
     * @param authenticatedUser Authenticated user object
     * @return current active session count
     * @throws IOException        When reading response from the REST call is failed
     * @throws FrameworkException When the REST response is not in 200 state
     */
    private int getActiveSessionCount(AuthenticatedUser authenticatedUser) throws IOException, FrameworkException {

        int sessionCount;
        String data = "{" +

                FrameworkConstants.JSSessionCountValidation.TABLE_NAME_TAG +
                FrameworkConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR +
                FrameworkConstants.JSSessionCountValidation.ACTIVE_SESSION_TABLE_NAME + "," +
                FrameworkConstants.JSSessionCountValidation.QUERY_TAG +
                FrameworkConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR +
                getQuery(authenticatedUser.getTenantDomain(), authenticatedUser.getUserName(), authenticatedUser
                        .getUserStoreDomain()) +
                "}";

        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        StringEntity entity = new StringEntity(data, ContentType.APPLICATION_JSON);
        HttpClient httpClient = httpClientBuilder.build();
        HttpPost request = new HttpPost(FrameworkConstants.JSSessionCountValidation.TABLE_SEARCH_COUNT_URL);

        setAuthorizationHeader(request,
                configurations.get(USERNAME_CONFIG_NAME).toString(),
                configurations.get(PASSWORD_CONFIG_NAME).toString());
        request.addHeader(FrameworkConstants.JSSessionCountValidation.CONTENT_TYPE_TAG, "application/json");
        request.setEntity(entity);
        HttpResponse response = httpClient.execute(request);

        if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(response.getEntity().getContent(),
                    FrameworkConstants.JSSessionCountValidation.UTF_8_TAG));
            StringBuilder responseResult = new StringBuilder();
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                responseResult.append(line);
            }
            sessionCount = parseInt(responseResult.toString());
            bufferedReader.close();
            return sessionCount;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Endpoint responded with " + response.getStatusLine().getStatusCode() + " status code");
            }
            throw new FrameworkException("Failed to retrieve data from endpoint");
        }

    }
}
