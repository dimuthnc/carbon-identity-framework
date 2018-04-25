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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Map;

/**
 * TODO:Class level comment
 */
public class IsWithinSessionLimitFunction implements IsValidFunction {

    private static final Log log = LogFactory.getLog(IsWithinSessionLimitFunction.class);

    @Override
    public Boolean validate(JsAuthenticationContext context, Map<String, String> map) {

        int sessionLimit = Integer.valueOf(map.get("sessionLimit"));
        boolean state = false;
        AuthenticatedUser authenticatedUser = context.getWrapped().getLastAuthenticatedUser();
        if (authenticatedUser == null) {
            return null;
        }

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

        try {
            HttpPost request = new HttpPost(FrameworkConstants.JSSessionCountValidation.TABLE_SEARCH_COUNT_URL);
            setAuthorizationHeader(request, FrameworkConstants.JSSessionCountValidation.USERNAME_CONFIG, FrameworkConstants.JSSessionCountValidation.PASSWORD_CONFIG);
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
                int sessionCount = Integer.valueOf(responseResult.toString());
                if (sessionCount < sessionLimit) {
                    state = true;
                }

            } else {
                log.error("Failed to retrieve data from endpoint. Error code :" +
                        response.getStatusLine().getStatusCode());
            }

        } catch (IOException e) {
            log.error("Problem occurred in session data retrieving", e);
        }

        return state;
    }

    private void setAuthorizationHeader(HttpRequestBase httpMethod, String username, String password) {

        String toEncode = username + FrameworkConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR + password;
        byte[] encoding = Base64.encodeBase64(toEncode.getBytes());
        String authHeader = new String(encoding, Charset.defaultCharset());
        httpMethod.addHeader(HTTPConstants.HEADER_AUTHORIZATION, FrameworkConstants.JSSessionCountValidation.AUTH_TYPE_KEY + authHeader);

    }

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
                FrameworkConstants.JSSessionCountValidation.USERSTORE_TAG +
                FrameworkConstants.JSSessionCountValidation.ATTRIBUTE_SEPARATOR +
                userStore +
                FrameworkConstants.JSSessionCountValidation.QUOTE;
    }
}
