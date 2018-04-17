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

import org.apache.axiom.om.OMElement;
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
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.SessionDataConstants;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Map;

/**
 * TODO:Class level comment
 */
public class GetSessionDataFunction implements GetDataFunction{

    private static final Log log = LogFactory.getLog(GetSessionDataFunction.class);
    OMElement sessionManagerConfigElement = IdentityConfigParser.getInstance()
            .getConfigElement("SessionLimitDataConfig");
    @Override
    public JSONObject retrieve(JsAuthenticationContext context, Map<String, String> map) {
        int retrieveCount = SessionDataConstants.RETRIEVE_COUNT;
        try{
            retrieveCount = Integer.valueOf(map.get("maxCount"));
        }catch (NullPointerException e){
            log.debug("Maximum session count value not found. Default value will be used");
        }
        JSONObject result = new JSONObject();
        AuthenticatedUser authenticatedUser = context.getWrapped().getLastAuthenticatedUser();
        if (authenticatedUser == null) {
            return null;
        }


        String data = "{" +
                SessionDataConstants.TABLE_NAME_TAG +
                SessionDataConstants.ATTRIBUTE_SEPARATOR +
                SessionDataConstants.ACTIVE_SESSION_TABLE_NAME + "," +
                SessionDataConstants.QUERY_TAG +
                SessionDataConstants.ATTRIBUTE_SEPARATOR +
                getQuery(authenticatedUser.getTenantDomain(), authenticatedUser.getUserName(), authenticatedUser
                        .getUserStoreDomain())
                +","+
                SessionDataConstants.START_TAG +
                SessionDataConstants.ATTRIBUTE_SEPARATOR +
                SessionDataConstants.START_INDEX + "," +
                SessionDataConstants.COUNT_TAG +
                SessionDataConstants.ATTRIBUTE_SEPARATOR +
                retrieveCount +
                "}";

        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        StringEntity entity = new StringEntity(data, ContentType.APPLICATION_JSON);
        HttpClient httpClient = httpClientBuilder.build();

        try {
            HttpPost request = new HttpPost(SessionDataConstants.TABLE_SEARCH_URL);
            setAuthorizationHeader(request, SessionDataConstants.USERNAME_CONFIG, SessionDataConstants.PASSWORD_CONFIG);
            request.addHeader(SessionDataConstants.CONTENT_TYPE_TAG, "application/json");
            request.setEntity(entity);

            HttpResponse response = httpClient.execute(request);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(response.getEntity().getContent(),
                        SessionDataConstants.UTF_8_TAG));
                StringBuilder responseResult = new StringBuilder();
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    responseResult.append(line);
                }
                JSONArray jsonArray = new JSONArray(responseResult.toString());
                result.put("sessions",jsonArray);


            } else {
                log.error("Failed to retrieve data from endpoint. Error code :" +
                        response.getStatusLine().getStatusCode());
            }

        } catch (IOException e) {
            log.error("Problem occurred in session data retrieving", e);
        }


        return result;
    }
    private void setAuthorizationHeader(HttpRequestBase httpMethod, String username, String password) {

        String toEncode = username + SessionDataConstants.ATTRIBUTE_SEPARATOR + password;
        byte[] encoding = Base64.encodeBase64(toEncode.getBytes());
        String authHeader = new String(encoding, Charset.defaultCharset());
        httpMethod.addHeader(HTTPConstants.HEADER_AUTHORIZATION, SessionDataConstants.AUTH_TYPE_KEY + authHeader);

    }

    private String getQuery(String tenantDomain, String username, String userStore) {

        return SessionDataConstants.QUOTE +
                SessionDataConstants.TENANT_DOMAIN_TAG +
                SessionDataConstants.ATTRIBUTE_SEPARATOR +
                tenantDomain +
                SessionDataConstants.AND_TAG +
                SessionDataConstants.USERNAME_TAG +
                SessionDataConstants.ATTRIBUTE_SEPARATOR +
                username +
                SessionDataConstants.AND_TAG +
                SessionDataConstants.USERSTORE_TAG +
                SessionDataConstants.ATTRIBUTE_SEPARATOR +
                userStore +
                SessionDataConstants.QUOTE;
    }
}
