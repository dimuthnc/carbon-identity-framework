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
package org.wso2.carbon.identity.application.authentication.framework.util;

/**
 * TODO:Class level comment
 */
public class SessionDataConstants {
    public static final String USERNAME_TAG = "username";
    public static String USERSTORE_TAG = "userstoreDomain";
    public static final String CONTENT_TYPE_TAG = "Content-type";
    public static final String UTF_8_TAG = "UTF-8";
    public static final String AUTH_TYPE_KEY = "Basic ";

    public static final String QUOTE = "\"";
    public static final String ATTRIBUTE_SEPARATOR = ":";

    public static final String ACTIVE_SESSION_TABLE_NAME = QUOTE + "ORG_WSO2_IS_ANALYTICS_STREAM_ACTIVESESSIONS" +QUOTE;
    public static final String TABLE_NAME_TAG = QUOTE + "tableName" + QUOTE;
    public static final String QUERY_TAG = QUOTE + "query" + QUOTE;
    public static final String COUNT_TAG = QUOTE + "count" + QUOTE;
    public static final String START_TAG = QUOTE + "start" + QUOTE;

    public static final String TENANT_DOMAIN_TAG = "tenantDomain";
    public static final String STATE_TAG = "state";
    public static final String SESSION_TAG = "sessions";
    public static final String AND_TAG = " AND ";


    public static final String TABLE_SEARCH_URL = "https://localhost:9444/analytics/search";
    public static final String TABLE_SEARCH_COUNT_URL = "https://localhost:9444/analytics/search_count";

    public static final int START_INDEX = 0;
    public static final int RETRIEVE_COUNT = 10;

    public static final String USERNAME_CONFIG = "admin";
    public static final String PASSWORD_CONFIG = "admin";

}
