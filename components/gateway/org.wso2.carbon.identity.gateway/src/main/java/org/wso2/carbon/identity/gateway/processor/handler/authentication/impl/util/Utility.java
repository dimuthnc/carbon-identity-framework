package org.wso2.carbon.identity.gateway.processor.handler.authentication.impl.util;


import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.gateway.internal.GatewayDataHolder;
import org.wso2.carbon.identity.gateway.processor.authenticator.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.gateway.processor.authenticator.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.gateway.processor.authenticator.RequestPathApplicationAuthenticator;
import org.wso2.carbon.identity.gateway.processor.handler.authentication.AuthenticationHandlerException;

import java.util.List;

public class Utility {
    public static ServiceProvider getServiceProvider(String requestType, String clientId, String tenantDomain)
            throws AuthenticationHandlerException {
        ServiceProvider serviceProvider = null;
        /*ApplicationManagementService applicationManagementService = ApplicationManagementService.getInstance();
        try {
            serviceProvider =
                    applicationManagementService.getServiceProviderByClientId(requestType, clientId, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            String errorMessage =
                    "Error occured while trying to get service providers by calling admin service, " + e.getMessage();
            throw new AuthenticationHandlerException(errorMessage, e);
        }*/
        return serviceProvider;
    }

    public static LocalApplicationAuthenticator getLocalApplicationAuthenticator(String name) {
        LocalApplicationAuthenticator localApplicationAuthenticator = null;
        List<LocalApplicationAuthenticator> localApplicationAuthenticators =
                GatewayDataHolder.getInstance().getLocalApplicationAuthenticators();
        for (LocalApplicationAuthenticator tmpLocalApplicationAuthenticator : localApplicationAuthenticators) {
            if (tmpLocalApplicationAuthenticator.getName().equals(name)) {
                localApplicationAuthenticator = tmpLocalApplicationAuthenticator;
                break;
            }
        }
        return localApplicationAuthenticator;
    }

    public static FederatedApplicationAuthenticator getFederatedApplicationAuthenticator(String name) {
        FederatedApplicationAuthenticator federatedApplicationAuthenticator = null;
        List<FederatedApplicationAuthenticator> federatedApplicationAuthenticators =
                GatewayDataHolder.getInstance().getFederatedApplicationAuthenticators();
        for (FederatedApplicationAuthenticator tmpFederatedApplicationAuthenticator :
                federatedApplicationAuthenticators) {
            if (tmpFederatedApplicationAuthenticator.getName().equals(name)) {
                federatedApplicationAuthenticator = tmpFederatedApplicationAuthenticator;
                break;
            }
        }
        return federatedApplicationAuthenticator;
    }

    public static RequestPathApplicationAuthenticator getRequestPathApplicationAuthenticator(String name) {
        RequestPathApplicationAuthenticator requestPathApplicationAuthenticator = null;
        List<RequestPathApplicationAuthenticator> requestPathApplicationAuthenticators =
                GatewayDataHolder.getInstance().getRequestPathApplicationAuthenticators();
        for (RequestPathApplicationAuthenticator authenticator : requestPathApplicationAuthenticators) {
            if (authenticator.getName().equals(name)) {
                requestPathApplicationAuthenticator = authenticator;
                break;
            }
        }
        return requestPathApplicationAuthenticator;
    }


}