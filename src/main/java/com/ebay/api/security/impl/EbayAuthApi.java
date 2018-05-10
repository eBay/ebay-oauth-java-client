/*
 * *
 *  * Copyright (c) 2018 eBay Inc.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *  http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  *
 */

package com.ebay.api.security.impl;

import com.ebay.api.security.CredentialHelper;
import com.ebay.api.security.CredentialHelper.Credentials;
import com.ebay.api.security.types.AccessToken;
import com.ebay.api.security.types.Environment;
import com.ebay.api.security.types.OAuthResponse;
import com.ebay.api.security.types.RefreshToken;
import com.ebay.api.security.v1.IEbayAuthApi;
import okhttp3.*;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static com.ebay.api.security.CredentialHelper.CredentialType.*;
import static com.ebay.api.security.impl.EbayAuthUtilities.buildScopeForRequest;

public class EbayAuthApi implements IEbayAuthApi {
    private static final Logger logger = LoggerFactory.getLogger(EbayAuthApi.class);
    public static final String CRED_SEPERATOR = ":";
    private static TimedCacheValue appAccessToken = null;

    private static class TimedCacheValue {
        private OAuthResponse value;
        private DateTime expiresAt;

        private TimedCacheValue(OAuthResponse value, DateTime expiresAt) {
            this.value = value;
            //Setting a buffer of 5 minutes for refresh
            this.expiresAt = expiresAt.minusMinutes(5);
        }

        private OAuthResponse getValue() {
            if (DateTime.now().isBefore(this.expiresAt)) {
                return this.value;
            }
            //Since the value is expired, return null
            return null;
        }
    }

    public OAuthResponse getApplicationToken(Environment environment, List<String> scopes) throws IOException {
        if (appAccessToken != null && appAccessToken.getValue() != null) {
            logger.debug("application access token returned from cache");
            return appAccessToken.getValue();
        }

        OkHttpClient client = new OkHttpClient();
        String scope = buildScopeForRequest(scopes).orElse("");
        Credentials credentials = CredentialHelper.getCredentials(environment);

        String requestData = String.format("grant_type=client_credentials&scope=%s", scope);
        RequestBody requestBody = RequestBody.create(MediaType.parse("application/x-www-form-urlencoded"), requestData);

        Request request = new Request.Builder().url(environment.getApiEndpoint())
                .header("Authorization", buildAuthorization(credentials))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .post(requestBody)
                .build();

        Response response = client.newCall(request).execute();
        if (response.isSuccessful()) {
            logger.debug("Network call to generate new token is successfull");
            OAuthResponse oAuthResponse = EbayAuthUtilities.parseForApplicationToken(response.body().string());
            AccessToken accessToken = oAuthResponse.getAccessToken().get();
            appAccessToken = new TimedCacheValue(oAuthResponse, new DateTime(accessToken.getExpiresOn()));
            return oAuthResponse;
        } else {
            return EbayAuthUtilities.handleError(response);
        }
    }

    private String buildAuthorization(Credentials credentials) {
        StringBuilder sb = new StringBuilder();
        sb.append(credentials.get(APP_ID)).append(CRED_SEPERATOR).append(credentials.get(CERT_ID));
        byte[] encodeBytes = Base64.getEncoder().encode(sb.toString().getBytes());
        return "Basic " + new String(encodeBytes);
    }

    public String generateUserAuthorizeUrl(Environment environment, List<String> scopes, Optional<String> state) {
        StringBuilder sb = new StringBuilder();
        Credentials credentials = CredentialHelper.getCredentials(environment);
        String scope = buildScopeForRequest(scopes).orElse("");

        sb.append(environment.getWebEndpoint()).append("?");
        sb.append("client_id=").append(credentials.get(APP_ID)).append("&");
        sb.append("response_type=code").append("&");
        sb.append("redirect_uri=").append(credentials.get(REDIRECT_URI)).append("&");
        sb.append("scope=").append(scope).append("&");
        if (state.isPresent()) {
            sb.append("state=").append(state.get());
        }
        //TODO Logger log the string created
        return sb.toString();
    }

    public OAuthResponse exchangeCode(Environment environment, String code) throws IOException {
        OkHttpClient client = new OkHttpClient();
        Credentials credentials = CredentialHelper.getCredentials(environment);

        StringBuilder requestData = new StringBuilder();
        requestData.append("grant_type=authorization_code").append("&");
        requestData.append(String.format("redirect_uri=%s", credentials.get(REDIRECT_URI))).append("&");
        requestData.append(String.format("code=%s", code));
        RequestBody requestBody = RequestBody.create(MediaType.parse("application/x-www-form-urlencoded"), requestData.toString());

        Request request = new Request.Builder().url(environment.getApiEndpoint())
                .header("Authorization", buildAuthorization(credentials))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .post(requestBody)
                .build();

        Response response = client.newCall(request).execute();
        if (response.isSuccessful()) {
            return EbayAuthUtilities.parseForUserToken(response.body().string());
        } else {
            return EbayAuthUtilities.handleError(response);
        }
    }

    @Override
    public OAuthResponse getAccessToken(Environment environment, String refreshToken, List<String> scopes) throws IOException {
        OkHttpClient client = new OkHttpClient();
        Credentials credentials = CredentialHelper.getCredentials(environment);

        String scope = buildScopeForRequest(scopes).orElse("");

        StringBuilder requestData = new StringBuilder();
        requestData.append("grant_type=refresh_token").append("&");
        requestData.append(String.format("refresh_token=%s", refreshToken));
        requestData.append(String.format("scope=%s", scope)).append("&");
        RequestBody requestBody = RequestBody.create(MediaType.parse("application/x-www-form-urlencoded"), requestData.toString());

        Request request = new Request.Builder().url(environment.getApiEndpoint())
                .header("Authorization", buildAuthorization(credentials))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .post(requestBody)
                .build();

        Response response = client.newCall(request).execute();
        if (response.isSuccessful()) {
            return EbayAuthUtilities.parseForUserToken(response.body().string());
        } else {
            return EbayAuthUtilities.handleError(response);
        }
    }
}