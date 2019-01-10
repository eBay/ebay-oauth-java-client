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

package com.ebay.api.client.auth.oauth2;

import static com.ebay.api.client.auth.oauth2.CredentialUtil.CredentialType.APP_ID;
import static com.ebay.api.client.auth.oauth2.CredentialUtil.CredentialType.CERT_ID;
import static com.ebay.api.client.auth.oauth2.CredentialUtil.CredentialType.REDIRECT_URI;
import static com.ebay.api.client.auth.oauth2.OAuth2Util.buildScopeForRequest;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebay.api.client.auth.oauth2.CredentialUtil.Credentials;
import com.ebay.api.client.auth.oauth2.model.AccessToken;
import com.ebay.api.client.auth.oauth2.model.CachedOAuthResponse;
import com.ebay.api.client.auth.oauth2.model.Environment;
import com.ebay.api.client.auth.oauth2.model.OAuthResponse;

public class OAuth2Api {
    private static final Logger logger = LoggerFactory.getLogger(OAuth2Api.class);
    public static final String CRED_SEPERATOR = ":";
    private static TimedCacheValue appAccessToken = null;

    private static class TimedCacheValue {

        private static Map<String, CachedOAuthResponse> oAuthResponsePerEnvironment = new ConcurrentHashMap<>();
        
        private TimedCacheValue(Environment environment, OAuthResponse value, DateTime expiresAt) {
            //Setting a buffer of 5 minutes for refresh
            DateTime expiresAtForCache = expiresAt.minusMinutes(5);
            
            CachedOAuthResponse cachedOAuthResponse = new CachedOAuthResponse(value, expiresAtForCache);
            oAuthResponsePerEnvironment.put(environment.getConfigIdentifier(), cachedOAuthResponse);
        }

        private OAuthResponse getValue(Environment environment) {
            CachedOAuthResponse cachedOAuthResponse = environment != null ? oAuthResponsePerEnvironment.get(environment.getConfigIdentifier()) : null;
            if (cachedOAuthResponse != null && DateTime.now().isBefore(cachedOAuthResponse.getExpiresAt())) {
                return cachedOAuthResponse.getValue();
            }
            //Since the value is expired, return null
            return null;
        }
    }

    public OAuthResponse getApplicationToken(Environment environment, List<String> scopes) throws IOException {
        if (appAccessToken != null && appAccessToken.getValue(environment) != null) {
            logger.debug("application access token returned from cache");
            return appAccessToken.getValue(environment);
        }

        OkHttpClient client = new OkHttpClient();
        String scope = buildScopeForRequest(scopes).orElse("");
        Credentials credentials = CredentialUtil.getCredentials(environment);

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
            OAuthResponse oAuthResponse = OAuth2Util.parseApplicationToken(response.body().string());
            AccessToken accessToken = oAuthResponse.getAccessToken().get();
            appAccessToken = new TimedCacheValue(environment, oAuthResponse, new DateTime(accessToken.getExpiresOn()));
            return oAuthResponse;
        } else {
            return OAuth2Util.handleError(response);
        }
    }

    private String buildAuthorization(Credentials credentials) {
        StringBuilder sb = new StringBuilder();
        sb.append(credentials.get(APP_ID)).append(CRED_SEPERATOR).append(credentials.get(CERT_ID));
        byte[] encodeBytes = Base64.getEncoder().encode(sb.toString().getBytes());
        return "Basic " + new String(encodeBytes);
    }

    public String generateUserAuthorizationUrl(Environment environment, List<String> scopes, Optional<String> state) {
        StringBuilder sb = new StringBuilder();
        Credentials credentials = CredentialUtil.getCredentials(environment);
        String scope = buildScopeForRequest(scopes).orElse("");

        sb.append(environment.getWebEndpoint()).append("?");
        sb.append("client_id=").append(credentials.get(APP_ID)).append("&");
        sb.append("response_type=code").append("&");
        sb.append("redirect_uri=").append(credentials.get(REDIRECT_URI)).append("&");
        sb.append("scope=").append(scope).append("&");
        if (state.isPresent()) {
            sb.append("state=").append(state.get());
        }
        logger.debug("authorize_url=" + sb.toString());
        return sb.toString();
    }

    public OAuthResponse exchangeCodeForAccessToken(Environment environment, String code) throws IOException {
        OkHttpClient client = new OkHttpClient();
        Credentials credentials = CredentialUtil.getCredentials(environment);

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
            return OAuth2Util.parseUserToken(response.body().string());
        } else {
            return OAuth2Util.handleError(response);
        }
    }

    public OAuthResponse getAccessToken(Environment environment, String refreshToken, List<String> scopes) throws IOException {
        OkHttpClient client = new OkHttpClient();
        Credentials credentials = CredentialUtil.getCredentials(environment);

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
            return OAuth2Util.parseUserToken(response.body().string());
        } else {
            return OAuth2Util.handleError(response);
        }
    }

    public String generateIdTokenUrl(Environment environment, Optional<String> state, String nonce) {
        StringBuilder sb = new StringBuilder();
        Credentials credentials = CredentialUtil.getCredentials(environment);

        sb.append(environment.getWebEndpoint()).append("?");
        sb.append("client_id=").append(credentials.get(APP_ID)).append("&");
        sb.append("response_type=id_token").append("&");
        sb.append("redirect_uri=").append(credentials.get(REDIRECT_URI)).append("&");
        sb.append("nonce=").append(nonce).append("&");
        if (state.isPresent()) {
            sb.append("state=").append(state.get());
        }
        logger.debug("id_token_url=" + sb.toString());
        return sb.toString();
    }
}