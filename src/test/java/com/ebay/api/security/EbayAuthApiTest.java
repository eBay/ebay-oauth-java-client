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

package com.ebay.api.security;

import com.ebay.api.security.impl.EbayAuthApi;
import com.ebay.api.security.types.AccessToken;
import com.ebay.api.security.types.Environment;
import com.ebay.api.security.types.OAuthResponse;
import com.ebay.api.security.v1.IEbayAuthApi;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.*;

public class EbayAuthApiTest {
    private static List<String> applicationScopesList = Arrays.asList(new String[]{"https://api.ebay.com/oauth/api_scope", "https://api.ebay.com/oauth/api_scope/buy.guest.order", "https://api.ebay.com/oauth/api_scope/buy.item.feed"});
    private static List<String> authorizationScopesList = Arrays.asList(new String[]{"https://api.ebay.com/oauth/api_scope", "https://api.ebay.com/oauth/api_scope/sell.marketing.readonly"});

    @BeforeClass
    public static void testSetup() throws FileNotFoundException {
        // Loading the app credentials
        CredentialLoaderTestUtil.loadAppCredentials();
    }

    @Test
    public void testGenerateAppTokenSandbox() throws IOException {
        IEbayAuthApi authApi = new EbayAuthApi();
        OAuthResponse response = authApi.getApplicationToken(Environment.SANDBOX, applicationScopesList);
        Optional<AccessToken> applicationToken = response.getAccessToken();
        assertNotNull(applicationToken.get());
        assertNotNull(applicationToken.get().getToken());
        assertTrue(applicationToken.get().getToken().trim().length() > 0);
    }

    @Test
    public void testGenerateAppTokenProduction() throws IOException {
        IEbayAuthApi authApi = new EbayAuthApi();
        //Only this scope is allowed for this app
        OAuthResponse response = authApi.getApplicationToken(Environment.PRODUCTION, Arrays.asList(new String[]{"https://api.ebay.com/oauth/api_scope"}));
        Optional<AccessToken> applicationToken = response.getAccessToken();
        assertNotNull(applicationToken.get());
        assertNotNull(applicationToken.get().getToken());
        assertTrue(applicationToken.get().getToken().trim().length() > 0);
    }

    @Test
    public void testGenerateAuthorizationUrlSandbox() {
        IEbayAuthApi authApi = new EbayAuthApi();
        String authorizeUrl = authApi.generateUserAuthorizeUrl(Environment.SANDBOX, authorizationScopesList, Optional.of("current-page"));
        System.out.println(authorizeUrl);
        assertNotNull(authorizeUrl);
    }

    @Test
    public void testGenerateAuthorizationUrlProduction() {
        IEbayAuthApi authApi = new EbayAuthApi();
        String authorizeUrl = authApi.generateUserAuthorizeUrl(Environment.PRODUCTION, authorizationScopesList, Optional.of("current-page"));
        System.out.println(authorizeUrl);
        assertNotNull(authorizeUrl);
    }

    @Test
    public void testCheckErrorHandling() throws IOException {
        IEbayAuthApi authApi = new EbayAuthApi();
        // Attempting with incorrect scope
        OAuthResponse response = authApi.getApplicationToken(Environment.PRODUCTION, Arrays.asList(new String[]{"https://api.ebay.com/oauth/"}));
        Optional<AccessToken> applicationToken = response.getAccessToken();
        assertNull(applicationToken);
        assertNotNull(response.getErrorMessage());
        assertTrue(response.getErrorMessage().contains("\"error\":\"invalid_scope\""));
    }
}