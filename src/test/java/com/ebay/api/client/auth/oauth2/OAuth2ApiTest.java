package com.ebay.api.client.auth.oauth2;

import com.ebay.api.client.auth.oauth2.model.Environment;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.ebay.api.client.auth.oauth2.CredentialLoaderTestUtil.CRED_PASSWORD;
import static com.ebay.api.client.auth.oauth2.CredentialLoaderTestUtil.CRED_USERNAME;
import static org.junit.Assert.*;

public class OAuth2ApiTest {
    private static final List<String> SCOPE_LIST = Arrays.asList("https://api.ebay.com/oauth/api_scope", "https://api.ebay.com/oauth/api_scope/sell.marketing.readonly");

    @BeforeClass
    public static void testSetup() {
        CredentialLoaderTestUtil.commonLoadCredentials(Environment.SANDBOX);
        assertNotNull("Please check if test-config.yaml is setup correctly", CRED_USERNAME);
        assertNotNull("Please check if test-config.yaml is setup correctly", CRED_PASSWORD);
    }

    @Test
    public void testgenerateUserAuthorizationUrlNoState()
        throws MalformedURLException, URISyntaxException {
        OAuth2Api oAuth2Api = new OAuth2Api();
        String actual = oAuth2Api.generateUserAuthorizationUrl(Environment.SANDBOX, SCOPE_LIST, Optional.empty());
        URI uri = new URL(actual).toURI();
        assertEquals("The host should be auth.sandbox.ebay.com", uri.getHost(),
            "auth.sandbox.ebay.com");
        assertEquals("The path should be /oauth2/authorize", uri.getPath(),
            "/oauth2/authorize");
        String queryParams = uri.getQuery();
        assertContainsCommonParams(queryParams);
        assertFalse("The query params do not include state", queryParams.contains("state"));
    }

    @Test
    public void testgenerateUserAuthorizationUrlWithState()
        throws MalformedURLException, URISyntaxException {
        OAuth2Api oAuth2Api = new OAuth2Api();
        String actual = oAuth2Api.generateUserAuthorizationUrl(Environment.SANDBOX, SCOPE_LIST, Optional.of("current-page"));
        URI uri = new URL(actual).toURI();
        assertEquals("The host should be auth.sandbox.ebay.com", uri.getHost(), "auth.sandbox.ebay.com");
        assertEquals("The path should be /oauth2/authorize", uri.getPath(), "/oauth2/authorize");
        String queryParams = uri.getQuery();
        assertContainsCommonParams(queryParams);
        assertTrue("The query params include state", queryParams.contains("&state"));
    }

    private void assertContainsCommonParams(String queryParams) {
        assertTrue("The query params include client_id", queryParams.contains("client_id"));
        assertTrue("The query params include response_type", queryParams.contains("&response_type"));
        assertTrue("The query params include redirect_uri", queryParams.contains("&redirect_uri"));
        assertTrue("The query params include scope", queryParams.contains("&scope"));
        assertTrue("The query params include auth_type", queryParams.contains("&auth_type"));
    }
}
