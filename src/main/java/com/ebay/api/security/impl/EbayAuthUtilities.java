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

import com.ebay.api.security.rest.client.TokenResponse;
import com.ebay.api.security.types.AccessToken;
import com.ebay.api.security.types.OAuthResponse;
import com.ebay.api.security.types.RefreshToken;
import com.ebay.api.security.types.TokenType;
import com.google.gson.Gson;
import okhttp3.Response;
import org.joda.time.DateTime;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Optional;

class EbayAuthUtilities {

    static OAuthResponse parseForApplicationToken(String s) {
        Gson gson = new Gson();
        TokenResponse tokenResponse = gson.fromJson(s, TokenResponse.class);
        AccessToken token = new AccessToken();
        token.setTokenType(TokenType.APPLICATION);
        token.setToken(tokenResponse.getAccessToken());
        token.setExpiresOn(generateExpiration(tokenResponse.getExpiresIn()));
        OAuthResponse oauthResponse = new OAuthResponse(Optional.of(token), null);
        return oauthResponse;
    }

    public static Date generateExpiration(int expiresIn) {
        return DateTime.now().plusSeconds(expiresIn).toDate();
    }

    static Optional<String> buildScopeForRequest(List<String> scopes) {
        String scopeList = null;
        if (null != scopes && !scopes.isEmpty()) {
            scopeList = String.join("+", scopes);
        }
        return Optional.of(scopeList);
    }

    static OAuthResponse parseForUserToken(String s) {
        Gson gson = new Gson();
        TokenResponse tokenResponse = gson.fromJson(s, TokenResponse.class);
        AccessToken accessToken = new AccessToken();
        accessToken.setTokenType(TokenType.USER);
        accessToken.setToken(tokenResponse.getAccessToken());
        accessToken.setExpiresOn(generateExpiration(tokenResponse.getExpiresIn()));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(tokenResponse.getRefreshToken());
        refreshToken.setExpiresOn(generateExpiration(tokenResponse.getRefreshTokenExpiresIn()));

        return new OAuthResponse(Optional.of(accessToken), Optional.of(refreshToken));
    }

    static OAuthResponse handleError(Response response) throws IOException {
        String errorMessage = response.body().string();
        return new OAuthResponse(errorMessage);
    }
}