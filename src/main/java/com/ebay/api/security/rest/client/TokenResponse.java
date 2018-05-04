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

package com.ebay.api.security.rest.client;

/*
Reference: https://developer.ebay.com/api-docs/static/oauth-auth-code-grant.html
{
    "access_token":"v^1.1#i^1#p^1#r^0#I^3#f^0#t^H4s ... wu67e3xAhskz4DAAA",
    "token_type":"Application Access Token",
    "expires_in":7200,
    "refresh_token":"N/A"
  }

    {
    "access_token": "v^1.1#i^1#p^3#r^1...XzMjRV4xMjg0",
    "expires_in": 7200,
    "refresh_token": "v^1.1#i^1#p^3#r^1...zYjRV4xMjg0",
    "refresh_token_expires_in": 47304000,
    "token_type": "User Access Token"
  }


 */

import com.google.gson.annotations.SerializedName;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class TokenResponse {
    @SerializedName("access_token")
    private String accessToken;

    @SerializedName("token_type")
    private String tokenType;

    @SerializedName("expires_in")
    private int expiresIn;

    @SerializedName("refresh_token")
    private String refreshToken;

    @SerializedName("refresh_token_expires_in")
    private int refreshTokenExpiresIn;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public int getRefreshTokenExpiresIn() {
        return refreshTokenExpiresIn;
    }

    public void setRefreshTokenExpiresIn(int refreshTokenExpiresIn) {
        this.refreshTokenExpiresIn = refreshTokenExpiresIn;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("TokenResponse{");
        sb.append("accessToken='").append(accessToken).append('\'');
        sb.append(", tokenType='").append(tokenType).append('\'');
        sb.append(", expiresIn=").append(expiresIn);
        sb.append(", refreshToken='").append(refreshToken).append('\'');
        sb.append(", refreshTokenExpiresIn='").append(refreshTokenExpiresIn).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
