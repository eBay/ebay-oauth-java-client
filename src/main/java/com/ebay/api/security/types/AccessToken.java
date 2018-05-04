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

package com.ebay.api.security.types;

import com.ebay.api.security.rest.client.TokenResponse;
import com.google.gson.Gson;

import java.util.Date;

public class AccessToken {
    private String token;
    private Date expiresOn;
    private TokenType tokenType;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Date getExpiresOn() {
        return expiresOn;
    }

    public void setExpiresOn(Date expiresOn) {
        this.expiresOn = expiresOn;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("AccessToken{");
        sb.append(", token='").append(token).append('\'');
        sb.append(", expiresOn=").append(expiresOn);
        sb.append('}');
        return sb.toString();
    }

    public void setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    public TokenType getTokenType() {
        return tokenType;
    }
}
