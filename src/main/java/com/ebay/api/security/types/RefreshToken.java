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

import java.util.Date;

public class RefreshToken {
    private String token;
    private Date expiresOn;
    private TokenType tokenType = TokenType.USER;

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

    public TokenType getTokenType() {
        return tokenType;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("RefreshToken{");
        sb.append("token='").append(token).append('\'');
        sb.append(", expiresOn=").append(expiresOn);
        sb.append(", tokenType=").append(tokenType);
        sb.append('}');
        return sb.toString();
    }
}
