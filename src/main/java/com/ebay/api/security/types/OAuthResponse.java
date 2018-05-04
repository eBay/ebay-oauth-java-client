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

import java.util.Optional;

public class OAuthResponse {
    private Optional<AccessToken> accessToken;
    private Optional<RefreshToken> refreshToken;
    private String errorMessage;

    public OAuthResponse(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public OAuthResponse(Optional<AccessToken> accessToken, Optional<RefreshToken> refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public Optional<AccessToken> getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(Optional<AccessToken> accessToken) {
        this.accessToken = accessToken;
    }

    public Optional<RefreshToken> getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(Optional<RefreshToken> refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("OAuthResponse{");
        sb.append("accessToken=").append(accessToken);
        sb.append(", refreshToken=").append(refreshToken);
        sb.append(", errorMessage='").append(errorMessage).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
