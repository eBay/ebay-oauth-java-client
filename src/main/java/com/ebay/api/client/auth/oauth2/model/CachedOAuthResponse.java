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

package com.ebay.api.client.auth.oauth2.model;

import org.joda.time.DateTime;

/**
 * The Class CachedOAuthResponse to hold OAuthResponse in cache 
 * for different environments: production/sandbox
 */
public class CachedOAuthResponse {

    private OAuthResponse value;
    private DateTime expiresAt;
    
    /**
     * Instantiates a new CachedOAuthResponse.
     */
    public CachedOAuthResponse(){};
    
    

    public CachedOAuthResponse(OAuthResponse value, DateTime expiresAt) {
        this.value = value;
        this.expiresAt = expiresAt;
    }



    /**
     * Gets the value of the value property
     * 
     * @return allowed type is {@link OAuthResponse}
     */
    public OAuthResponse getValue() {
        return value;
    }

    /**
     * Sets the value of the value property
     *
     * @param value
     *            allowed type is {@link OAuthResponse}
     */
    public void setValue(OAuthResponse value) {
        this.value = value;
    }

    /**
     * Gets the value of the expiresAt property
     * 
     * @return allowed type is {@link DateTime}
     */
    public DateTime getExpiresAt() {
        return expiresAt;
    }

    /**
     * Sets the value of the expiresAt property
     *
     * @param expiresAt
     *            allowed type is {@link DateTime}
     */
    public void setExpiresAt(DateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

}
