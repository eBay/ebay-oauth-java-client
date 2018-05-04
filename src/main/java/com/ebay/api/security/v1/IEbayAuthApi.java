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

package com.ebay.api.security.v1;

import com.ebay.api.security.types.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface IEbayAuthApi {
    OAuthResponse getApplicationToken(Environment environment, List<String> scopes) throws IOException;

    String generateUserAuthorizeUrl(Environment environment, List<String> scopes, Optional<String> state);

    OAuthResponse exchangeCode(Environment environment, String code) throws IOException;

    OAuthResponse getAccessToken(Environment environment, String refreshToken, List<String> scopes) throws IOException;
}