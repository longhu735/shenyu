/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shenyu.plugin.sign.provider;

import com.google.common.collect.ImmutableMap;
import org.apache.shenyu.common.utils.DigestUtils;
import org.apache.shenyu.common.utils.JsonUtils;
import org.apache.shenyu.plugin.sign.api.SignParameters;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class DefaultSignProviderTest {

    private final SignProvider signProvider = new DefaultSignProvider();

    @Test
    void testGenerateSign() {
        SignParameters signParameters = new SignParameters("2.0.0", "108C27175A2C43C1BC29B1E483D57E3D",
                "1673093719090", "C25A751BBCE25392DF61B352A2440FF9",
                URI.create("http://localhost:9195/http/test/path/456?name=Lee&data=3"));
        String token = JsonUtils.toJson(ImmutableMap.of("alg", "MD5",
                "appKey", "108C27175A2C43C1BC29B1E483D57E3D",
                "timestamp", "1673093719090"));
        signParameters.setParameters(Base64.getEncoder().encodeToString(token.getBytes(StandardCharsets.UTF_8)));

        String actual = signProvider.generateSign("061521A73DD94A3FA873C25D050685BB", signParameters);
        assertThat(actual, is("4892285C655127FE0B05BCAA4A47B093"));
    }

    @Test
    void testGenerateSignWithBody() {
        SignParameters signParameters = new SignParameters("2.0.0", "108C27175A2C43C1BC29B1E483D57E3D",
                "1673093719090", "C25A751BBCE25392DF61B352A2440FF9",
                URI.create("http://localhost:9195/http/test/payment?userName=Lee&userId=3"));

        String token = JsonUtils.toJson(ImmutableMap.of(
                "alg", "MD5",
                "appKey", "108C27175A2C43C1BC29B1E483D57E3D",
                "timestamp", "1673093719090"));
        signParameters.setParameters(Base64.getEncoder().encodeToString(token.getBytes(StandardCharsets.UTF_8)));

        ImmutableMap<String, String> requestBody = ImmutableMap.of("userName", "Lee", "userId", "3");
        String actual = signProvider.generateSign("061521A73DD94A3FA873C25D050685BB", signParameters, JsonUtils.toJson(requestBody));
        assertThat(actual, is("61A097079016A18B1246A375482BEDBC"));
    }

    @Test
    //客户端调用demo
    void testGenerateSignWithBody1() {
        String AK = "869260F20A324D799C6554F354BC9FA9";
        String SK = "CF413A21253F4C27832F2A0948144B3B";
        String timestamp = "1709625896000";
        String version = "2.0.0";
        String parameters = JsonUtils.toJson(ImmutableMap.of(
                "alg", "MD5",
                "appKey", AK,
                "timestamp", timestamp));
        String base64Parameters = Base64.getEncoder()
                .encodeToString(parameters.getBytes(StandardCharsets.UTF_8));

        URI uri = URI.create("http://127.0.0.1:9195/ndc/aq/getPorts?id=2");
        String signature = sign(SK,base64Parameters,uri,null);

        String Token = base64Parameters+"."+signature;
        //todo send http request
        System.out.println(Token);


    }
    private  String sign(final String signKey, final String base64Parameters, final URI uri, final String body) {

        String data = base64Parameters
                + getRelativeURL(uri)
                + Optional.ofNullable(body).orElse("");

        return DigestUtils.md5Hex(data+signKey).toUpperCase();
    }

    private  String getRelativeURL(final URI uri) {
        if (Objects.isNull(uri.getQuery())) {
            return uri.getPath();
        }
        return uri.getPath() + "?" + uri.getQuery();
    }

}
