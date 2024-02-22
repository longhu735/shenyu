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

package org.apache.shenyu.plugin.sign.extractor;

import org.apache.commons.lang3.StringUtils;
import org.apache.shenyu.common.constant.Constants;
import org.apache.shenyu.plugin.sign.api.SignParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpRequest;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.Map;

public class CustomExtractor implements SignParameterExtractor {
    private static final Logger LOG = LoggerFactory.getLogger(CustomExtractor.class);

    @Override
    public SignParameters extract(final HttpRequest httpRequest) {
        Map<String, String> queryParams = UriComponentsBuilder.fromUri(httpRequest.getURI())
                .build()
                .getQueryParams()
                .toSingleValueMap();
        //验证APP访问者身份
        String appKey = queryParams.get("token");
        //获取APP访问者签名
        String signature = queryParams.get(Constants.SIGN);
        //获取APP访问者时间戳
        String timestamp = queryParams.get(Constants.TIMESTAMP);
        if (StringUtils.isNotEmpty(timestamp)) {
            try {
                timestamp = URLDecoder.decode(timestamp, "utf-8");
            } catch (UnsupportedEncodingException e) {
                LOG.error("签名异常{}", e);
            }
        }
        URI uri = httpRequest.getURI();

        return new SignParameters(null, appKey, timestamp, signature, uri);
    }
}
