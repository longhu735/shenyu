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

import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;
import org.apache.shenyu.common.utils.custom.AESUtil;
import org.apache.shenyu.plugin.sign.api.SignParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Map;
import java.util.Objects;

@Component
public class CustomSignProvider implements SignProvider {
    private static final Logger LOG = LoggerFactory.getLogger(CustomSignProvider.class);

    @Override
    public String generateSign(final String signKey, final SignParameters signParameters, final String requestBody) {
        return sign(signKey, signParameters, requestBody);
    }

    @Override
    public String generateSign(final String secretKey, final SignParameters signParameters) {
        return sign(secretKey, signParameters, null);
    }

    private String sign(final String secretKey, final SignParameters signParameters, final String requestBody) {
        Map<String, String> params = getParams(signParameters, requestBody);
        String serviceData = null;
        try {
            serviceData = AESUtil.decrypt(secretKey, "");
        } catch (Exception e) {
            LOG.error("签名异常{}", e);
        }
        String sign = org.apache.shenyu.common.utils.custom.SignatureUtil.generateSign(params, serviceData);
        return sign;
    }

    private Map<String, String> getParams(final SignParameters signParameters, final String requestBody) {
        Map<String, String> params = Maps.newHashMap();
        if (Objects.isNull(requestBody)) {
            return params;
        }
        //get requestBodyParameter
        if (!StringUtils.isEmpty(requestBody)) {
            //buz_data或者requestBody 必须是以对象形式提交，如果客户端以字符串形式提交，则会造成签名不一致
            params.put("buz_data", requestBody);
        }
        // get url params
        Map<String, String> queryParams = UriComponentsBuilder.fromUri(signParameters.getUri())
                .build()
                .getQueryParams()
                .toSingleValueMap();
        params.putAll(queryParams);
        LOG.info("请求参数转码前{}", params);
        //对请求参数进行转码
        for (String key : params.keySet()) {
            try {
                params.put(key, URLDecoder.decode(params.get(key), "utf-8"));
            } catch (UnsupportedEncodingException e) {
                LOG.error("签名异常{}", e);
            }
        }
        LOG.info("请求参数转码后{}", params);
        return params;
    }
}
