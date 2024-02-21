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

package org.apache.shenyu.common.utils.custom;

import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.apache.shenyu.common.constant.Constants.SIGN;

/**
 * SignatureUtil.
 */
public final class SignatureUtil {
    private static final Logger LOG = LoggerFactory.getLogger(SignatureUtil.class);

    /**
     * 请求参数签名.
     * secret: test
     * 系统参数： appkey=test timestamp=1477395862 version=1.0
     * 应用参数： number=123 string=测试 double=123.123 boolean=true empty=
     * 加密前的字符串为 testappkeytestbooleantruedouble123.123number123string测试timestamp1477395862version1.0
     *
     * @param paramMap  请求参数
     * @param secretKey 签名秘钥
     * @return String
     */
    public static String generateSign(final Map<String, String> paramMap, final String secretKey) {
        return SignatureUtil.generateSign(paramMap, secretKey, null);
    }

    /**
     * encode.
     *
     * @param paramMap  map
     * @param secretKey 秘钥
     * @param signType  加密类型
     * @return String
     */
    public static String generateSign(final Map<String, String> paramMap, final String secretKey, final String signType) {
        List<String> keyList = Lists.newArrayList(paramMap.keySet());
        Collections.sort(keyList);

        StringBuilder signStr = new StringBuilder(secretKey);
        for (String key : keyList) {
            if (SIGN.equalsIgnoreCase(key)) {
                continue;
            }
            signStr.append(key).append(paramMap.get(key));
        }
        LOG.info("验签前字符串:{}", signStr.toString());
        String sign = null;
        try {
            sign = switchSignature(signStr.toString(), StringUtils.isBlank(signType) ? "MD5" : signType,
                    "UTF-8");
        } catch (UnsupportedEncodingException e) {
            LOG.error("系统验签异常{}", e);
        }
        return sign.toLowerCase();

    }

    /**
     * encode.
     *
     * @param content  内容
     * @param signType 加密类型
     * @param charset  字符集
     * @return String
     * @throws UnsupportedEncodingException 异常
     */
    private static String switchSignature(final String content, final String signType, final String charset) throws UnsupportedEncodingException {
        String sign = "";
        switch (signType) {
            case "SHA1":
                break;
            case "MD5":
                sign = EncryptUtil.md5(content, charset);
                break;
            default:
        }
        return sign;
    }

}
