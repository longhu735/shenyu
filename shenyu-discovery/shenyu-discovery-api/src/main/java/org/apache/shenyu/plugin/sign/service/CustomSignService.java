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

package org.apache.shenyu.plugin.sign.service;

import org.apache.commons.lang3.StringUtils;
import org.apache.shenyu.common.constant.Constants;
import org.apache.shenyu.common.utils.DateUtils;
import org.apache.shenyu.plugin.api.result.ShenyuResultEnum;
import org.apache.shenyu.plugin.sign.api.SignParameters;
import org.apache.shenyu.plugin.sign.api.VerifyResult;
import org.apache.shenyu.plugin.sign.api.VerifySupplier;
import org.apache.shenyu.plugin.sign.extractor.SignParameterExtractor;
import org.apache.shenyu.plugin.sign.provider.SignProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.server.ServerWebExchange;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.function.BiFunction;

/**
 * The ComposableSignService is composable SignService.
 * <pre>
 *  1. new ComposableSignService(new DefaultExtractor(), new DefaultSignProvider())
 *    Version 1: 2.5.0 SignService
 *    Version 2:Implements from <a href="https://github.com/apache/shenyu/issues/4208">#4208</a>
 *    parameters:
 *     {
 *           "alg":"HMD5",
 *           "version":"1.0.0",
 *           "appKey":"506EEB535CF740D7A755CB4B9F4A1536",
 *           "timestamp":"1571711067186"
 *     }<br>
 *   signature = Sign(base64Encoding(parameters )
 *    + Relative URL+ Body* ,secret); * indicate Optional , it
 *    depends on config.<br>
 *    Relative URL = path [ "?" query ]
 *    eg: /apache/shenyu/pulls?name=xiaoMing
 *
 *    token = base64Encoding(header) + '.'
 *    + base64Encoding(signature)
 * 2. new ComposableSignService(new CustomExtractor(), new CustomSignProvider())
 *     Customs {@link org.apache.shenyu.plugin.sign.extractor.SignParameterExtractor} and {@link org.apache.shenyu.plugin.sign.provider.SignProvider}
 *  </pre>
 */
public class CustomSignService implements SignService {
    private static final Logger LOG = LoggerFactory.getLogger(CustomSignService.class);

    @Value("${shenyu.sign.delay}")
    private int delay;

    @Autowired
    private RedisTemplate redisTemplate;

    private final SignParameterExtractor extractor;

    private final SignProvider signProvider;

    public CustomSignService(final SignParameterExtractor extractor, final SignProvider signProvider) {

        this.extractor = extractor;

        this.signProvider = signProvider;
    }

    /**
     * Gets verifyResult.
     *
     * @param exchange    exchange
     * @param requestBody requestBody
     * @return result
     */
    @Override
    public VerifyResult signatureVerify(final ServerWebExchange exchange, final String requestBody) {
        return signatureVerify(exchange, (signKey, signParameters) -> signProvider.generateSign(signKey, signParameters, requestBody));
    }

    /**
     * Gets verifyResult.
     *
     * @param exchange exchange
     * @return result
     */
    @Override
    public VerifyResult signatureVerify(final ServerWebExchange exchange) {

        return signatureVerify(exchange, signProvider::generateSign);
    }

    private VerifyResult signatureVerify(final ServerWebExchange exchange, final BiFunction<String, SignParameters, String> signFunction) {
        //生成请求参数 注意extractor的注入时间
        SignParameters signParameters = extractor.extract(exchange.getRequest());
        return verify(signParameters, signFunction);
    }

    private VerifyResult verify(final SignParameters signParameters,
                                final BiFunction<String, SignParameters, String> signFunction) {
        return VerifySupplier
                .apply(() -> verifySignParameters(signParameters))
                .and(() -> verifyExpires(signParameters.getTimestamp()))
                .and(() -> verifyAuthConfig(signParameters.getAppKey()))
                .and(() -> verifySign(signParameters, signFunction))
                .verify();

    }

    //验证APPKEY参数是否存在或启用
    private VerifyResult verifyAuthConfig(final String appKey) {
        if (Objects.isNull(appKey)) {
            LOG.error("sign APP_KEY does not exist {}", appKey);
            return VerifyResult.fail(Constants.SIGN_APP_KEY_IS_NOT_EXIST);
        }
        return VerifyResult.success();
    }

    //签名参数非空校验
    private VerifyResult verifySignParameters(final SignParameters signParameters) {
        boolean success = StringUtils.isNoneBlank(signParameters.getAppKey())
                && StringUtils.isNoneBlank(signParameters.getTimestamp())
                && StringUtils.isNoneBlank(signParameters.getSignature());
        if (success) {
            return VerifyResult.success();
        }
        LOG.error("sign parameters are incomplete,{}", signParameters);
        return VerifyResult.fail(Constants.SIGN_PARAMS_ERROR);
    }

    private VerifyResult verifySign(final SignParameters signParameters, final BiFunction<String, SignParameters, String> signFunction) {
        String secretKey = (String) redisTemplate.opsForValue().get("kepler-service-ops:gateway:token:" + signParameters.getAppKey());

        String sign = signFunction.apply(secretKey, signParameters);

        boolean result = Objects.equals(sign, signParameters.getSignature());
        if (!result) {
            LOG.error("the SignUtils generated signature value is:{},the accepted value is:{}", sign, signParameters.getSignature());
            return VerifyResult.fail(Constants.SIGN_VALUE_IS_ERROR);
        }
        return VerifyResult.success();
    }


    //验证该请求是否过期
    private VerifyResult verifyExpires(final String signParameters) {
        final LocalDateTime start = DateUtils.parseLocalDateTime(signParameters, "yyyy-MM-dd HH:mm:ss");
        final LocalDateTime now = LocalDateTime.now();
        final long between = DateUtils.acquireMinutesBetween(start, now);
        if (Math.abs(between) <= delay) {
            return VerifyResult.success();
        }
        return VerifyResult.fail(String.format(ShenyuResultEnum.SIGN_TIME_IS_TIMEOUT.getMsg(), delay));
    }
}
