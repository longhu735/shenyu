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

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.shenyu.common.constant.Constants;
import org.apache.shenyu.common.dto.AppAuthData;
import org.apache.shenyu.common.dto.AuthParamData;
import org.apache.shenyu.common.dto.AuthPathData;
import org.apache.shenyu.common.utils.DateUtils;
import org.apache.shenyu.plugin.api.context.ShenyuContext;
import org.apache.shenyu.plugin.api.result.ShenyuResultEnum;
import org.apache.shenyu.plugin.base.utils.PathMatchUtils;
import org.apache.shenyu.plugin.sign.api.SignParameters;
import org.apache.shenyu.plugin.sign.api.VerifyResult;
import org.apache.shenyu.plugin.sign.api.VerifySupplier;
import org.apache.shenyu.plugin.sign.cache.SignAuthDataCache;
import org.apache.shenyu.plugin.sign.extractor.SignParameterExtractor;
import org.apache.shenyu.plugin.sign.provider.SignProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.server.ServerWebExchange;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;

import static org.apache.shenyu.plugin.sign.extractor.DefaultExtractor.VERSION_0;

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
public class ComposableSignService implements SignService {

    private static final Logger LOG = LoggerFactory.getLogger(ComposableSignService.class);

    @Value("${shenyu.sign.delay}")
    private int delay;

    @Autowired
    private RedisTemplate redisTemplate;

    private final SignParameterExtractor extractor;

    private final SignProvider signProvider;

    public ComposableSignService(final SignParameterExtractor extractor, final SignProvider signProvider) {

        this.extractor = extractor;

        this.signProvider = signProvider;
    }

    @Override
    public VerifyResult signatureVerify(final ServerWebExchange exchange, final String requestBody) {
        return signatureVerify(exchange, (signKey, signParameters) -> signProvider.generateSign(signKey, signParameters, requestBody));
    }

    @Override
    public VerifyResult signatureVerify(final ServerWebExchange exchange) {
        return signatureVerify(exchange, signProvider::generateSign);
    }

    private VerifyResult signatureVerify(final ServerWebExchange exchange, final BiFunction<String, SignParameters, String> signFunction) {

        final ShenyuContext shenyuContext = exchange.getAttribute(Constants.CONTEXT);
        assert shenyuContext != null;
        //生成请求参数 注意extractor的注入时间
        SignParameters signParameters = extractor.extract(exchange.getRequest());
        if (signParameters.getVersion().equals(VERSION_0)) {
            return verify0(signParameters, signFunction);
        } else {
            //获取秘钥
            AppAuthData appAuthData = Optional.ofNullable(signParameters.getAppKey())
                    .map(key -> SignAuthDataCache.getInstance().obtainAuthData(key))
                    .orElse(null);

            VerifyResult result = verify(signParameters, appAuthData, signFunction);

            if (result.isSuccess()) {
                handleExchange(exchange, appAuthData, shenyuContext.getContextPath());
            }
            return result;
        }

    }

    private VerifyResult verify(final SignParameters signParameters,
                                final AppAuthData appAuthData,
                                final BiFunction<String, SignParameters, String> signFunction) {

        return VerifySupplier
                .apply(() -> verifySignParameters(signParameters))
                .and(() -> verifyExpires(signParameters))
                .and(() -> verifyAuthConfig(appAuthData, signParameters))
                .and(() -> verifyPath(appAuthData, signParameters))
                .and(() -> verifySign(appAuthData.getAppSecret(), signParameters, signFunction))
                .verify();

    }

    private VerifyResult verifyPath(final AppAuthData appAuthData, final SignParameters signParameters) {
        //校验appkey是否为当前访问的请求路径配置签名策略
        if (BooleanUtils.isNotTrue(appAuthData.getOpen())) {
            return VerifyResult.success();
        }

        List<AuthPathData> pathDataList = appAuthData.getPathDataList();
        if (CollectionUtils.isEmpty(pathDataList)) {
            LOG.error("You have not configured the sign path:{}", signParameters.getAppKey());
            return VerifyResult.fail(Constants.SIGN_PATH_NOT_EXIST);
        }

        boolean match = pathDataList.stream().filter(AuthPathData::getEnabled)
                .anyMatch(e -> PathMatchUtils.match(e.getPath(), signParameters.getUri().getPath()));
        if (!match) {
            LOG.error("You have not configured the sign path:{},{}", signParameters.getAppKey(), signParameters.getUri().getPath());
            return VerifyResult.fail(Constants.SIGN_PATH_NOT_EXIST);
        }
        return VerifyResult.success();
    }

    private VerifyResult verifyAuthConfig(final AppAuthData appAuthData, final SignParameters signParameters) {
        //验证APPKEY参数是否存在或启用
        if (Objects.isNull(appAuthData) || BooleanUtils.isFalse(appAuthData.getEnabled())) {
            LOG.error("sign APP_KEY does not exist or has been disabled,{}", signParameters.getAppKey());
            return VerifyResult.fail(Constants.SIGN_APP_KEY_IS_NOT_EXIST);
        }
        return VerifyResult.success();
    }

    private VerifyResult verifySignParameters(final SignParameters signParameters) {
        //签名参数非空校验
        boolean success = StringUtils.isNoneBlank(signParameters.getAppKey())
                && StringUtils.isNoneBlank(signParameters.getTimestamp())
                && StringUtils.isNoneBlank(signParameters.getSignature());
        if (success) {
            return VerifyResult.success();
        }
        LOG.error("sign parameters are incomplete,{}", signParameters);
        return VerifyResult.fail(Constants.SIGN_PARAMS_ERROR);
    }

    private VerifyResult verifyExpires(final SignParameters signParameters) {
        //验证该请求是否过期
        final LocalDateTime start = DateUtils.formatLocalDateTimeFromTimestampBySystemTimezone(Long.parseLong(signParameters.getTimestamp()));
        final LocalDateTime now = LocalDateTime.now();
        final long between = DateUtils.acquireMinutesBetween(start, now);
        if (Math.abs(between) <= delay) {
            return VerifyResult.success();
        }
        return VerifyResult.fail(String.format(ShenyuResultEnum.SIGN_TIME_IS_TIMEOUT.getMsg(), delay));
    }

    private VerifyResult verifySign(final String signKey,
                                    final SignParameters signParameters,
                                    final BiFunction<String, SignParameters, String> signFunction) {

        String sign = signFunction.apply(signKey, signParameters);

        boolean result = Objects.equals(sign, signParameters.getSignature());
        if (!result) {
            LOG.error("the SignUtils generated signature value is:{},the accepted value is:{}", sign, signParameters.getSignature());
            return VerifyResult.fail(Constants.SIGN_VALUE_IS_ERROR);
        }
        return VerifyResult.success();
    }

    private void handleExchange(final ServerWebExchange exchange,
                                final AppAuthData appAuthData,
                                final String contextPath) {

        List<AuthParamData> paramDataList = appAuthData.getParamDataList();

        if (!CollectionUtils.isEmpty(paramDataList)) {
            paramDataList.stream().filter(p ->
                            ("/" + p.getAppName()).equals(contextPath))
                    .map(AuthParamData::getAppParam)
                    .filter(StringUtils::isNoneBlank).findFirst()
                    .ifPresent(param -> exchange.getRequest().mutate().headers(httpHeaders -> httpHeaders.set(Constants.APP_PARAM, param)).build());
        }
    }

    private VerifyResult verify0(final SignParameters signParameters,
                                  final BiFunction<String, SignParameters, String> signFunction) {
        return VerifySupplier
                .apply(() -> verifySignParameters(signParameters))
                .and(() -> verifyExpires0(signParameters))
                .and(() -> verifyAuthConfig0(signParameters))
                .and(() -> verifySign0(signParameters, signFunction))
                .verify();
    }

    private VerifyResult verifyExpires0(final SignParameters signParameters) {
        final LocalDateTime start = DateUtils.parseLocalDateTime(signParameters.getTimestamp(), "yyyy-MM-dd HH:mm:ss");
        final LocalDateTime now = LocalDateTime.now();
        final long between = DateUtils.acquireMinutesBetween(start, now);
        if (Math.abs(between) <= delay) {
            return VerifyResult.success();
        }
        return VerifyResult.fail(String.format(ShenyuResultEnum.SIGN_TIME_IS_TIMEOUT.getMsg(), delay));
    }

    //验证APPKEY参数是否存在或启用
    private VerifyResult verifyAuthConfig0(final SignParameters signParameters) {
        if (Objects.isNull(signParameters.getAppKey())) {
            LOG.error("sign APP_KEY does not exist {}", signParameters.getAppKey());
            return VerifyResult.fail(Constants.SIGN_APP_KEY_IS_NOT_EXIST);
        }
        return VerifyResult.success();
    }

    private VerifyResult verifySign0(final SignParameters signParameters, final BiFunction<String, SignParameters, String> signFunction) {
        String secretKey = (String) redisTemplate.opsForValue().get("kepler-service-ops:gateway:token:" + signParameters.getAppKey());

        String sign = signFunction.apply(secretKey, signParameters);

        boolean result = Objects.equals(sign, signParameters.getSignature());
        if (!result) {
            LOG.error("the SignUtils generated signature value is:{},the accepted value is:{}", sign, signParameters.getSignature());
            return VerifyResult.fail(Constants.SIGN_VALUE_IS_ERROR);
        }
        return VerifyResult.success();
    }
}
