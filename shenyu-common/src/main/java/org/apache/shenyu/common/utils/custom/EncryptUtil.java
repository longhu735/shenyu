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

import java.io.UnsupportedEncodingException;

/**
 * EncryptUtil.
 */
public final class EncryptUtil {

    /**
     * md5加密.
     * @param content 密码
     * @param charset 字符集
     * @return string
     * @throws UnsupportedEncodingException 异常
     */
    public static String md5(final String content, final String charset) throws UnsupportedEncodingException {
        return MD5Util.encode(content.getBytes(charset));
    }

}
