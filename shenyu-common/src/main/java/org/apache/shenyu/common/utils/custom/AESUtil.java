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

import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

/**
 * AESUtil.
 */
public class AESUtil {

    private static final String PWD = "!D7A^LrOTeMhtrEbZcEfygn6UB7#a!xX";

    private static final String AES_ECB_TYPE = "AES/ECB/PKCS5Padding";

    private static final String AES_GCM_TYPE = "AES/GCM/NoPadding";

    /**
     * encrypt.
     *
     * @param data     密文
     * @param password 秘钥
     * @return String
     * @throws Exception 异常
     */
    public static String encrypt(final String data, final String password) throws Exception {
        Key key;
        if (StringUtils.isBlank(password)) {
            key = getSecretKey(PWD);
        } else {
            key = getSecretKey(password);
        }
        Cipher cipher = Cipher.getInstance(AES_ECB_TYPE);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypt = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypt);
    }

    /**
     * decrypt.
     *
     * @param data     密文
     * @param password 秘钥
     * @return String
     * @throws Exception 异常
     */
    public static String decrypt(final String data, final String password) throws Exception {
        Key key;
        if (StringUtils.isBlank(password)) {
            key = getSecretKey(PWD);
        } else {
            key = getSecretKey(password);
        }
        Cipher cipher = Cipher.getInstance(AES_ECB_TYPE);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypt = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decrypt);
    }

    private static Key getSecretKey(final String password) {
        return new SecretKeySpec(password.getBytes(), "AES");
    }

}
