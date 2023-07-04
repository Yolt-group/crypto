package com.yolt.crypto.keymanagement;


import com.yolt.crypto.keymanagement.AWSCloudHSMMetricsService.AliasWithKeyTuple;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AWSCloudHSMMetricsServiceTest {

    @Test
    void testAliasPattern() {
        assertThat(isValidAlias("0005291f-68bb-4d5f-9a3f-7aa330fb7641_4d92e917-8711-4be9-b3e9-ab49c82811e1"), is(true));
        assertThat(isValidAlias("0005291f-68bb-4d5f-9a3f-7aa330fb7641_52dfc7e2-38d4-48a3-b442-52ad3e2bc8bd:public"), is(false));
        assertThat(isValidAlias("0005291f-68bb-4d5f-9a3f-7aa330fb7641_52dfc7e2-38d4-48a3-b442-52ad3e2bc8bd"), is(true));
        assertThat(isValidAlias("0005291f-68bb-4d5f-9a3f-7aa330fb7641_4d92e917-8711-4be9-b3e9-ab49c82811e1:public"), is(false));
        assertThat(isValidAlias("141f08f5-cc7a-483e-beeb-3e28244404b1_2d4a98e4-c633-4472-a2e3-27c632f61e04"), is(true));
        assertThat(isValidAlias("141f08f5-cc7a-483e-beeb-3e28244404b1_466e1978-a44b-43b9-9c37-6f3895a05b3a"), is(true));
        assertThat(isValidAlias("public"), is(false));
    }

    private boolean isValidAlias(String alias) {
        return AWSCloudHSMMetricsService.ALIAS.matcher(alias).matches();
    }

    @Test
    void keySize() {
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        when(privateKey.getModulus()).thenReturn(BigInteger.valueOf(4294967296L));

        AliasWithKeyTuple tuple = new AliasWithKeyTuple("", privateKey);
        // 2^32 = 4294967296L, so goes into 64 bit bucket
        assertThat(tuple.getKeySize(), is(64));
    }
}
