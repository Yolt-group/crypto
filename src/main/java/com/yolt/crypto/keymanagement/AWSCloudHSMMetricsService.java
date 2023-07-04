package com.yolt.crypto.keymanagement;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.MultiGauge;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAKey;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static java.util.stream.Collectors.counting;
import static java.util.stream.Collectors.groupingBy;

/**
 * This service communicates with CloudHSM to fetch private keys and to sign data. It uses Vault for retrieving CloudHSM
 * login credentials and to fallback to Vault for fetching private keys and signing data.
 */
@Slf4j
@Service
@ConditionalOnProperty(prefix = "yolt.crypto", name = "cloudHSM.enabled")
public class AWSCloudHSMMetricsService {

    static final Pattern ALIAS = Pattern
            .compile("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})_([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})");

    private final AWSCloudHSM awsCloudHSM;
    private final MultiGauge multiGauge;

    @Autowired
    public AWSCloudHSMMetricsService(MeterRegistry registry, AWSCloudHSM awsCloudHSM) {
        this.awsCloudHSM = awsCloudHSM;
        this.multiGauge = MultiGauge.builder("cloudhsm_keys").register(registry);
    }

    @Scheduled(fixedRate = 600000, initialDelay = 30000)
    public void gatherMetrics() throws KeyStoreException {
        List<String> labels = awsCloudHSM.findAllKeyLabels();

        // clientGroupId / keySize / count()
        Map<String, Map<Integer, Long>> metrics = labels.stream()
                .filter(alias -> ALIAS.matcher(alias).matches())
                .map(this::getAliasWithCaviumKeyTuple)
                .filter(AliasWithKeyTuple::isRSAKey)
                .collect(
                        groupingBy(tuple -> tuple.alias().split("_")[0],
                                groupingBy(AliasWithKeyTuple::getKeySize, counting())));

        List<MultiGauge.Row<?>> rows = new LinkedList<>();
        metrics.forEach((alias, keySizeMap) ->
                keySizeMap.forEach((keySize, count) -> {
                    Tags tags = Tags.of(
                            Tag.of("clientGroupId", alias),
                            Tag.of("keySize", Integer.toString(keySize)),
                            // can not be derived with cloudhsm-jce v5
                            // not used in metrics, left for backwards compatibility
                            Tag.of("exportable", "undefined")
                    );
                    rows.add(MultiGauge.Row.of(tags, count));
                }));

        multiGauge.register(rows, true);
    }

    @SneakyThrows
    private AliasWithKeyTuple getAliasWithCaviumKeyTuple(String alias) {
        try {
            Key key = awsCloudHSM.getKeyByLabel(alias);
            return new AliasWithKeyTuple(alias, key);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | ClassCastException e) {
            log.error("Error gathering metrics from HSM while getting a Cavium key by alias: {}", alias, e);
            throw new KeyNotFoundException("Error getting Cavium key from HSM", e);
        }
    }

    record AliasWithKeyTuple(String alias, Key key) {
        boolean isRSAKey() {
            return key instanceof RSAKey;
        }

        public int getKeySize() {
            if (key instanceof RSAKey rsaKey) {
                return keySize(rsaKey);
            }
            return -1;
        }

        private int keySize(RSAKey rsaKey) {
            // the modulus is a big integer without any leading zeros.
            // so while the key size may have been generated as 1024,
            // the actual bit length may be 1023.
            //
            // rounding ensures we can group the keys into nice buckets.
            BigInteger modulus = rsaKey.getModulus();
            int bitLength = modulus.bitLength();
            double nextPowerOf2 = Math.ceil(Math.log(bitLength) / Math.log(2));
            return (int) Math.floor(Math.pow(2, nextPowerOf2));
        }
    }
}
