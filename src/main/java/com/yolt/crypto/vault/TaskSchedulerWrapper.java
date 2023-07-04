package com.yolt.crypto.vault;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.stereotype.Service;

/**
 * Wrap it to make sure the bean follows the correct lifecycle.
 * <p>
 * Why is this bean here? We added a different implementation for vault authentication and this needs a ThreadPoolTaskScheduler
 * through the SessionManager (see VaultAuthentication) this directly calls <tt>threadPoolTaskScheduler()</tt>
 * which is not yet initialized then. The error occurred while wiring <tt>vaultSSLWebServerFactoryCustomizer</tt> bean.
 * This way we make sure it is initialized. This code is taken from <tt>VaultBootstrapConfiguration</tt> which used this approach,
 * however the VaultTemplate does not.
 */
@Service
public class TaskSchedulerWrapper implements InitializingBean, DisposableBean {

    private final ThreadPoolTaskScheduler taskScheduler;

    public TaskSchedulerWrapper() {
        this.taskScheduler = new ThreadPoolTaskScheduler();
        taskScheduler.setThreadNamePrefix("spring-vault-ThreadPoolTaskScheduler-");
        taskScheduler.setDaemon(true);
    }

    public ThreadPoolTaskScheduler getTaskScheduler() {
        return this.taskScheduler;
    }

    @Override
    public void destroy() throws Exception {
        this.taskScheduler.destroy();
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        this.taskScheduler.afterPropertiesSet();
    }
}