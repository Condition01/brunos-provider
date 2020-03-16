package br.com.provider.config

import org.springframework.context.annotation.Configuration
import org.springframework.security.saml.provider.SamlServerConfiguration
import org.springframework.security.saml.provider.service.config.SamlServiceProviderServerBeanConfiguration

@Configuration
class BeanConfig : SamlServiceProviderServerBeanConfiguration() {

    public override fun getDefaultHostSamlServerConfiguration(): SamlServerConfiguration {
        return SamlServerConfiguration()
    }

}