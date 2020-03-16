package br.com.provider.security

import br.com.provider.config.BeanConfig
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.saml.key.SimpleKey
import org.springframework.security.saml.provider.config.RotatingKeys
import org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityConfiguration
import org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityDsl
import org.springframework.security.saml.provider.service.config.*
import org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityDsl.serviceProvider
import org.springframework.security.saml.saml2.metadata.NameId

@EnableWebSecurity
@Configuration
@Order(1)
class SamlSecurity(
        beanConfig: BeanConfig
) : SamlServiceProviderSecurityConfiguration("/saml/sp", beanConfig) {

    private val bConfig = beanConfig

    override fun configure(http: HttpSecurity?) {
        super.configure(http)
        http
                ?.apply(serviceProvider())
                ?.prefix(prefix)
                ?.useStandardFilters()
                ?.entityId("http://localhost:8084")
                ?.alias("bruno-sp")
                ?.signMetadata(true)
                ?.signRequests(true)
                ?.wantAssertionsSigned(true)
                ?.singleLogout(true)
                ?.nameIds(mutableListOf<NameId>(NameId.EMAIL, NameId.PERSISTENT, NameId.UNSPECIFIED))
                ?.rotatingKeys(getKeys())
                ?.identityProvider(
                    ExternalIdentityProviderConfiguration()
                            .setAlias("spring-security-saml-idp")
                            .setMetadata("http://localhost:8081/sample-idp/saml/idp/metadata")
                            .setLinktext("Spring Security SAML IDP/8081")
                            .setNameId(NameId.EMAIL)
                            .setAssertionConsumerServiceIndex(0)
                )
    }

    fun getKeys(): RotatingKeys =
            RotatingKeys()
                    .setActive(
                            SimpleKey()
                                    .setName("sp-signing-key-1")
                                    .setPrivateKey("-----BEGIN RSA PRIVATE KEY-----\n" +
                                            "Proc-Type: 4,ENCRYPTED\n" +
                                            "DEK-Info: DES-EDE3-CBC,7C8510E4CED17A9F\n" +
                                            "\n" +
                                            "SRYezKuY+AgM+gdiklVDBQ1ljeCFKnW3c5BM9sEyEOfkQm0zZx6fLr0afup0ToE4\n" +
                                            "iJGLxKw8swAnUAIjYda9wxqIEBb9mILyuRPevyfzmio2lE9KnARDEYRBqbwD9Lpd\n" +
                                            "vwZKNGHHJbZAgcUNfhXiYakmx0cUyp8HeO3Vqa/0XMiI/HAdlJ/ruYeT4e2DSrz9\n" +
                                            "ORZA2S5OvNpRQeCVf26l6ODKXnkDL0t5fDVY4lAhaiyhZtoT0sADlPIERBw73kHm\n" +
                                            "fGCTniY9qT0DT+R5Rqukk42mN2ij/cAr+kdV5colBi1fuN6d9gawCiH4zSb3LzHQ\n" +
                                            "9ccSlz6iQV1Ty2cRuTkB3zWC6Oy4q0BRlXnVRFOnOfYJztO6c2hD3Q9NxkDAbcgR\n" +
                                            "YWJWHpd0/HI8GyBpOG7hAS1l6aoleH30QCDOo7N2rFrTAaPC6g84oZOFSqkqvx4R\n" +
                                            "KTbWRwgJsqVxM6GqV6H9x1LNn2CpBizdGnp8VvnIiYcEvItMJbT1C1yeIUPoDDU2\n" +
                                            "Ct0Jofw/dquXStHWftPFjpIqB+5Ou//HQ2VNzjbyThNWVGtjnEKwSiHacQLS1sB3\n" +
                                            "iqFtSN/VCpdOcRujEBba+x5vlc8XCV1qr6x1PbvfPZVjyFdSM6JQidr0uEeDGDW3\n" +
                                            "TuYC1YgURN8zh0QF2lJIMX3xgbhr8HHNXv60ulcjeqYmna6VCS8AKJQgRTr4DGWt\n" +
                                            "Afv9BFV943Yp3nHwPC7nYC4FvMxOn4qW4KrHRJl57zcY6VDL4J030CfmvLjqUbuT\n" +
                                            "LYiQp/YgFlmoE4bcGuCiaRfUJZCwooPK2dQMoIvMZeVl9ExUGdXVMg==\n" +
                                            "-----END RSA PRIVATE KEY-----\n")
                                    .setPassphrase("sppassword")
                                    .setCertificate("-----BEGIN CERTIFICATE-----\n" +
                                            "MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
                                            "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
                                            "A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
                                            "DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
                                            "MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
                                            "MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
                                            "TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
                                            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
                                            "vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
                                            "+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
                                            "y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
                                            "XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
                                            "qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
                                            "RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B\n" +
                                            "-----END CERTIFICATE-----")
                    )
                    .setStandBy(
                            mutableListOf<SimpleKey>(
                                    SimpleKey()
                                            .setName("key2")
                                            .setPrivateKey("-----BEGIN RSA PRIVATE KEY-----\n" +
                                                    "Proc-Type: 4,ENCRYPTED\n" +
                                                    "DEK-Info: DES-EDE3-CBC,393409C5B5DFA31D\n" +
                                                    "\n" +
                                                    "O40s+E7P75d8OOcfvE3HTNY8gsULhYk7SBdRw50ZklH5G/TZwCxxfoRfPiA4Q1Jf\n" +
                                                    "bpEHF8BzyLzjXZwYJT5UqaXW/3ozMj7BZ95UfCR0hrxMXQWq4Nak6gFyHh/1focS\n" +
                                                    "ljzsLoBjyqjCc4BiFPD8uQHVGFv/PttCLydshnAVdSSrFLi0kVsFJMYOmL9ILG6l\n" +
                                                    "Ld7Sb2ayD0/+1L0lLW8F6IbTtEYAwuA+mX25Imr9JMPKem1YwI1pqUHr8ifq0kd+\n" +
                                                    "JsoI4Q0Qf2CKv/nfZI5EjqJO34U5podj2zkqN1W3z7dzdTYNOmigq8XVrBiSmT8B\n" +
                                                    "lE7Ea1GDFol90AeF6ltJWEE6rM6kYzOoModXdK0ozEu4JNnBV/Fu81sOV9zHBs+9\n" +
                                                    "zqM7jCC16b6n5W2IKGad02GVCBKE0fmIEfhEUsTJw5UJLjNFYF2PkA13Y7jVGZMT\n" +
                                                    "38MfE3gWcYYOhXVPuMvJ1thXbjXEImg3yH+XHN3RMyups2B1s2JAXYVP2n5zI9pS\n" +
                                                    "Y3Wt6iXAkKJ0Fiaa/myitUGtL1QvbhBOOfsw9HFuesxzJuKTJ7gqs0ceYwtpQ4X8\n" +
                                                    "wjk0HXz/riAb+BI6ImEd6H077e/U5u1c9WOdqAKEExAlXL8EhG5Azsj84cCAFuGl\n" +
                                                    "+T5XVBir0a1jUBQycnsinGZoy3lhE+92j8EhM4LgrDbzoqICVLrk1jX9FiDbcqzZ\n" +
                                                    "if87phEJmxz+ymCygUjzYohc0sIOwVcMl+s6Y+JsfSBDyg2XEIhzPPdGdgpCrxBg\n" +
                                                    "KEtaNgtbHXo7UOlN6voWliM14n1g13+xtUuX7hRve3Uy7MMwtuSVJA==\n" +
                                                    "-----END RSA PRIVATE KEY-----\n")
                                            .setPassphrase("sppassword")
                                            .setCertificate("-----BEGIN CERTIFICATE-----\n" +
                                                    "MIICgTCCAeoCCQCQqf5mvKPOpzANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
                                                    "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
                                                    "A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
                                                    "DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDQ0NDZaFw0yODA1\n" +
                                                    "MTExNDQ0NDZaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
                                                    "MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
                                                    "TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
                                                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCXJXpaDE6QmY9eN9pwcG8k/54a\n" +
                                                    "K9YLzRgln64hZ6mvdK+OIIBB5E2Pgenfc3Pi8pF0B9dGUbbNK8+8L6HcZRT/3aXM\n" +
                                                    "WlJsENJdMS13pnmSFimsTqoxYnayc2EaHULtvhMvLKf7UPRwX4jzxLanc6R4IcUL\n" +
                                                    "JZ/dg9gBT5KDlm164wIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAHDyh2B4AZ1C9LSi\n" +
                                                    "gis+sAiVJIzODsnKg8pIWGI7bcFUK+i/Vj7qlx09ZD/GbrQts87Yp4aq+5OqVqb5\n" +
                                                    "n6bS8DWB8jHCoHC5HACSBb3J7x/mC0PBsKXA9A8NSFzScErvfD/ACjWg3DJEghxn\n" +
                                                    "lqAVTm/DQX/t8kNTdrLdlzsYTuE0\n" +
                                                    "-----END CERTIFICATE-----")
                                    ,
                                    SimpleKey()
                                            .setName("key3")
                                            .setPrivateKey("-----BEGIN RSA PRIVATE KEY-----\n" +
                                                    "Proc-Type: 4,ENCRYPTED\n" +
                                                    "DEK-Info: DES-EDE3-CBC,EF0A6B6E2C665851\n" +
                                                    "\n" +
                                                    "UQ4gDBIOTrksMOLT2fXiqfcD3wpWT54jWhWq0fls8mLz65FU7/LY2dwATGmcCJrU\n" +
                                                    "N6T9E8mmqbWO8gCKVEx8zBKHOAh9wJVJKVl7aDmHWFYDU1xyighg1GB468ZIqx4/\n" +
                                                    "dFMY75hxNrOVNbicKcH1XKfn/GtJavbDon9L870l3X2cLFEIUiZGWFcTd8mAWHHY\n" +
                                                    "d9IHgVQhwE2jBG9wnywO3FEKecwmo5m+VZsTQGWuZIYHSPhNcsoeEg+OViJGaFzi\n" +
                                                    "xcbW1h+bIG6B3tIdXB7QIf79VPoW7vpXhCvl9+iMk6Tb3JhvnPEulPykiB8xsmzh\n" +
                                                    "jqr0qc+eYmdTBjmYA5DPuICjo1YLNUZdys8AAe9qyXMU2baPiOsEwcBN1J1oXm/f\n" +
                                                    "2v5IQX4aNq4KI0SowdNCSv/4txUwbyxGfHcTa+Jy1MbDKV8ggaHYQ1k76mLryRfZ\n" +
                                                    "3JN937KLmArF6wK2JVO/VkGM1JWdlxcmcYpBGN0lCxFz5qIcMdQT08amCXyfk8Ov\n" +
                                                    "KX5pFXXFNItFwXJW/tsZNfBiOPP2b7MLjxKuWvVm4SL0aOZG6NuOkZBnJ6AT7jIk\n" +
                                                    "XTX7csdT/ogOrQrQiSeISeUUGgRULdHZLCgRQ4yVm58FE6QytFcuNddK0f527zr2\n" +
                                                    "3qrRHT5153693p7Zb/FupEBlPK5yf3jpLKPGZTor1r5QQHsOE60nsZIhz4VtmNj8\n" +
                                                    "f5+mgpFJ+s6UbkCqOFiE4FTbiWTvIX2K9Ho29FnnTPeLkaq9H4onFAAv2JM2JYEB\n" +
                                                    "Mz8ZcX+KkiaArqIOvWgqCfLY4taF5XOPaU4/UGUXUUW4lQFw/0+0cw==\n" +
                                                    "-----END RSA PRIVATE KEY-----\n")
                                            .setPassphrase("sppassword")
                                            .setCertificate("-----BEGIN CERTIFICATE-----\n" +
                                                    "MIICgTCCAeoCCQC3dvhia5XvzjANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
                                                    "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
                                                    "A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
                                                    "DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDQ1MzBaFw0yODA1\n" +
                                                    "MTExNDQ1MzBaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
                                                    "MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
                                                    "TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
                                                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2iAUrJXrHaSOWrU95v8GUGVVl\n" +
                                                    "5vWrYrNRFtsK5qkhB/nRbL08CbqIeD4pkJuIg0LuJdsBuMtYqOnhQSFF5tT36OId\n" +
                                                    "ld9SfPA5m8zqPLsCcjWPQ66xoMdReEXN9E8s/mZOXn3jkKIqywUxJ+wkS5qoBlvm\n" +
                                                    "ShwDff+igFlF/fBfpwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBACDBjvIpc1/2yZ3T\n" +
                                                    "Qe29bKif5pr/3NdKz4MWBJ6vjRk7Bs2hbPrM2ajxLbqPx6PRPeTOw5XZgrufDj9H\n" +
                                                    "mrvKHM2LZTp/cIUpxcNpVRyDA4iVNDc7V3qszaWP9ZIswAYnvmyDL2UHVDLE8xoG\n" +
                                                    "z/AkxsRNN9VXNHewjQO605umiAKJ\n" +
                                                    "-----END CERTIFICATE-----")
                            )
                    )
}