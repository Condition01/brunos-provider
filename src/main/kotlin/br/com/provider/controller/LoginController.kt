package br.com.provider.controller

import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning
import org.springframework.security.saml.provider.service.ServiceProviderService
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping

@Controller
class LoginController(private val provisioning: SamlProviderProvisioning<ServiceProviderService>) {

    @RequestMapping(value = ["/", "/index", "/logged-in"])
    fun selectProvider(): String{
//        sample.web.ServiceProviderController.logger.info("Sample SP Application - You are logged in!")
        return "logged-in"
    }

    @RequestMapping(value = ["/hello"])
    fun getHelloWorld(): String{
//        sample.web.ServiceProviderController.logger.info("Sample SP Application - You are logged in!")
        return "hello-world"
    }

}