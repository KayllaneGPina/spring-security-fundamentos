package br.com.dio.primeiros_passos;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {

    @GetMapping
    public String welcome() {
        return "WELCOME TO MY SPRING BOOT WEB API";
    }

    @GetMapping("/users")
    public String users() {
        return "AUTHORIZED USER";
    }

    @GetMapping("/managers")
    public String managers() {
        return "AUTHORIZED MANAGERS";
    }
}
