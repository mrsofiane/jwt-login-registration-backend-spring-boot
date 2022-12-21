package me.mrsofiane.demo.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/hello")

public class RootController {

    @GetMapping
    public String hello() {
        return "hello world";
    }
}
