package com.nuzhd.springsecurityjwt.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo/demo-controller")
public class DemoController {

    @GetMapping
    public ResponseEntity<String> hello(){
        return ResponseEntity.ok("Hello from secured controller!");
    }

}
