package com.nuzhd.springsecurityjwt.auth.controller;

import com.nuzhd.springsecurityjwt.auth.AuthenticationRequest;
import com.nuzhd.springsecurityjwt.auth.AuthenticationResponse;
import com.nuzhd.springsecurityjwt.auth.RegisterRequest;
import com.nuzhd.springsecurityjwt.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest registerRequest){
        return ResponseEntity.ok(authService.register(registerRequest));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody AuthenticationRequest authenticationRequest){
        return ResponseEntity.ok(authService.authenticate(authenticationRequest));
    }
}
