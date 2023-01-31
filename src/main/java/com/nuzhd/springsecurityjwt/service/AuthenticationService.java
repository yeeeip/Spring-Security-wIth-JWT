package com.nuzhd.springsecurityjwt.service;

import com.nuzhd.springsecurityjwt.auth.AuthenticationRequest;
import com.nuzhd.springsecurityjwt.auth.AuthenticationResponse;
import com.nuzhd.springsecurityjwt.auth.RegisterRequest;
import com.nuzhd.springsecurityjwt.repository.MyUserRepository;
import com.nuzhd.springsecurityjwt.user.MyUser;
import com.nuzhd.springsecurityjwt.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final MyUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;

    public AuthenticationResponse register(RegisterRequest regRequest) {
        MyUser user = MyUser.builder()
                .firstName(regRequest.getFirstName())
                .lastName(regRequest.getFirstName())
                .email(regRequest.getEmail())
                .password(passwordEncoder.encode(regRequest.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authRequest) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getEmail(),
                        authRequest.getPassword()
                )
        );

        MyUser user = userRepository.findByEmail(authRequest.getEmail())
                .orElseThrow();

        userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
