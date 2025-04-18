package org.example.expert.domain.auth.service;

import lombok.RequiredArgsConstructor;
import org.example.expert.config.JwtUtil;
import org.example.expert.config.PasswordEncoder;
import org.example.expert.domain.auth.dto.request.SigninRequest;
import org.example.expert.domain.auth.dto.request.SignupRequest;
import org.example.expert.domain.auth.dto.response.SigninResponse;
import org.example.expert.domain.auth.dto.response.SignupResponse;
import org.example.expert.domain.auth.exception.AuthException;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.enums.UserRole;
import org.example.expert.domain.user.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Transactional
    public SignupResponse signup(SignupRequest signupRequest) {

        // 1. 이메일 중복 여부를 확인하고 이미 존재하는 경우 예외를 던져 요청을 종료함
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new InvalidRequestException("이미 존재하는 이메일입니다.");
        }

        // 2. 사용자의 비밀번호를 암호화
        // 이 작업은 이메일 중복이 없는 경우에만 수행되므로, 불필요한 연산을 방지함
        String encodedPassword = passwordEncoder.encode(signupRequest.getPassword());

        // 3. 사용자가 입력한 역할을 enum 타입으로 변환
        UserRole userRole = UserRole.of(signupRequest.getUserRole());

        // 4. 새 유저 객체를 생성. 이메일, 암호화된 비밀번호, 역할 정보를 포함
        User newUser = new User(
                signupRequest.getEmail(),
                encodedPassword,
                userRole
        );

        // 5. 생성한 유저 객체를 데이터베이스에 저장하고, 저장된 결과를 반환받음
        User savedUser = userRepository.save(newUser);

        // 6. 저장된 유저 정보를 기반으로 JWT 토큰을 생성
        String bearerToken = jwtUtil.createToken(savedUser.getId(), savedUser.getEmail(), userRole);

        // 7. 생성된 토큰을 담아 SignupResponse 객체를 생성하여 반환
        return new SignupResponse(bearerToken);
    }

    @Transactional(readOnly = true)
    public SigninResponse signin(SigninRequest signinRequest) {
        User user = userRepository.findByEmail(signinRequest.getEmail()).orElseThrow(
                () -> new InvalidRequestException("가입되지 않은 유저입니다."));

        // 로그인 시 이메일과 비밀번호가 일치하지 않을 경우 401을 반환합니다.
        if (!passwordEncoder.matches(signinRequest.getPassword(), user.getPassword())) {
            throw new AuthException("잘못된 비밀번호입니다.");
        }

        String bearerToken = jwtUtil.createToken(user.getId(), user.getEmail(), user.getUserRole());

        return new SigninResponse(bearerToken);
    }
}
