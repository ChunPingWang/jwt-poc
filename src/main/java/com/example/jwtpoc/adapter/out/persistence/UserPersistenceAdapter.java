package com.example.jwtpoc.adapter.out.persistence;

import com.example.jwtpoc.application.port.out.UserRepository;
import com.example.jwtpoc.domain.model.User;

import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 持久化適配器 - 實作出站埠
 *
 * 負責 Domain Model ↔ JPA Entity 的轉換
 * 遵循 Dependency Inversion: Domain 定義介面，Adapter 實作
 */
@Component
public class UserPersistenceAdapter implements UserRepository {

    private final UserJpaRepository jpaRepository;

    public UserPersistenceAdapter(UserJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return jpaRepository.findByUsername(username)
                .map(this::toDomain);
    }

    @Override
    public User save(User user) {
        UserEntity entity = toEntity(user);
        UserEntity saved = jpaRepository.save(entity);
        return toDomain(saved);
    }

    @Override
    public boolean existsByUsername(String username) {
        return jpaRepository.existsByUsername(username);
    }

    // === Mapper Methods ===

    private User toDomain(UserEntity entity) {
        User user = new User(entity.getUsername(), entity.getPassword(), entity.getRole());
        user.setId(entity.getId());
        return user;
    }

    private UserEntity toEntity(User user) {
        UserEntity entity = new UserEntity(user.getUsername(), user.getPassword(), user.getRole());
        entity.setId(user.getId());
        return entity;
    }
}
