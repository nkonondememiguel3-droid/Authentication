package e.dream.learn.authentification.repository;

import e.dream.learn.authentification.model.User;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {

    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);

    @Query("""
            select u.* from users u
            inner join registered_device rd on u.id = rd.user_id
            where rd.mac_address = :macAddress
            """)
    Optional<User> findByMacAddress(@Param("macAddress") String macAddress);

}
