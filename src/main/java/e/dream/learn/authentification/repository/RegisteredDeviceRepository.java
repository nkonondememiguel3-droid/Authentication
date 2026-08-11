package e.dream.learn.authentification.repository;

import e.dream.learn.authentification.model.RegisteredDevice;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RegisteredDeviceRepository extends CrudRepository<RegisteredDevice, Long> {

    Optional<RegisteredDevice> findByMacAddress(String macAddress);

    // Used during authentication to verify if a user owns this specific approved hardware device
    Optional<RegisteredDevice> findByUserIdAndMacAddressAndIsApprovedTrue(long userId, String macAddress);
}
