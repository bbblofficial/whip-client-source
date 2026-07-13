package gg.whip.server.repository;

import fr.whip.api.model.Download;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface DownloadRepository extends JpaRepository<Download, UUID> {

    Optional<Download> findByDownloadId(String downloadId);

    @Query("SELECT d FROM Download d JOIN FETCH d.user WHERE d.downloadId = :downloadId")
    Optional<Download> findByDownloadIdWithUser(@Param("downloadId") String downloadId);

    boolean existsByDownloadId(String downloadId);
}
