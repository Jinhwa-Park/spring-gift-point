package gift.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import gift.entity.Category;

@Repository
public interface CategoryRepository extends JpaRepository<Category, Long> {

}
