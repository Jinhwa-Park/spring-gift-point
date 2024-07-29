package gift.service;

import gift.entity.Category;
import gift.exception.CustomException;
import gift.repository.CategoryRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CategoryService {
    private final CategoryRepository categoryRepository;

    public CategoryService(CategoryRepository categoryRepository) {
        this.categoryRepository = categoryRepository;
    }

    public List<Category> getAllCategories() {
        return categoryRepository.findAll();
    }

    public Optional<Category> getCategoryById(Long id) {
        return categoryRepository.findById(id);
    }

    public Category createCategory(Category category) {
        return categoryRepository.save(category);
    }

    public Category updateCategory(Long id, Category categoryDetails) {
        Category category = categoryRepository.findById(id)
                .orElseThrow(() -> new CustomException.EntityNotFoundException("Category not found"));
        category.update(
                categoryDetails.getName(),
                categoryDetails.getColor(),
                categoryDetails.getImageUrl(),
                categoryDetails.getDescription()
        );
        return categoryRepository.save(category);
    }

    public void deleteCategory(Long id) {
        if (!categoryRepository.existsById(id)) {
            throw new CustomException.EntityNotFoundException("Category not found");
        }
        categoryRepository.deleteById(id);
    }
}
